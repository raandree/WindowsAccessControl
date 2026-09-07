Describe 'Invoke-WindowsAccessControlLabAcceptance' {
    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot '..\..\Lab\Invoke-WindowsAccessControlLabAcceptance.ps1'
        $script:command = Get-Command -Name $scriptPath
    }

    It 'Should reject <Case> editions before loading lab dependencies' -ForEach @(
        @{ Case = 'an empty list of'; Editions = @() }
        @{ Case = 'null'; Editions = $null }
    ) {
        Mock Import-Module { throw 'Lab dependencies were loaded before validating editions.' }

        {
            & $scriptPath -PowerShellEdition $Editions -CoverageEdition None -WhatIf
        } | Should -Throw "*validate argument on parameter 'PowerShellEdition'*"

        Should -Invoke Import-Module -Exactly -Times 0
    }

    It 'exposes one payload deployment switch through the supported names' {
        $parameter = $script:command.Parameters['SkipPayloadDeployment']

        $parameter.ParameterType | Should -Be ([System.Management.Automation.SwitchParameter])
        $aliases = @(
            $parameter.Attributes |
                Where-Object { $_ -is [System.Management.Automation.AliasAttribute] } |
                ForEach-Object { $_.AliasNames }
        )
        $aliases | Should -Contain 'SkipPayload'
        $aliases | Should -Contain 'SkipDeployment'
    }

    It 'guards payload reset and copy operations with the deployment switch' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $scriptPath,
            [ref]$tokens,
            [ref]$errors
        )

        $errors | Should -BeNullOrEmpty
        $deploymentGuard = $ast.FindAll({
                param($node)

                $node -is [System.Management.Automation.Language.IfStatementAst] -and
                $node.Clauses.Item1.Extent.Text -match '^\s*-not\s+\$SkipPayloadDeployment\s*$'
            }, $true) | Select-Object -First 1

        $deploymentGuard | Should -Not -BeNullOrEmpty
        $deploymentGuard.Extent.Text | Should -Match 'Copy-LabFileItem'
        $deploymentGuard.Extent.Text | Should -Match 'Reset the acceptance payload directory'
    }

    It 'does not describe payload deployment when deployment is skipped' {
        $scriptText = Get-Content -LiteralPath $scriptPath -Raw
        $skipAction = '"Run the domain-lab acceptance in $($editions -join '' and '')"'

        $scriptText | Should -Match '\$shouldProcessAction\s*=\s*if\s*\(\$SkipPayloadDeployment\)'
        $scriptText | Should -Match ([regex]::Escape($skipAction))
        $scriptText | Should -Match '\$PSCmdlet\.ShouldProcess\([\s\S]+\$shouldProcessAction\s*\)'
    }

    It 'keeps the unredacted console log out of the payload directory' {
        $scriptText = Get-Content -LiteralPath $scriptPath -Raw

        $scriptText | Should -Match '\$consoleLogPath\s*=\s*Join-Path\s+\$env:TEMP'
        $scriptText | Should -Not -Match 'ChangeExtension\(\s*\$OutputPath'
    }

    It 'retains console output in the native-process pipeline without losing returned output' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $scriptPath, [ref]$tokens, [ref]$errors
        )
        $errors | Should -BeNullOrEmpty
        $pipeline = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.PipelineAst] -and
                $node.Extent.Text -match '^& \$executable @arguments 2>&1'
        }, $true)
        $pipeline | Should -Not -BeNullOrEmpty
        $executable = Join-Path $PSHOME 'pwsh.exe'
        if (-not (Test-Path -LiteralPath $executable)) {
            $executable = Join-Path $PSHOME 'powershell.exe'
        }
        $arguments = @('-NoProfile', '-NonInteractive', '-Command', "'retained console output'")
        $consoleLogPath = Join-Path $TestDrive 'acceptance.console.log'

        $operation = [scriptblock]::Create(
            'param($executable, $arguments, $consoleLogPath)' + "`n" + $pipeline.Extent.Text
        )
        $output = & $operation $executable $arguments $consoleLogPath

        $output | Should -Be 'retained console output'
        $consoleLogPath | Should -Exist
        Get-Content -LiteralPath $consoleLogPath -Raw | Should -Match 'retained console output'
    }
}

Describe 'Domain lab host evidence collection' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $script:acceptanceScript = Join-Path $PSScriptRoot '..\..\Lab\Invoke-WindowsAccessControlLabAcceptance.ps1'

        function Import-Lab {
            [CmdletBinding()]
            param([string]$Name, [switch]$NoValidation)
            throw "Unexpected real lab import '$Name' (NoValidation=$NoValidation)."
        }

        function Invoke-LabCommand {
            [CmdletBinding()]
            param(
                [string]$ComputerName,
                [string]$ActivityName,
                [scriptblock]$ScriptBlock,
                [object[]]$ArgumentList,
                [switch]$PassThru,
                [switch]$NoDisplay
            )
            throw (
                "Unexpected real lab command '$ActivityName' on '$ComputerName' " +
                "(arguments=$($ArgumentList.Count), callback=$($null -ne $ScriptBlock), " +
                "PassThru=$PassThru, NoDisplay=$NoDisplay)."
            )
        }

        function New-LabPSSession {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions', '',
                Justification = 'This test stub never creates a session.'
            )]
            [CmdletBinding()]
            param([string]$ComputerName)
            throw "Unexpected real lab session for '$ComputerName'."
        }
    }

    BeforeEach {
        $runRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $runRoot -ItemType Directory
        $script:runnerParameters = @{
            PowerShellEdition = 'Core'
            CoverageEdition = 'None'
            EvidencePath = Join-Path $runRoot 'evidence.json'
            CoverageEvidencePath = Join-Path $runRoot 'coverage.xml'
            SkipPayloadDeployment = $true
            Confirm = $false
            WarningAction = 'SilentlyContinue'
            InformationAction = 'SilentlyContinue'
            ErrorAction = 'Stop'
        }
        Mock Import-Module { }
        Mock Import-Lab { }
        Mock Invoke-LabCommand {
            [pscustomobject]@{ ExitCode = 0; Output = @(); ConsoleLogPath = 'test-console.log' }
        }
        Mock New-LabPSSession {
            New-MockObject -Type ([System.Management.Automation.Runspaces.PSSession])
        }
        Mock Remove-PSSession { }
        Mock Copy-Item {
            [pscustomobject]@{
                Format = 'WindowsAccessControl.DomainLabAcceptance'
                SchemaVersion = 1
                Result = 'Passed'
            } | ConvertTo-Json | Set-Content -LiteralPath $Destination
        }
    }

    It 'Should reject a missing remote process exit status' {
        Mock Invoke-LabCommand {
            [pscustomobject]@{ Output = @(); ConsoleLogPath = 'test-console.log' }
        }

        { & $script:acceptanceScript @script:runnerParameters } |
            Should -Throw '*exit status*'

        Should -Invoke Copy-Item -Exactly -Times 0
    }

    It 'Should fail when fresh evidence cannot be collected even if an old report exists' {
        $previousEvidencePath = Join-Path $runRoot 'evidence-core.json'
        $previousEvidence = '{"Result":"Passed","Marker":"previous run"}'
        Set-Content -LiteralPath $previousEvidencePath -Value $previousEvidence -NoNewline
        Mock Copy-Item { throw [System.IO.IOException]::new('Expected evidence copy failure.') }

        { & $script:acceptanceScript @script:runnerParameters } |
            Should -Throw '*evidence collection failed*'

        Get-Content -LiteralPath $previousEvidencePath -Raw | Should -BeExactly $previousEvidence
    }

    It 'Should fail when requested code coverage cannot be collected' {
        $script:runnerParameters.CoverageEdition = 'Core'
        Mock Copy-Item { throw [System.IO.IOException]::new('Expected coverage copy failure.') } -ParameterFilter {
            $Path -like '*lab-coverage*.xml'
        }

        { & $script:acceptanceScript @script:runnerParameters } |
            Should -Throw '*evidence collection failed*'
    }

    It 'Should return evidence collected successfully for the selected edition' {
        $result = & $script:acceptanceScript @script:runnerParameters

        $result.Result | Should -BeExactly 'Passed'
        $result.PowerShellEdition | Should -BeExactly 'Core'
        Should -Invoke Copy-Item -Exactly -Times 1
    }

    It 'Should use new remote artifact paths for each invocation' {
        $script:runnerParameters.CoverageEdition = 'Core'
        Mock Copy-Item {
            [pscustomobject]@{
                Format = 'WindowsAccessControl.DomainLabAcceptance'
                SchemaVersion = 1
                Result = 'Passed'
                RemotePath = [string]$Path
            } | ConvertTo-Json | Set-Content -LiteralPath $Destination
        }

        $first = & $script:acceptanceScript @script:runnerParameters
        $firstCoverage = Get-Content -LiteralPath $script:runnerParameters.CoverageEvidencePath -Raw |
            ConvertFrom-Json
        $second = & $script:acceptanceScript @script:runnerParameters
        $secondCoverage = Get-Content -LiteralPath $script:runnerParameters.CoverageEvidencePath -Raw |
            ConvertFrom-Json

        $first.RemotePath | Should -Not -BeExactly $second.RemotePath
        $firstCoverage.RemotePath | Should -Not -BeExactly $secondCoverage.RemotePath
    }
}
