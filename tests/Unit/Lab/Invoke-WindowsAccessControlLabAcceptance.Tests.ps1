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
        Mock Invoke-LabCommand { [string]$ArgumentList[-1] } -ParameterFilter {
            $ActivityName -eq 'Validate the acceptance payload directory'
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

Describe 'Domain lab runner directory ownership' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $script:acceptanceScript = Join-Path $PSScriptRoot '..\..\Lab\Invoke-WindowsAccessControlLabAcceptance.ps1'
        . (Join-Path $PSScriptRoot '..\..\Lab\WindowsAccessControl.LabRunnerOwnership.ps1')
        $script:markerFileName = '.windows-access-control-lab-runner'

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

        function Copy-LabFileItem {
            [CmdletBinding()]
            param([string]$Path, [string]$ComputerName, [string]$DestinationFolderPath, [switch]$Recurse)
            throw "Unexpected real lab copy of '$Path' to '$DestinationFolderPath' on '$ComputerName' (Recurse=$Recurse)."
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

        function New-TestRunnerMarker {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions', '',
                Justification = 'This test helper writes only below TestDrive.'
            )]
            [CmdletBinding()]
            param([Parameter(Mandatory)][string]$Directory)

            $marker = Get-WindowsAccessControlLabRunnerMarker
            [IO.File]::WriteAllText(
                (Join-Path $Directory $marker.FileName),
                $marker.Text,
                [Text.UTF8Encoding]::new($false)
            )
        }

        $script:remoteStepFilter = {
            $ActivityName -in @(
                'Validate the acceptance payload directory'
                'Reset the acceptance payload directory'
                'Reset the package staging directory'
                'Install the packaged module into the machine module path'
            )
        }

        # Runs one remote step the way remoting does: from the text of its script
        # block alone, in a fresh runspace that holds none of the test's
        # functions. A non-null protected list stands in for the remote
        # machine's own protected directories, so these cases never evaluate
        # the real list; WindowsAccessControl.LabRunnerOwnership.Tests.ps1
        # proves that list against this machine.
        function Invoke-TestRemoteStep {
            param(
                [scriptblock]$ScriptBlock,
                [object[]]$ArgumentList,
                [AllowNull()][string[]]$ProtectedPath
            )

            $shell = [powershell]::Create()
            try {
                $null = $shell.AddScript({
                        param($StepText, $StepArguments, $TestProtectedPath)

                        if ($null -ne $TestProtectedPath) {
                            $protectedPathStub = { $TestProtectedPath }.GetNewClosure()
                            Set-Item -Path 'function:global:Get-WacTestProtectedPath' -Value $protectedPathStub
                            Set-Alias -Name Get-WindowsAccessControlLabRunnerProtectedPath -Value Get-WacTestProtectedPath -Scope Global
                        }
                        & ([scriptblock]::Create($StepText)) @StepArguments
                    }.ToString())
                $null = $shell.AddArgument($ScriptBlock.ToString())
                $null = $shell.AddArgument($ArgumentList)
                $null = $shell.AddArgument($ProtectedPath)
                $shell.Invoke()
            }
            finally {
                $shell.Dispose()
            }
        }

        $packageSource = Join-Path $TestDrive 'PackageSource'
        $null = New-Item -Path (Join-Path $packageSource '_rels') -ItemType Directory -Force
        New-ModuleManifest -Path (Join-Path $packageSource 'WindowsAccessControl.psd1') -ModuleVersion '91.0.0'
        Set-Content -LiteralPath (Join-Path $packageSource '_rels\.rels') -Value '<Relationships />'
        Set-Content -LiteralPath (Join-Path $packageSource '[Content_Types].xml') -Value '<Types />'
        Set-Content -LiteralPath (Join-Path $packageSource 'WindowsAccessControl.nuspec') -Value '<package />'
        $script:packagePath = Join-Path $TestDrive 'WindowsAccessControl.91.0.0.nupkg'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory($packageSource, $script:packagePath)
    }

    BeforeEach {
        $script:remoteRoot = [IO.Path]::GetFullPath((Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))))
        $script:payloadRoot = Join-Path $script:remoteRoot 'WacRepo'
        $script:packageDirectory = Join-Path $script:payloadRoot 'package'
        $script:programFiles = Join-Path $script:remoteRoot 'ProgramFiles'
        $script:installTarget = Join-Path $script:programFiles 'WindowsPowerShell\Modules\WindowsAccessControl\91.0.0'
        $null = New-Item -Path $script:programFiles -ItemType Directory -Force

        # Every remote step of these tests writes below TestDrive, never below
        # the real Program Files. Mock bodies run inside the runner script,
        # where $script: names the runner's scope, so the values they read are
        # plain variables of this scope.
        $script:originalProgramFiles = $env:ProgramFiles
        $env:ProgramFiles = $script:programFiles
        $testProtectedPath = @(
            [Environment]::GetFolderPath('Windows')
            $script:originalProgramFiles
            [Environment]::GetFolderPath('CommonApplicationData')
        )

        $script:runnerParameters = @{
            RemoteRepositoryPath = $script:payloadRoot
            PowerShellEdition = 'Core'
            CoverageEdition = 'None'
            EvidencePath = Join-Path $script:remoteRoot 'evidence.json'
            CoverageEvidencePath = Join-Path $script:remoteRoot 'coverage.xml'
            Confirm = $false
            WarningAction = 'SilentlyContinue'
            InformationAction = 'SilentlyContinue'
            ErrorAction = 'Stop'
        }

        Mock Import-Module { }
        Mock Import-Lab { }
        Mock Copy-LabFileItem {
            if ($Path -like '*.nupkg') {
                [IO.File]::Copy($Path, (Join-Path $DestinationFolderPath (Split-Path -Path $Path -Leaf)))
            }
        }
        Mock Invoke-LabCommand {
            Invoke-TestRemoteStep -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ProtectedPath $testProtectedPath
        } -ParameterFilter $script:remoteStepFilter
        Mock Invoke-LabCommand {
            [pscustomobject]@{ ExitCode = 0; Output = @(); ConsoleLogPath = 'test-console.log' }
        } -ParameterFilter { $ActivityName -like 'WindowsAccessControl domain-lab acceptance*' }
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
        } -ParameterFilter { $null -ne $FromSession }
    }

    AfterEach {
        $env:ProgramFiles = $script:originalProgramFiles
    }

    It 'Should refuse to delete an unmarked payload root and stop before copying the payload' {
        $null = New-Item -Path $script:payloadRoot -ItemType Directory -Force
        $sentinel = Join-Path $script:payloadRoot 'operator-data.txt'
        Set-Content -LiteralPath $sentinel -Value 'not created by the runner' -NoNewline

        { & $script:acceptanceScript @script:runnerParameters } |
            Should -Throw "*Refusing to replace '$($script:payloadRoot)'*-RemoteRepositoryPath*"

        Get-Content -LiteralPath $sentinel -Raw | Should -BeExactly 'not created by the runner'
        Should -Invoke Copy-LabFileItem -Exactly -Times 0
        Should -Invoke Invoke-LabCommand -Exactly -Times 0 -ParameterFilter {
            $ActivityName -like 'WindowsAccessControl domain-lab acceptance*'
        }
    }

    It 'Should create and mark an absent payload root' {
        $null = & $script:acceptanceScript @script:runnerParameters

        Join-Path $script:payloadRoot $script:markerFileName | Should -Exist
        (Get-WindowsAccessControlLabRunnerDirectoryState -Path $script:payloadRoot).State | Should -BeExactly 'Owned'
        Join-Path $script:payloadRoot 'output' | Should -Exist
        Should -Invoke Copy-LabFileItem -Exactly -Times 3
    }

    It 'Should replace a marked payload root with a fresh marked payload root' {
        $null = New-Item -Path (Join-Path $script:payloadRoot 'tests') -ItemType Directory -Force
        Set-Content -LiteralPath (Join-Path $script:payloadRoot 'tests\stale.ps1') -Value '# stale'
        New-TestRunnerMarker -Directory $script:payloadRoot

        $null = & $script:acceptanceScript @script:runnerParameters

        Join-Path $script:payloadRoot 'tests\stale.ps1' | Should -Not -Exist
        Join-Path $script:payloadRoot $script:markerFileName | Should -Exist
    }

    It 'Should reject a payload root under a protected directory of the remote machine before any reset' {
        $testProtectedDirectory = Join-Path $script:remoteRoot 'Protected'
        Mock Invoke-LabCommand {
            Invoke-TestRemoteStep -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ProtectedPath @($testProtectedDirectory)
        } -ParameterFilter $script:remoteStepFilter
        $script:runnerParameters.RemoteRepositoryPath = Join-Path $testProtectedDirectory 'WacRepo'

        { & $script:acceptanceScript @script:runnerParameters } |
            Should -Throw "*lies under the protected directory '$testProtectedDirectory'*"

        Join-Path $testProtectedDirectory 'WacRepo' | Should -Not -Exist
        Should -Invoke Invoke-LabCommand -Exactly -Times 0 -ParameterFilter { $ActivityName -like 'Reset*' }
        Should -Invoke Copy-LabFileItem -Exactly -Times 0
    }

    It 'Should reject a protected payload root even when it reuses the deployed payload' {
        $testProtectedDirectory = Join-Path $script:remoteRoot 'Protected'
        Mock Invoke-LabCommand {
            Invoke-TestRemoteStep -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ProtectedPath @($testProtectedDirectory)
        } -ParameterFilter $script:remoteStepFilter
        $script:runnerParameters.RemoteRepositoryPath = Join-Path $testProtectedDirectory 'WacRepo'
        $script:runnerParameters.SkipPayloadDeployment = $true

        { & $script:acceptanceScript @script:runnerParameters } |
            Should -Throw "*lies under the protected directory '$testProtectedDirectory'*"

        Should -Invoke Invoke-LabCommand -Exactly -Times 0 -ParameterFilter {
            $ActivityName -like 'WindowsAccessControl domain-lab acceptance*'
        }
    }

    It 'Should refuse an unmarked package staging directory when it reuses the deployed payload' {
        $null = New-Item -Path $script:packageDirectory -ItemType Directory -Force
        $previousPackage = Join-Path $script:packageDirectory 'WindowsAccessControl.0.0.1.nupkg'
        Set-Content -LiteralPath $previousPackage -Value 'previous package' -NoNewline
        $script:runnerParameters.SkipPayloadDeployment = $true
        $script:runnerParameters.ModuleSource = 'Installed'
        $script:runnerParameters.PackagePath = $script:packagePath

        { & $script:acceptanceScript @script:runnerParameters } |
            Should -Throw "*Refusing to replace '$($script:packageDirectory)'*"

        Get-Content -LiteralPath $previousPackage -Raw | Should -BeExactly 'previous package'
        Should -Invoke Copy-LabFileItem -Exactly -Times 0
        Should -Invoke Invoke-LabCommand -Exactly -Times 0 -ParameterFilter {
            $ActivityName -eq 'Install the packaged module into the machine module path'
        }
    }

    It 'Should refuse to replace an unmarked installation of the same module version' {
        $null = New-Item -Path $script:installTarget -ItemType Directory -Force
        $existingModule = Join-Path $script:installTarget 'WindowsAccessControl.psm1'
        Set-Content -LiteralPath $existingModule -Value '# installed by someone else' -NoNewline
        $script:runnerParameters.ModuleSource = 'Installed'
        $script:runnerParameters.PackagePath = $script:packagePath

        { & $script:acceptanceScript @script:runnerParameters } |
            Should -Throw "*Refusing to replace '$($script:installTarget)'*different module version*"

        Get-Content -LiteralPath $existingModule -Raw | Should -BeExactly '# installed by someone else'
        Join-Path $script:installTarget $script:markerFileName | Should -Not -Exist
        Should -Invoke Invoke-LabCommand -Exactly -Times 0 -ParameterFilter {
            $ActivityName -like 'WindowsAccessControl domain-lab acceptance*'
        }
    }

    It 'Should mark the module version directory it installs and leave out the package artifacts' {
        $script:runnerParameters.ModuleSource = 'Installed'
        $script:runnerParameters.PackagePath = $script:packagePath

        $null = & $script:acceptanceScript @script:runnerParameters

        @(Get-ChildItem -LiteralPath $script:installTarget -Force | ForEach-Object Name | Sort-Object) |
            Should -Be @($script:markerFileName, 'WindowsAccessControl.psd1')
        (Get-WindowsAccessControlLabRunnerDirectoryState -Path $script:installTarget).State |
            Should -BeExactly 'Owned'
        Should -Invoke Invoke-LabCommand -Exactly -Times 1 -ParameterFilter {
            $ActivityName -like 'WindowsAccessControl domain-lab acceptance*' -and
                $ArgumentList[-1] -eq $script:installTarget
        }
    }

    It 'Should replace a same-version installation that carries the runner marker' {
        $null = New-Item -Path $script:installTarget -ItemType Directory -Force
        New-TestRunnerMarker -Directory $script:installTarget
        Set-Content -LiteralPath (Join-Path $script:installTarget 'stale.psm1') -Value '# stale'
        $script:runnerParameters.ModuleSource = 'Installed'
        $script:runnerParameters.PackagePath = $script:packagePath

        $null = & $script:acceptanceScript @script:runnerParameters

        Join-Path $script:installTarget 'stale.psm1' | Should -Not -Exist
        Join-Path $script:installTarget 'WindowsAccessControl.psd1' | Should -Exist
        Join-Path $script:installTarget $script:markerFileName | Should -Exist
    }

    It "Should stop when '<Activity>' does not confirm its directory" -ForEach @(
        @{ Activity = 'Validate the acceptance payload directory' }
        @{ Activity = 'Reset the acceptance payload directory' }
        @{ Activity = 'Reset the package staging directory' }
        @{ Activity = 'Install the packaged module into the machine module path' }
    ) {
        # AutomatedLab can report a remote failure as a non-terminating error
        # and return no output, so a silent step stands in for that failure.
        $testSilentActivity = $Activity
        Mock Invoke-LabCommand { } -ParameterFilter { $ActivityName -eq $testSilentActivity }
        $script:runnerParameters.ModuleSource = 'Installed'
        $script:runnerParameters.PackagePath = $script:packagePath

        { & $script:acceptanceScript @script:runnerParameters } |
            Should -Throw "*'$Activity'*did not confirm*"

        Should -Invoke Invoke-LabCommand -Exactly -Times 0 -ParameterFilter {
            $ActivityName -like 'WindowsAccessControl domain-lab acceptance*'
        }
    }

    It 'Should delete directories recursively only inside the owned package staging tree' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:acceptanceScript, [ref]$tokens, [ref]$errors
        )
        $errors | Should -BeNullOrEmpty

        $recursiveRemovals = @($ast.FindAll({
                    param($node)

                    $node -is [System.Management.Automation.Language.CommandAst] -and
                        $node.GetCommandName() -in @('Remove-Item', 'ri', 'rm', 'rmdir', 'rd', 'del', 'erase') -and
                        @($node.CommandElements | Where-Object {
                                $_ -is [System.Management.Automation.Language.CommandParameterAst] -and
                                    'recurse'.StartsWith($_.ParameterName.ToLowerInvariant())
                            }).Count -gt 0
                }, $true))

        $recursiveRemovals.Count | Should -BeGreaterThan 0
        foreach ($removal in $recursiveRemovals) {
            $elements = @($removal.CommandElements)
            $pathIndex = [array]::FindIndex($elements, [Predicate[object]] {
                    param($element)
                    $element -is [System.Management.Automation.Language.CommandParameterAst] -and
                        $element.ParameterName -eq 'LiteralPath'
                })
            $pathIndex | Should -BeGreaterThan 0 -Because "'$($removal.Extent.Text)' must name its target literally"
            $elements[$pathIndex + 1].Extent.Text |
                Should -Match '^(?:\$staging|\(Join-Path \$staging \$artifact\))$' -Because (
                    "'$($removal.Extent.Text)' must delete only inside the owned package staging tree"
                )
        }
    }
}
