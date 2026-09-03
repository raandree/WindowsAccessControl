Describe 'Invoke-WindowsAccessControlLabAcceptance' {
    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot '..\..\Lab\Invoke-WindowsAccessControlLabAcceptance.ps1'
        $script:command = Get-Command -Name $scriptPath
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
}