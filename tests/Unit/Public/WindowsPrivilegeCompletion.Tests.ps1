BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
    $script:module = Get-Module -Name 'WindowsAccessControl'

    function Get-PrivilegeCompletion {
        param(
            [Parameter(Mandatory)]
            [string]$InputScript
        )

        @((TabExpansion2 -inputScript $InputScript -cursorColumn $InputScript.Length).CompletionMatches)
    }
}

Describe 'Windows privilege name completion' -Tag 'Unit', 'WindowsOnly' {
    Context 'Command <_>' -ForEach @(
        'Enable-WindowsPrivilege'
        'Disable-WindowsPrivilege'
        'Test-WindowsPrivilege'
    ) {
        BeforeAll {
            $script:commandName = $_
            $script:allCompletion = Get-PrivilegeCompletion -InputScript "$script:commandName -Name Se"
        }

        It 'Should offer the Windows privilege constants' {
            $script:allCompletion.CompletionText | Should -Contain 'SeSecurityPrivilege'
            $script:allCompletion.CompletionText | Should -Contain 'SeBackupPrivilege'
            $script:allCompletion.CompletionText | Should -Contain 'SeTakeOwnershipPrivilege'
        }

        It 'Should offer only values the parameter accepts' {
            $script:allCompletion | Should -Not -BeNullOrEmpty
            foreach ($match in $script:allCompletion) {
                $match.CompletionText | Should -Match '^Se[A-Za-z0-9]+Privilege$'
                $match.ResultType | Should -Be ([System.Management.Automation.CompletionResultType]::ParameterValue)
            }
        }

        It 'Should narrow the offer to the typed prefix' {
            $completion = Get-PrivilegeCompletion -InputScript "$script:commandName -Name SeTakeO"

            $completion.CompletionText | Should -Be 'SeTakeOwnershipPrivilege'
        }

        It 'Should match a fragment anywhere in the constant name' {
            $completion = Get-PrivilegeCompletion -InputScript "$script:commandName -Name Ownership"

            $completion.CompletionText | Should -Be 'SeTakeOwnershipPrivilege'
        }

        It 'Should complete a positional argument' {
            $completion = Get-PrivilegeCompletion -InputScript "$script:commandName SeSecu"

            $completion.CompletionText | Should -Be 'SeSecurityPrivilege'
        }
    }

    Context 'Completion detail' {
        It 'Should name the user right the privilege grants' {
            $completion = Get-PrivilegeCompletion -InputScript 'Enable-WindowsPrivilege -Name SeSecurityP'

            $completion.ToolTip | Should -Be 'SeSecurityPrivilege: Manage auditing and security log'
        }

        It 'Should treat an unbalanced wildcard character as literal text' {
            $completion = & $script:module {
                param($WordToComplete)

                [WindowsPrivilegeNameCompleter]::new().CompleteArgument(
                    'Enable-WindowsPrivilege', 'Name', $WordToComplete, $null, $null
                )
            } 'Se['

            $completion | Should -BeNullOrEmpty
        }
    }
}
