. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Remove-ScheduledTaskAccessRule' `
    -RequiredParameters @('InputObject', 'AllowedRootPath', 'PassThru') `
    -SupportsShouldProcess $true `
    -SupportsTargetArrays $false

Describe 'Remove-ScheduledTaskAccessRule behavior' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
    }

    It 'Should reject a rule whose canonical identity no longer matches' {
        InModuleScope WindowsAccessControl {
            Mock Resolve-WindowsTaskSchedulerTarget {
                [pscustomobject]@{
                    ObjectType      = 'ScheduledTask'
                    TaskPath        = '\Operations'
                    TaskName        = 'Cleanup'
                    CanonicalTarget = 'ScheduledTask:WACHOST:\OPERATIONS\CLEANUP'
                }
            }
            Mock Invoke-WindowsTaskSchedulerAclRuleMutation

            $ace = [Security.AccessControl.CommonAce]::new(
                [Security.AccessControl.AceFlags]::None,
                [Security.AccessControl.AceQualifier]::AccessAllowed,
                0x00120089,
                [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                $false,
                $null)
            $rule = [pscustomobject]@{
                TaskPath        = '\Operations'
                TaskName        = 'Cleanup'
                CanonicalTarget = 'ScheduledTask:WACHOST:\OPERATIONS\OTHER'
                SID             = 'S-1-1-0'
                IsInherited     = $false
                NativeAce       = $ace
            }
            $rule.PSObject.TypeNames.Insert(
                0, 'WindowsAccessControl.ScheduledTaskAccessRule')

            {
                $rule | Remove-ScheduledTaskAccessRule `
                    -AllowedRootPath '\Operations' -Confirm:$false
            } | Should -Throw -ExpectedMessage '*canonical identity*'

            Should -Invoke Invoke-WindowsTaskSchedulerAclRuleMutation -Times 0 -Exactly
        }
    }
}
