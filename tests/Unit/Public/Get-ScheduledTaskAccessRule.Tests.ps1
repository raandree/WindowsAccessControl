. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Get-ScheduledTaskAccessRule' `
    -RequiredParameters @('TaskPath', 'TaskName', 'Account', 'ExcludeInherited', 'ExcludeExplicit', 'ThrottleLimit') `
    -SupportsShouldProcess $false

Describe 'Get-ScheduledTaskAccessRule behavior' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
    }

    It 'Should emit task-bound rules that carry the leaf task identity' {
        $rules = InModuleScope WindowsAccessControl {
            $script:target = [pscustomobject]@{
                ObjectType       = 'ScheduledTask'
                Path             = '\Operations\Cleanup'
                TaskPath         = '\Operations'
                TaskName         = 'Cleanup'
                CanonicalTarget  = 'ScheduledTask:Local:\OPERATIONS\CLEANUP'
                DescriptorSource = 'TaskSchedulerCom'
            }
            $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
                'D:(A;;FA;;;SY)(D;;FW;;;S-1-5-21-1-2-3-1000)'
            )
            $bytes = [byte[]]::new($descriptor.BinaryLength)
            $descriptor.GetBinaryForm($bytes, 0)
            Mock Resolve-WindowsTaskSchedulerTarget { $script:target }
            Mock Get-WindowsTaskSchedulerSecurityDescriptor {
                Write-Output -InputObject $bytes -NoEnumerate
            }

            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                @(Get-ScheduledTaskAccessRule -TaskPath '\Operations' -TaskName 'Cleanup')
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }
        }

        $rules.Count | Should -Be 2
        $rules[0].PSObject.TypeNames |
            Should -Contain 'WindowsAccessControl.ScheduledTaskAccessRule'
        $rules[0].TaskName | Should -BeExactly 'Cleanup'
        $rules[0].TaskPath | Should -BeExactly '\Operations'
        $rules[1].AccessControlType |
            Should -Be ([System.Security.AccessControl.AccessControlType]::Deny)
        $rules[1].IsOrphaned | Should -BeTrue
        $rules[1].AccessRights | Should -Be ([WindowsScheduledTaskRights]::Write)
    }
}
