. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Add-ScheduledTaskAccessRule' `
    -RequiredParameters @('TaskPath', 'TaskName', 'AllowedRootPath', 'Account', 'AccessRights', 'AccessControlType', 'ThrottleLimit', 'PassThru') `
    -SupportsShouldProcess $true

Describe 'Add-ScheduledTaskAccessRule behavior' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
    }

    It 'Should not expose folder inheritance scope on a leaf task' {
        (Get-Command Add-ScheduledTaskAccessRule).Parameters.ContainsKey('AppliesTo') |
            Should -BeFalse
    }

    It 'Should require an explicit containment boundary before writing' {
        InModuleScope WindowsAccessControl {
            Mock Invoke-WindowsTaskSchedulerAclRuleMutation

            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                {
                    Add-ScheduledTaskAccessRule `
                        -TaskPath '\Microsoft\Windows\Defrag' `
                        -TaskName 'ScheduledDefrag' `
                        -AllowedRootPath '\Microsoft' `
                        -Account 'S-1-1-0' `
                        -AccessRights Read `
                        -Confirm:$false
                } | Should -Throw -ExpectedMessage '*Microsoft system-tree*'
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }

            Should -Invoke Invoke-WindowsTaskSchedulerAclRuleMutation -Times 0 -Exactly
        }
    }
}
