. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Set-ScheduledTaskSecurityDescriptor' `
    -RequiredParameters @('TaskPath', 'TaskName', 'AllowedRootPath', 'Sddl', 'ThrottleLimit', 'PassThru') `
    -SupportsShouldProcess $true

Describe 'Set-ScheduledTaskSecurityDescriptor behavior' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $script:target = [pscustomobject]@{
            ObjectType = 'ScheduledTask'
            Path = '\Operations\Cleanup'
            TaskPath = '\Operations'
            TaskName = 'Cleanup'
            CanonicalTarget = 'ScheduledTask:WACHOST:\OPERATIONS\CLEANUP'
            DescriptorSource = 'TaskSchedulerCom'
        }
        Mock -ModuleName WindowsAccessControl Resolve-WindowsTaskSchedulerTarget {
            $script:target
        }
        Mock -ModuleName WindowsAccessControl Set-WindowsTaskSchedulerSecurityDescriptor {
            param($SecurityDescriptor)
            Write-Output -InputObject $SecurityDescriptor -NoEnumerate
        }
    }

    It 'Should route one contained DACL write and return typed PassThru output' {
        $result = InModuleScope WindowsAccessControl {
            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                Set-ScheduledTaskSecurityDescriptor `
                    -TaskPath '\Operations' `
                    -TaskName 'Cleanup' `
                    -AllowedRootPath '\Operations' `
                    -Sddl 'D:(A;;FR;;;WD)' `
                    -PassThru `
                    -Confirm:$false
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }
        }

        $result.PSObject.TypeNames |
            Should -Contain 'WindowsAccessControl.ScheduledTaskSecurityDescriptor'
        $result.TaskName | Should -BeExactly 'Cleanup'
        $result.Sddl | Should -BeExactly 'D:(A;;FR;;;WD)'
        Should -Invoke -ModuleName WindowsAccessControl `
            Set-WindowsTaskSchedulerSecurityDescriptor `
            -Times 1 `
            -Exactly `
            -ParameterFilter { $Target -eq $script:target }
    }

    It 'Should not call the persistence helper under WhatIf' {
        InModuleScope WindowsAccessControl {
            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                Set-ScheduledTaskSecurityDescriptor `
                    -TaskPath '\Operations' `
                    -TaskName 'Cleanup' `
                    -AllowedRootPath '\Operations' `
                    -Sddl 'D:(A;;FR;;;WD)' `
                    -WhatIf
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }
        }

        Should -Invoke -ModuleName WindowsAccessControl `
            Set-WindowsTaskSchedulerSecurityDescriptor `
            -Times 0 `
            -Exactly
    }

    It 'Should route default execution through serialized batch dispatch' {
        InModuleScope WindowsAccessControl {
            Mock Invoke-WindowsTaskSchedulerCommandBatch

            Set-ScheduledTaskSecurityDescriptor `
                -TaskPath '\Operations' `
                -TaskName 'Cleanup' `
                -AllowedRootPath '\Operations' `
                -Sddl 'D:(A;;FR;;;WD)' `
                -ThrottleLimit 3 `
                -Confirm:$false

            Should -Invoke Invoke-WindowsTaskSchedulerCommandBatch `
                -Times 1 `
                -Exactly `
                -ParameterFilter {
                    $CommandName -eq 'Set-ScheduledTaskSecurityDescriptor' -and
                    $PathParameterName -eq 'TaskPath' -and
                    $TaskName -eq 'Cleanup' -and
                    $ThrottleLimit -eq 3 -and
                    $SerializeByCanonicalTarget -and
                    $ConfirmationImpact -eq 'High'
                }
        }
    }
}
