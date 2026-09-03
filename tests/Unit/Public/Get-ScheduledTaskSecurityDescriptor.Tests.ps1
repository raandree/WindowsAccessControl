. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Get-ScheduledTaskSecurityDescriptor' `
    -RequiredParameters @('TaskPath', 'TaskName', 'ThrottleLimit') `
    -SupportsShouldProcess $false

Describe 'Get-ScheduledTaskSecurityDescriptor behavior' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            'D:(A;;FR;;;WD)'
        )
        $script:descriptorBytes = [byte[]]::new($descriptor.BinaryLength)
        $descriptor.GetBinaryForm($script:descriptorBytes, 0)
    }

    It 'Should return a typed descriptor through the worker path' {
        InModuleScope WindowsAccessControl -Parameters @{
            DescriptorBytes = $script:descriptorBytes
        } {
            $script:target = [pscustomobject]@{
                ObjectType = 'ScheduledTask'
                Path = '\Operations\Cleanup'
                TaskPath = '\Operations'
                TaskName = 'Cleanup'
                CanonicalTarget = 'ScheduledTask:WACHOST:\OPERATIONS\CLEANUP'
                DescriptorSource = 'TaskSchedulerCom'
            }
            Mock Resolve-WindowsTaskSchedulerTarget { $script:target }
            Mock Get-WindowsTaskSchedulerSecurityDescriptor {
                Write-Output -InputObject $DescriptorBytes -NoEnumerate
            }

            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                $result = Get-ScheduledTaskSecurityDescriptor `
                    -TaskPath '\Operations' `
                    -TaskName 'Cleanup'
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }

            $result.PSObject.TypeNames |
                Should -Contain 'WindowsAccessControl.ScheduledTaskSecurityDescriptor'
            $result.TaskPath | Should -BeExactly '\Operations'
            $result.TaskName | Should -BeExactly 'Cleanup'
            $result.Sddl | Should -BeExactly 'D:(A;;FR;;;WD)'
            Should -Invoke Get-WindowsTaskSchedulerSecurityDescriptor `
                -Times 1 `
                -Exactly `
                -ParameterFilter { $Target -eq $script:target }
        }
    }

    It 'Should route default execution through the batch dispatcher' {
        InModuleScope WindowsAccessControl {
            Mock Invoke-WindowsTaskSchedulerCommandBatch

            Get-ScheduledTaskSecurityDescriptor `
                -TaskPath '\Operations' `
                -TaskName 'Cleanup' `
                -ThrottleLimit 3

            Should -Invoke Invoke-WindowsTaskSchedulerCommandBatch `
                -Times 1 `
                -Exactly `
                -ParameterFilter {
                    $CommandName -eq 'Get-ScheduledTaskSecurityDescriptor' -and
                    $PathParameterName -eq 'TaskPath' -and
                    $TaskName -eq 'Cleanup' -and
                    $ThrottleLimit -eq 3
                }
        }
    }
}
