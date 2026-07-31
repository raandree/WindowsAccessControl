. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Set-TaskFolderSecurityDescriptor' `
    -RequiredParameters @('Path', 'AllowedRootPath', 'Sddl', 'ThrottleLimit', 'PassThru') `
    -SupportsShouldProcess $true

Describe 'Set-TaskFolderSecurityDescriptor behavior' -Tag 'Unit', 'WindowsOnly' {
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
            ObjectType = 'TaskFolder'
            Path = '\Operations'
            TaskPath = '\Operations'
            CanonicalTarget = 'TaskFolder:WACHOST:\OPERATIONS'
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
                Set-TaskFolderSecurityDescriptor `
                    -Path '\Operations' `
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
            Should -Contain 'WindowsAccessControl.TaskFolderSecurityDescriptor'
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
                Set-TaskFolderSecurityDescriptor `
                    -Path '\Operations' `
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
}
