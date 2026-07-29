. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Add-TaskFolderAccessRule' `
    -RequiredParameters @('Path', 'AllowedRootPath', 'Account', 'AccessRights', 'AccessControlType', 'AppliesTo', 'ThrottleLimit', 'PassThru') `
    -SupportsShouldProcess $true

Describe 'Add-TaskFolderAccessRule behavior' -Tag 'Unit', 'WindowsOnly' {
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
            ObjectType       = 'TaskFolder'
            Path             = '\Operations'
            TaskPath         = '\Operations'
            CanonicalTarget  = 'TaskFolder:Local:\OPERATIONS'
            DescriptorSource = 'TaskSchedulerCom'
        }
        Mock -ModuleName WindowsAccessControl Resolve-WindowsTaskSchedulerTarget {
            $script:target
        }
        Mock -ModuleName WindowsAccessControl Invoke-WindowsTaskSchedulerAclRuleMutation
    }

    It 'Should deduplicate accounts and apply the requested inheritance scope' {
        InModuleScope WindowsAccessControl {
            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                Add-TaskFolderAccessRule `
                    -Path '\Operations' `
                    -AllowedRootPath '\Operations' `
                    -Account 'S-1-1-0', 'S-1-1-0' `
                    -AccessRights ReadAndTraverse `
                    -AppliesTo SubfoldersAndTasksOnly `
                    -Confirm:$false
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }
        }

        Should -Invoke -ModuleName WindowsAccessControl `
            Invoke-WindowsTaskSchedulerAclRuleMutation `
            -Times 1 `
            -Exactly `
            -ParameterFilter {
                $Operation -eq 'Add' -and
                $SecurityIdentifier.Count -eq 1 -and
                $AccessMask -eq 0x001200A9 -and
                [int]$AceFlags -eq 11
            }
    }

    It 'Should not persist anything under WhatIf' {
        InModuleScope WindowsAccessControl {
            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                Add-TaskFolderAccessRule `
                    -Path '\Operations' `
                    -AllowedRootPath '\Operations' `
                    -Account 'S-1-1-0' `
                    -AccessRights Read `
                    -WhatIf
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }
        }

        Should -Invoke -ModuleName WindowsAccessControl `
            Invoke-WindowsTaskSchedulerAclRuleMutation -Times 0 -Exactly
    }
}
