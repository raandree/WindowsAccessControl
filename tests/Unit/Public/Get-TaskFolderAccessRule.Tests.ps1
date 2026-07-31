. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Get-TaskFolderAccessRule' `
    -RequiredParameters @('Path', 'Account', 'ExcludeInherited', 'ExcludeExplicit', 'ThrottleLimit') `
    -SupportsShouldProcess $false

Describe 'Get-TaskFolderAccessRule behavior' -Tag 'Unit', 'WindowsOnly' {
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
            TaskName         = $null
            CanonicalTarget  = 'TaskFolder:WACHOST:\OPERATIONS'
            DescriptorSource = 'TaskSchedulerCom'
        }
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            'D:(A;;FA;;;SY)(A;OICIID;0x1200a9;;;WD)'
        )
        $script:descriptorBytes = [byte[]]::new($descriptor.BinaryLength)
        $descriptor.GetBinaryForm($script:descriptorBytes, 0)
        Mock -ModuleName WindowsAccessControl Resolve-WindowsTaskSchedulerTarget {
            $script:target
        }
        Mock -ModuleName WindowsAccessControl Get-WindowsTaskSchedulerSecurityDescriptor {
            Write-Output -InputObject $script:descriptorBytes -NoEnumerate
        }
    }

    It 'Should emit typed rules with Task Scheduler rights and folder scope' {
        $rules = InModuleScope WindowsAccessControl {
            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                @(Get-TaskFolderAccessRule -Path '\Operations')
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }
        }

        $rules.Count | Should -Be 2
        $rules[0].PSObject.TypeNames |
            Should -Contain 'WindowsAccessControl.TaskFolderAccessRule'
        $rules[0].TaskPath | Should -BeExactly '\Operations'
        $rules[0].SID | Should -BeExactly 'S-1-5-18'
        $rules[0].AccessRights | Should -Be ([WindowsTaskFolderRights]::FullControl)
        $rules[0].AppliesTo | Should -BeExactly 'ThisFolderOnly'
        $rules[0].IsInherited | Should -BeFalse
        $rules[1].SID | Should -BeExactly 'S-1-1-0'
        $rules[1].AccessRights | Should -Be ([WindowsTaskFolderRights]::ReadAndTraverse)
        $rules[1].AppliesTo | Should -BeExactly 'ThisFolderSubfoldersAndTasks'
        $rules[1].IsInherited | Should -BeTrue
    }

    It 'Should filter inherited and explicit rules independently' {
        $explicit = InModuleScope WindowsAccessControl {
            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                @(Get-TaskFolderAccessRule -Path '\Operations' -ExcludeInherited)
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }
        }
        $inherited = InModuleScope WindowsAccessControl {
            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                @(Get-TaskFolderAccessRule -Path '\Operations' -ExcludeExplicit)
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }
        }

        $explicit.SID | Should -BeExactly 'S-1-5-18'
        $inherited.SID | Should -BeExactly 'S-1-1-0'
    }

    It 'Should reject contradictory inheritance filters' {
        {
            InModuleScope WindowsAccessControl {
                $script:WindowsAccessControlBatchWorker.Value = $true
                try {
                    Get-TaskFolderAccessRule -Path '\Operations' `
                        -ExcludeInherited -ExcludeExplicit
                }
                finally {
                    $script:WindowsAccessControlBatchWorker.Value = $false
                }
            }
        } | Should -Throw -ExpectedMessage '*cannot be used together*'
    }
}
