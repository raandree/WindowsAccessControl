. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Get-TaskFolderSecurityDescriptor' `
    -RequiredParameters @('Path', 'ThrottleLimit') `
    -SupportsShouldProcess $false

Describe 'Get-TaskFolderSecurityDescriptor behavior' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            'D:(A;;FR;;;WD)'
        )
        $script:descriptorBytes = [byte[]]::new($descriptor.BinaryLength)
        $descriptor.GetBinaryForm($script:descriptorBytes, 0)
    }

    AfterAll {
        Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
    }

    It 'Should return a typed descriptor through the worker path' {
        InModuleScope WindowsAccessControl -Parameters @{
            DescriptorBytes = $script:descriptorBytes
        } {
            $script:target = [pscustomobject]@{
                ObjectType = 'TaskFolder'
                Path = '\Operations'
                TaskPath = '\Operations'
                CanonicalTarget = 'TaskFolder:Local:\OPERATIONS'
                DescriptorSource = 'TaskSchedulerCom'
            }
            Mock Resolve-WindowsTaskSchedulerTarget { $script:target }
            Mock Get-WindowsTaskSchedulerSecurityDescriptor {
                Write-Output -InputObject $DescriptorBytes -NoEnumerate
            }

            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                $result = Get-TaskFolderSecurityDescriptor -Path '\Operations'
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }

            $result.PSObject.TypeNames |
                Should -Contain 'WindowsAccessControl.TaskFolderSecurityDescriptor'
            $result.TaskPath | Should -BeExactly '\Operations'
            $result.Sddl | Should -BeExactly 'D:(A;;FR;;;WD)'
            Should -Invoke Get-WindowsTaskSchedulerSecurityDescriptor `
                -Times 1 `
                -Exactly `
                -ParameterFilter { $Target -eq $script:target }
        }
    }
}
