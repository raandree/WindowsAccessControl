. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Get-SmbShareEffectiveAccess' `
    -RequiredParameters @('Name', 'Account', 'AccessRights', 'ThrottleLimit') `
    -SupportsShouldProcess $false

Describe 'Get-SmbShareEffectiveAccess behavior' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
        $script:currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            "O:SYG:SYD:(A;;0x001F01FF;;;$($script:currentSid.Value))"
        )
        $script:descriptorBytes = [byte[]]::new($descriptor.BinaryLength)
        $descriptor.GetBinaryForm($script:descriptorBytes, 0)
    }

    AfterAll {
        Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
    }

    It 'Should return an explicitly local share-only SID-derived result' {
        InModuleScope WindowsAccessControl -Parameters @{
            CurrentSid = $script:currentSid.Value
            DescriptorBytes = $script:descriptorBytes
        } {
            Mock Resolve-WindowsSmbShareTarget {
                [pscustomobject]@{
                    ObjectType = 'SmbShare'
                    Path = 'WacLab$'
                    ShareName = 'WacLab$'
                    NativePath = 'WacLab$'
                    NativeObjectType = 5
                    CanonicalTarget = 'SmbShare:Local:WACLAB$'
                }
            }
            Mock Get-WindowsNamedSecurityDescriptor { $DescriptorBytes }

            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                $result = Get-SmbShareEffectiveAccess `
                    -Name 'WacLab$' `
                    -Account $CurrentSid `
                    -AccessRights Read
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }

            $result.PSObject.TypeNames |
                Should -Contain 'WindowsAccessControl.SmbShareEffectiveAccess'
            $result.ShareName | Should -BeExactly 'WacLab$'
            $result.SID | Should -BeExactly $CurrentSid
            $result.IsAllowed | Should -BeTrue
            $result.AuthorizationContext | Should -BeExactly 'LocalSidDerived'
            $result.IncludesBackingNtfs | Should -BeFalse
            Should -Invoke Get-WindowsNamedSecurityDescriptor `
                -Times 1 `
                -Exactly `
                -ParameterFilter {
                    $Sections -eq (
                        [WindowsSecurityDescriptorSection]::Owner -bor
                        [WindowsSecurityDescriptorSection]::Group -bor
                        [WindowsSecurityDescriptorSection]::Access
                    )
                }
        }
    }

    It 'Should report a denied requested-rights result' {
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            "O:SYG:SYD:(A;;0x00020000;;;$($script:currentSid.Value))"
        )
        $limitedBytes = [byte[]]::new($descriptor.BinaryLength)
        $descriptor.GetBinaryForm($limitedBytes, 0)

        InModuleScope WindowsAccessControl -Parameters @{
            CurrentSid = $script:currentSid.Value
            DescriptorBytes = $limitedBytes
        } {
            Mock Resolve-WindowsSmbShareTarget {
                [pscustomobject]@{
                    ShareName = 'WacLab$'
                    NativePath = 'WacLab$'
                    NativeObjectType = 5
                    CanonicalTarget = 'SmbShare:Local:WACLAB$'
                }
            }
            Mock Get-WindowsNamedSecurityDescriptor { $DescriptorBytes }
            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                $result = Get-SmbShareEffectiveAccess `
                    -Name 'WacLab$' `
                    -Account $CurrentSid `
                    -AccessRights Full
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }

            $result.RequestedRights | Should -Be ([WindowsSmbShareRights]::Full)
            $result.IsAllowed | Should -BeFalse
        }
    }

    It 'Should leave the decision null when no rights are requested' {
        InModuleScope WindowsAccessControl -Parameters @{
            CurrentSid = $script:currentSid.Value
            DescriptorBytes = $script:descriptorBytes
        } {
            Mock Resolve-WindowsSmbShareTarget {
                [pscustomobject]@{
                    ShareName = 'WacLab$'
                    NativePath = 'WacLab$'
                    NativeObjectType = 5
                    CanonicalTarget = 'SmbShare:Local:WACLAB$'
                }
            }
            Mock Get-WindowsNamedSecurityDescriptor { $DescriptorBytes }
            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                $result = Get-SmbShareEffectiveAccess `
                    -Name 'WacLab$' `
                    -Account $CurrentSid
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }

            $result.RequestedRights | Should -BeNullOrEmpty
            $result.IsAllowed | Should -BeNullOrEmpty
        }
    }

    It 'Should preserve an unsigned generic-read mask' {
        InModuleScope WindowsAccessControl {
            $rights = ConvertTo-WindowsSmbShareRights -AccessMask 0x80000000L

            $rights.ToString() | Should -BeExactly 'GenericRead'
            [uint64]([int64]$rights -band 0xFFFFFFFFL) | Should -Be 0x80000000L
        }
    }

    It 'Should accept GenericRead as requested rights without signed overflow' {
        InModuleScope WindowsAccessControl -Parameters @{
            CurrentSid = $script:currentSid.Value
            DescriptorBytes = $script:descriptorBytes
        } {
            Mock Resolve-WindowsSmbShareTarget {
                [pscustomobject]@{
                    ShareName = 'WacLab$'
                    NativePath = 'WacLab$'
                    NativeObjectType = 5
                    CanonicalTarget = 'SmbShare:Local:WACLAB$'
                }
            }
            Mock Get-WindowsNamedSecurityDescriptor { $DescriptorBytes }
            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                $result = Get-SmbShareEffectiveAccess `
                    -Name 'WacLab$' `
                    -Account $CurrentSid `
                    -AccessRights GenericRead
            }
            finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }

            $result.RequestedRights | Should -Be ([WindowsSmbShareRights]::GenericRead)
            $result.IsAllowed | Should -BeFalse
        }
    }
}