BeforeDiscovery {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'Windows access control DSC access-rule adapters' -Tag 'Unit', 'WindowsOnly' {
    InModuleScope WindowsAccessControl {
        BeforeEach {
            $script:rules = @()
            Mock Resolve-WindowsIdentityReference {
                [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
            }
            Mock Get-NTFSAccessRule { $script:rules }
            Mock Get-RegistryKeyAccessRule { $script:rules }
            Mock Get-ServiceAccessRule { $script:rules }
            Mock Get-ProcessAccessRule { $script:rules }
            Mock Add-NTFSAccessRule
            Mock Add-RegistryKeyAccessRule
            Mock Add-ServiceAccessRule
            Mock Add-ProcessAccessRule
            Mock Remove-NTFSAccessRule
            Mock Remove-RegistryKeyAccessRule
            Mock Remove-ServiceAccessRule
            Mock Remove-ProcessAccessRule
        }

        It 'Should find one exact <ObjectFamily> rule' -ForEach @(
            @{
                ObjectFamily = 'FileSystem'; Target = 'C:\Data'; Mask = 131209
                AppliesTo = 'ThisFolderOnly'; GetCommand = 'Get-NTFSAccessRule'
            }
            @{
                ObjectFamily = 'RegistryKey'; Target = 'HKLM:\Software\Contoso'
                Mask = 131097; AppliesTo = 'ThisKeyOnly'
                GetCommand = 'Get-RegistryKeyAccessRule'
            }
            @{
                ObjectFamily = 'Service'; Target = 'BITS'; Mask = 4
                AppliesTo = $null; GetCommand = 'Get-ServiceAccessRule'
            }
            @{
                ObjectFamily = 'ServiceControlManager'; Target = $null; Mask = 1
                AppliesTo = $null; GetCommand = 'Get-ServiceAccessRule'
            }
            @{
                ObjectFamily = 'Process'; Target = $null; Mask = 4096
                AppliesTo = $null; GetCommand = 'Get-ProcessAccessRule'
            }
        ) {
            $storedMask = if ($ObjectFamily -eq 'FileSystem') {
                $Mask -bor 0x00100000
            } else {
                $Mask
            }
            $exactRule = [pscustomobject]@{
                SID = 'S-1-1-0'
                AccessMask = [uint64]$storedMask
                AccessRights = [int]$storedMask
                AccessControlType = 'Allow'
                AppliesTo = $AppliesTo
                IsInherited = $false
            }
            $script:rules = @(
                [pscustomobject]@{
                    SID = 'S-1-1-0'; AccessMask = [uint64]($storedMask + 1)
                    AccessRights = [int]($storedMask + 1)
                    AccessControlType = 'Allow'; AppliesTo = $AppliesTo
                    IsInherited = $false
                }
                $exactRule
            )
            $parameters = @{
                ObjectFamily = $ObjectFamily
                Account = 'Everyone'
                AccessMask = [uint64]$Mask
                AccessControlType = 'Allow'
            }
            if ($Target) { $parameters.Target = $Target }
            if ($AppliesTo) { $parameters.AppliesTo = $AppliesTo }
            if ($ObjectFamily -eq 'RegistryKey') { $parameters.RegistryView = 'Default' }
            if ($ObjectFamily -eq 'Process') {
                $parameters.ProcessId = 42
                $parameters.CreationTimeFileTime = 123456789
            }

            Get-WindowsAccessControlDscAccessRule @parameters | Should -BeTrue
            Should -Invoke -CommandName $GetCommand -Exactly -Times 1
        }

        It 'Should add an absent exact <ObjectFamily> rule' -ForEach @(
            @{ ObjectFamily = 'FileSystem'; Target = 'C:\Data'; Mask = 131209; AppliesTo = 'ThisFolderOnly'; AddCommand = 'Add-NTFSAccessRule' }
            @{ ObjectFamily = 'RegistryKey'; Target = 'HKLM:\Software\Contoso'; Mask = 131097; AppliesTo = 'ThisKeyOnly'; AddCommand = 'Add-RegistryKeyAccessRule' }
            @{ ObjectFamily = 'Service'; Target = 'BITS'; Mask = 4; AppliesTo = $null; AddCommand = 'Add-ServiceAccessRule' }
            @{ ObjectFamily = 'ServiceControlManager'; Target = $null; Mask = 1; AppliesTo = $null; AddCommand = 'Add-ServiceAccessRule' }
            @{ ObjectFamily = 'Process'; Target = $null; Mask = 4096; AppliesTo = $null; AddCommand = 'Add-ProcessAccessRule' }
        ) {
            $parameters = @{
                ObjectFamily = $ObjectFamily; Account = 'Everyone'
                AccessMask = [uint64]$Mask; AccessControlType = 'Allow'
                Ensure = 'Present'
            }
            if ($Target) { $parameters.Target = $Target }
            if ($AppliesTo) { $parameters.AppliesTo = $AppliesTo }
            if ($ObjectFamily -eq 'RegistryKey') { $parameters.RegistryView = 'Default' }
            if ($ObjectFamily -eq 'Process') {
                $parameters.ProcessId = 42
                $parameters.CreationTimeFileTime = 123456789
            }

            Set-WindowsAccessControlDscAccessRule @parameters

            Should -Invoke -CommandName $AddCommand -Exactly -Times 1
        }

        It 'Should remove a present exact <ObjectFamily> rule' -ForEach @(
            @{ ObjectFamily = 'FileSystem'; Target = 'C:\Data'; Mask = 131209; AppliesTo = 'ThisFolderOnly'; RemoveCommand = 'Remove-NTFSAccessRule' }
            @{ ObjectFamily = 'RegistryKey'; Target = 'HKLM:\Software\Contoso'; Mask = 131097; AppliesTo = 'ThisKeyOnly'; RemoveCommand = 'Remove-RegistryKeyAccessRule' }
            @{ ObjectFamily = 'Service'; Target = 'BITS'; Mask = 4; AppliesTo = $null; RemoveCommand = 'Remove-ServiceAccessRule' }
            @{ ObjectFamily = 'ServiceControlManager'; Target = $null; Mask = 1; AppliesTo = $null; RemoveCommand = 'Remove-ServiceAccessRule' }
            @{ ObjectFamily = 'Process'; Target = $null; Mask = 4096; AppliesTo = $null; RemoveCommand = 'Remove-ProcessAccessRule' }
        ) {
            $storedMask = if ($ObjectFamily -eq 'FileSystem') {
                $Mask -bor 0x00100000
            } else {
                $Mask
            }
            $script:rules = @([pscustomobject]@{
                SID = 'S-1-1-0'; AccessMask = [uint64]$storedMask
                AccessRights = [int]$storedMask
                AccessControlType = 'Allow'; AppliesTo = $AppliesTo
                IsInherited = $false
            })
            $parameters = @{
                ObjectFamily = $ObjectFamily; Account = 'Everyone'
                AccessMask = [uint64]$Mask; AccessControlType = 'Allow'
                Ensure = 'Absent'
            }
            if ($Target) { $parameters.Target = $Target }
            if ($AppliesTo) { $parameters.AppliesTo = $AppliesTo }
            if ($ObjectFamily -eq 'RegistryKey') { $parameters.RegistryView = 'Default' }
            if ($ObjectFamily -eq 'Process') {
                $parameters.ProcessId = 42
                $parameters.CreationTimeFileTime = 123456789
            }

            Set-WindowsAccessControlDscAccessRule @parameters

            Should -Invoke -CommandName $RemoveCommand -Exactly -Times 1
        }

        It 'Should not add an exact rule that is already present' {
            $script:rules = @([pscustomobject]@{
                SID = 'S-1-1-0'; AccessMask = [uint64]4
                AccessControlType = 'Allow'; IsInherited = $false
            })

            Set-WindowsAccessControlDscAccessRule `
                -ObjectFamily Service `
                -Target BITS `
                -Account Everyone `
                -AccessMask 4 `
                -AccessControlType Allow `
                -Ensure Present

            Should -Invoke Add-ServiceAccessRule -Exactly -Times 0
        }

        It 'Should not remove an exact rule that is already absent' {
            Set-WindowsAccessControlDscAccessRule `
                -ObjectFamily Service `
                -Target BITS `
                -Account Everyone `
                -AccessMask 4 `
                -AccessControlType Allow `
                -Ensure Absent

            Should -Invoke Remove-ServiceAccessRule -Exactly -Times 0
        }

        It 'Should remove every duplicate exact rule' {
            $rule = [pscustomobject]@{
                SID = 'S-1-1-0'; AccessMask = [uint64]4
                AccessControlType = 'Allow'; IsInherited = $false
            }
            $script:rules = @($rule, $rule)

            Set-WindowsAccessControlDscAccessRule `
                -ObjectFamily Service `
                -Target BITS `
                -Account Everyone `
                -AccessMask 4 `
                -AccessControlType Allow `
                -Ensure Absent

            Should -Invoke Remove-ServiceAccessRule -Exactly -Times 2
        }

        It 'Should reject inherited and opposite-scope rules as exact matches' {
            $script:rules = @(
                [pscustomobject]@{
                    SID = 'S-1-1-0'; AccessMask = [uint64]131097
                    AccessControlType = 'Allow'; AppliesTo = 'ThisKeyOnly'
                    IsInherited = $true
                }
                [pscustomobject]@{
                    SID = 'S-1-1-0'; AccessMask = [uint64]131097
                    AccessControlType = 'Allow'; AppliesTo = 'ThisKeyAndSubkeys'
                    IsInherited = $false
                }
            )

            Get-WindowsAccessControlDscAccessRule `
                -ObjectFamily RegistryKey `
                -Target 'HKLM:\Software\Contoso' `
                -Account Everyone `
                -AccessMask 131097 `
                -AccessControlType Allow `
                -AppliesTo ThisKeyOnly |
                Should -BeFalse
        }

        It 'Should compare inheritance scope case-insensitively' {
            $script:rules = @([pscustomobject]@{
                SID = 'S-1-1-0'; AccessMask = [uint64]131097
                AccessControlType = 'Allow'; AppliesTo = 'ThisKeyOnly'
                IsInherited = $false
            })

            Get-WindowsAccessControlDscAccessRule `
                -ObjectFamily RegistryKey `
                -Target 'HKLM:\Software\Contoso' `
                -Account Everyone `
                -AccessMask 131097 `
                -AccessControlType Allow `
                -AppliesTo thiskeyonly |
                Should -BeTrue
        }

        It 'Should normalize a lowercase NTFS inheritance scope' {
            $script:rules = @([pscustomobject]@{
                SID = 'S-1-1-0'; AccessMask = [uint64]1179785
                AccessRights = [int]1179785; AccessControlType = 'Allow'
                AppliesTo = 'ThisFolderOnly'; IsInherited = $false
            })

            Get-WindowsAccessControlDscAccessRule `
                -ObjectFamily FileSystem `
                -Target 'C:\Data' `
                -Account Everyone `
                -AccessMask 131209 `
                -AccessControlType Allow `
                -AppliesTo thisfolderonly |
                Should -BeTrue
        }

        It 'Should reject an opposite access qualifier' {
            $script:rules = @([pscustomobject]@{
                SID = 'S-1-1-0'; AccessMask = [uint64]4
                AccessControlType = 'Deny'; IsInherited = $false
            })

            Get-WindowsAccessControlDscAccessRule `
                -ObjectFamily Service `
                -Target BITS `
                -Account Everyone `
                -AccessMask 4 `
                -AccessControlType Allow |
                Should -BeFalse
        }

        It 'Should match a Deny NTFS rule without adding Synchronize' {
            $script:rules = @([pscustomobject]@{
                SID = 'S-1-1-0'; AccessMask = [uint64]131209
                AccessRights = [int]131209; AccessControlType = 'Deny'
                AppliesTo = 'ThisFolderOnly'; IsInherited = $false
            })

            Get-WindowsAccessControlDscAccessRule `
                -ObjectFamily FileSystem `
                -Target 'C:\Data' `
                -Account Everyone `
                -AccessMask 131209 `
                -AccessControlType Deny `
                -AppliesTo ThisFolderOnly |
                Should -BeTrue
        }

        It 'Should preserve an unsigned high-bit rights mask' {
            Set-WindowsAccessControlDscAccessRule `
                -ObjectFamily Service `
                -Target BITS `
                -Account Everyone `
                -AccessMask ([uint64]2147483648) `
                -AccessControlType Allow `
                -Ensure Present

            Should -Invoke Add-ServiceAccessRule -Exactly -Times 1 `
                    -ParameterFilter {
                        $ServiceRights -eq [WindowsServiceRights]::GenericRead
                }
        }
    }
}
