BeforeDiscovery {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
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
            Mock Get-SmbShareAccessRule { $script:rules }
            Mock Get-ADObjectAccessRule { $script:rules }
            Mock Get-TaskFolderAccessRule { $script:rules }
            Mock Get-ScheduledTaskAccessRule { $script:rules }
            Mock Get-CertificatePrivateKeyAccessRule { $script:rules }
            Mock Resolve-WindowsADServer { 'dc01.contoso.test' }
            Mock Add-NTFSAccessRule
            Mock Add-RegistryKeyAccessRule
            Mock Add-ServiceAccessRule
            Mock Add-ProcessAccessRule
            Mock Add-SmbShareAccessRule
            Mock Add-ADObjectAccessRule
            Mock Add-TaskFolderAccessRule
            Mock Add-ScheduledTaskAccessRule
            Mock Add-CertificatePrivateKeyAccessRule
            Mock Remove-NTFSAccessRule
            Mock Remove-RegistryKeyAccessRule
            Mock Remove-ServiceAccessRule
            Mock Remove-ProcessAccessRule
            Mock Remove-SmbShareAccessRule
            Mock Remove-ADObjectAccessRule
            Mock Remove-TaskFolderAccessRule
            Mock Remove-ScheduledTaskAccessRule
            Mock Remove-CertificatePrivateKeyAccessRule
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
            @{
                ObjectFamily = 'SmbShare'; Target = 'WacLab$'; Mask = 1179785
                AppliesTo = $null; GetCommand = 'Get-SmbShareAccessRule'
            }
            @{
                ObjectFamily = 'ADObject'
                Target = 'CN=Test,OU=Targets,DC=contoso,DC=test'; Mask = 16
                AppliesTo = $null; GetCommand = 'Get-ADObjectAccessRule'
            }
            @{
                ObjectFamily = 'TaskFolder'; Target = '\Operations'; Mask = 33
                AppliesTo = 'ThisFolderOnly'; GetCommand = 'Get-TaskFolderAccessRule'
            }
            @{
                ObjectFamily = 'ScheduledTask'; Target = '\Operations'; Mask = 32
                AppliesTo = $null; GetCommand = 'Get-ScheduledTaskAccessRule'
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
                InheritanceType = 'None'
                ObjectTypeGuid = [guid]::Empty
                InheritedObjectTypeGuid = [guid]::Empty
            }
            $script:rules = @(
                [pscustomobject]@{
                    SID = 'S-1-1-0'; AccessMask = [uint64]($storedMask + 1)
                    AccessRights = [int]($storedMask + 1)
                    AccessControlType = 'Allow'; AppliesTo = $AppliesTo
                    IsInherited = $false
                    InheritanceType = 'None'
                    ObjectTypeGuid = [guid]::Empty
                    InheritedObjectTypeGuid = [guid]::Empty
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
            if ($ObjectFamily -eq 'ScheduledTask') { $parameters.TaskName = 'Cleanup' }
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
            @{ ObjectFamily = 'SmbShare'; Target = 'WacLab$'; Mask = 1179785; AppliesTo = $null; AddCommand = 'Add-SmbShareAccessRule' }
            @{ ObjectFamily = 'ADObject'; Target = 'CN=Test,OU=Targets,DC=contoso,DC=test'; Mask = 16; AppliesTo = $null; AddCommand = 'Add-ADObjectAccessRule' }
            @{ ObjectFamily = 'TaskFolder'; Target = '\Operations'; Mask = 33; AppliesTo = 'ThisFolderOnly'; AddCommand = 'Add-TaskFolderAccessRule' }
            @{ ObjectFamily = 'ScheduledTask'; Target = '\Operations'; Mask = 32; AppliesTo = $null; AddCommand = 'Add-ScheduledTaskAccessRule' }
        ) {
            $parameters = @{
                ObjectFamily = $ObjectFamily; Account = 'Everyone'
                AccessMask = [uint64]$Mask; AccessControlType = 'Allow'
                Ensure = 'Present'
            }
            if ($Target) { $parameters.Target = $Target }
            if ($AppliesTo) { $parameters.AppliesTo = $AppliesTo }
            if ($ObjectFamily -eq 'RegistryKey') { $parameters.RegistryView = 'Default' }
            if ($ObjectFamily -eq 'ADObject') {
                $parameters.AllowedBaseDistinguishedName = 'OU=Targets,DC=contoso,DC=test'
            }
            if ($ObjectFamily -in @('TaskFolder', 'ScheduledTask')) {
                $parameters.AllowedRootPath = '\Operations'
            }
            if ($ObjectFamily -eq 'ScheduledTask') { $parameters.TaskName = 'Cleanup' }
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
            @{ ObjectFamily = 'SmbShare'; Target = 'WacLab$'; Mask = 1179785; AppliesTo = $null; RemoveCommand = 'Remove-SmbShareAccessRule' }
            @{ ObjectFamily = 'ADObject'; Target = 'CN=Test,OU=Targets,DC=contoso,DC=test'; Mask = 16; AppliesTo = $null; RemoveCommand = 'Remove-ADObjectAccessRule' }
            @{ ObjectFamily = 'TaskFolder'; Target = '\Operations'; Mask = 33; AppliesTo = 'ThisFolderOnly'; RemoveCommand = 'Remove-TaskFolderAccessRule' }
            @{ ObjectFamily = 'ScheduledTask'; Target = '\Operations'; Mask = 32; AppliesTo = $null; RemoveCommand = 'Remove-ScheduledTaskAccessRule' }
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
                InheritanceType = 'None'
                ObjectTypeGuid = [guid]::Empty
                InheritedObjectTypeGuid = [guid]::Empty
            })
            $parameters = @{
                ObjectFamily = $ObjectFamily; Account = 'Everyone'
                AccessMask = [uint64]$Mask; AccessControlType = 'Allow'
                Ensure = 'Absent'
            }
            if ($Target) { $parameters.Target = $Target }
            if ($AppliesTo) { $parameters.AppliesTo = $AppliesTo }
            if ($ObjectFamily -eq 'RegistryKey') { $parameters.RegistryView = 'Default' }
            if ($ObjectFamily -eq 'ADObject') {
                $parameters.AllowedBaseDistinguishedName = 'OU=Targets,DC=contoso,DC=test'
            }
            if ($ObjectFamily -in @('TaskFolder', 'ScheduledTask')) {
                $parameters.AllowedRootPath = '\Operations'
            }
            if ($ObjectFamily -eq 'ScheduledTask') { $parameters.TaskName = 'Cleanup' }
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

        It 'Should reject a directory rule whose object scope differs' {
            $script:rules = @([pscustomobject]@{
                SID = 'S-1-1-0'; AccessMask = [uint64]16
                AccessControlType = 'Allow'; IsInherited = $false
                InheritanceType = 'None'
                ObjectTypeGuid = [guid]'bf967a86-0de6-11d0-a285-00aa003049e2'
                InheritedObjectTypeGuid = [guid]::Empty
            })

            Get-WindowsAccessControlDscAccessRule `
                -ObjectFamily ADObject `
                -Target 'CN=Test,OU=Targets,DC=contoso,DC=test' `
                -Account Everyone `
                -AccessMask 16 `
                -AccessControlType Allow |
                Should -BeFalse
        }

        It 'Should match a directory rule on both object GUIDs and inheritance' {
            $objectTypeGuid = [guid]'bf967a86-0de6-11d0-a285-00aa003049e2'
            $script:rules = @([pscustomobject]@{
                SID = 'S-1-1-0'; AccessMask = [uint64]16
                AccessControlType = 'Allow'; IsInherited = $false
                InheritanceType = 'Descendents'
                ObjectTypeGuid = $objectTypeGuid
                InheritedObjectTypeGuid = [guid]::Empty
            })

            Get-WindowsAccessControlDscAccessRule `
                -ObjectFamily ADObject `
                -Target 'CN=Test,OU=Targets,DC=contoso,DC=test' `
                -Account Everyone `
                -AccessMask 16 `
                -AccessControlType Allow `
                -InheritanceType Descendents `
                -ObjectTypeGuid $objectTypeGuid |
                Should -BeTrue
        }

        It 'Should require an allowed base before a directory write' {
            {
                Set-WindowsAccessControlDscAccessRule `
                    -ObjectFamily ADObject `
                    -Target 'CN=Test,OU=Targets,DC=contoso,DC=test' `
                    -Account Everyone `
                    -AccessMask 16 `
                    -AccessControlType Allow `
                    -Ensure Present
            } | Should -Throw '*AllowedBaseDistinguishedName*'
            Should -Invoke Add-ADObjectAccessRule -Exactly -Times 0
        }

        It 'Should require an allowed root path before a <ObjectFamily> write' -ForEach @(
            @{ ObjectFamily = 'TaskFolder'; AddCommand = 'Add-TaskFolderAccessRule' }
            @{ ObjectFamily = 'ScheduledTask'; AddCommand = 'Add-ScheduledTaskAccessRule' }
        ) {
            $parameters = @{
                ObjectFamily = $ObjectFamily
                Target = '\Operations'
                Account = 'Everyone'
                AccessMask = [uint64]32
                AccessControlType = 'Allow'
                Ensure = 'Present'
            }
            if ($ObjectFamily -eq 'TaskFolder') { $parameters.AppliesTo = 'ThisFolderOnly' }
            if ($ObjectFamily -eq 'ScheduledTask') { $parameters.TaskName = 'Cleanup' }

            { Set-WindowsAccessControlDscAccessRule @parameters } |
                Should -Throw '*AllowedRootPath*'
            Should -Invoke -CommandName $AddCommand -Exactly -Times 0
        }

        It 'Should reject a task-folder rule whose inheritance scope differs' {
            $script:rules = @([pscustomobject]@{
                SID = 'S-1-1-0'; AccessMask = [uint64]33
                AccessControlType = 'Allow'; AppliesTo = 'ThisFolderAndTasks'
                IsInherited = $false
            })

            Get-WindowsAccessControlDscAccessRule `
                -ObjectFamily TaskFolder `
                -Target '\Operations' `
                -Account Everyone `
                -AccessMask 33 `
                -AccessControlType Allow `
                -AppliesTo ThisFolderOnly |
                Should -BeFalse
        }

        It 'Should match a private-key rule on the effective rights mask' {
            # The provider stores a candidate ACE with the matching generic bit
            # added, so the raw stored mask never equals the requested mask.
            $script:rules = @([pscustomobject]@{
                SID = 'S-1-1-0'
                AccessMask = [uint64]2148663433
                EffectiveAccessMask = [uint64]1179785
                AccessControlType = 'Allow'
                IsInherited = $false
                NativeAce = [pscustomobject]@{
                    AceType = [System.Security.AccessControl.AceType]::AccessAllowed
                }
            })

            Get-WindowsAccessControlDscAccessRule `
                -ObjectFamily CertificatePrivateKey `
                -Target 'WacUnitKey' `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyScope Machine `
                -Account Everyone `
                -AccessMask 1179785 `
                -AccessControlType Allow |
                Should -BeTrue

            Should -Invoke Get-CertificatePrivateKeyAccessRule -Exactly -Times 1 `
                -ParameterFilter {
                    $ProviderName -ceq 'Microsoft Software Key Storage Provider' -and
                        $KeyName -ceq 'WacUnitKey' -and
                        $KeyScope -ceq 'Machine'
                }
        }

        It 'Should match a generic private-key right against its effective mask' {
            # GENERIC_READ is 0x80000000; the ACE it creates reads back as the
            # expanded 0x00120089. Comparing the raw request would report the
            # grant absent and make a removal a silent no-op.
            $script:rules = @([pscustomobject]@{
                SID = 'S-1-1-0'
                AccessMask = [uint64]2148663433
                EffectiveAccessMask = [uint64]1179785
                AccessControlType = 'Allow'
                IsInherited = $false
                NativeAce = [pscustomobject]@{
                    AceType = [System.Security.AccessControl.AceType]::AccessAllowed
                }
            })

            Get-WindowsAccessControlDscAccessRule `
                -ObjectFamily CertificatePrivateKey `
                -Target 'WacUnitKey' `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyScope Machine `
                -Account Everyone `
                -AccessMask ([uint64](
                    [int64][int][WindowsCryptoKeyRights]::GenericRead -band 0xFFFFFFFFL
                )) `
                -AccessControlType Allow |
                Should -BeTrue
        }

        It 'Should not let a conditional allow ACE report a private-key grant as present' {
            $script:rules = @([pscustomobject]@{
                SID = 'S-1-1-0'
                AccessMask = [uint64]2148663433
                EffectiveAccessMask = [uint64]1179785
                AccessControlType = 'Allow'
                IsInherited = $false
                NativeAce = [pscustomobject]@{
                    AceType = [System.Security.AccessControl.AceType]::AccessAllowedCallback
                }
            })

            Get-WindowsAccessControlDscAccessRule `
                -ObjectFamily CertificatePrivateKey `
                -Target 'WacUnitKey' `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyScope Machine `
                -Account Everyone `
                -AccessMask 1179785 `
                -AccessControlType Allow |
                Should -BeFalse
        }

        It 'Should add a missing private-key allow rule by key identity' {
            Set-WindowsAccessControlDscAccessRule `
                -ObjectFamily CertificatePrivateKey `
                -Target 'WacUnitKey' `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyScope Machine `
                -Account Everyone `
                -AccessMask 1179785 `
                -AccessControlType Allow `
                -Ensure Present

            Should -Invoke Add-CertificatePrivateKeyAccessRule -Exactly -Times 1 `
                -ParameterFilter {
                    $ProviderName -ceq 'Microsoft Software Key Storage Provider' -and
                        $KeyName -ceq 'WacUnitKey' -and
                        $KeyScope -ceq 'Machine' -and
                        $Confirm -eq $false
                }
        }

        It 'Should remove a matching private-key rule by its effective rights' {
            $script:rules = @(
                [pscustomobject]@{
                    SID = 'S-1-1-0'
                    AccessMask = [uint64]2148663433
                    EffectiveAccessMask = [uint64]1179785
                    AccessControlType = 'Allow'
                    IsInherited = $false
                    NativeAce = [pscustomobject]@{
                        AceType = [System.Security.AccessControl.AceType]::AccessAllowed
                    }
                }
                [pscustomobject]@{
                    SID = 'S-1-1-0'
                    AccessMask = [uint64]2148663433
                    EffectiveAccessMask = [uint64]1179785
                    AccessControlType = 'Allow'
                    IsInherited = $false
                    NativeAce = [pscustomobject]@{
                        AceType = [System.Security.AccessControl.AceType]::AccessAllowed
                    }
                }
            )

            Set-WindowsAccessControlDscAccessRule `
                -ObjectFamily CertificatePrivateKey `
                -Target 'WacUnitKey' `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyScope Machine `
                -Account Everyone `
                -AccessMask 1179785 `
                -AccessControlType Allow `
                -Ensure Absent

            # One removal clears every duplicate, so a second call would only
            # produce the warning that a revocation matched nothing.
            Should -Invoke Remove-CertificatePrivateKeyAccessRule -Exactly -Times 1 `
                -ParameterFilter {
                    $KeyName -ceq 'WacUnitKey' -and
                        [long][int]$AccessRights -eq 1179785 -and
                        $Confirm -eq $false
                }
        }

        It 'Should refuse to create a private-key deny rule' {
            {
                Set-WindowsAccessControlDscAccessRule `
                    -ObjectFamily CertificatePrivateKey `
                    -Target 'WacUnitKey' `
                    -ProviderName 'Microsoft Software Key Storage Provider' `
                    -KeyScope Machine `
                    -Account Everyone `
                    -AccessMask 1179785 `
                    -AccessControlType Deny `
                    -Ensure Present
            } | Should -Throw '*deny rule cannot be created*'
            Should -Invoke Add-CertificatePrivateKeyAccessRule -Exactly -Times 0
        }
    }
}
