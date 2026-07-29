BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'ConvertFrom-WindowsRegistryNativePath' -Tag 'Unit', 'WindowsOnly' {
    It 'Should map <NativePath> to <Expected>' -ForEach @(
        @{ NativePath = 'MACHINE\SOFTWARE\Contoso'; Expected = 'HKLM:\SOFTWARE\Contoso' }
        @{ NativePath = 'CURRENT_USER\Control Panel'; Expected = 'HKCU:\Control Panel' }
        @{ NativePath = 'CLASSES_ROOT\.txt'; Expected = 'HKCR:\.txt' }
        @{ NativePath = 'USERS\.DEFAULT'; Expected = 'HKU:\.DEFAULT' }
        @{ NativePath = 'MACHINE'; Expected = 'HKLM:' }
    ) {
        InModuleScope WindowsAccessControl -Parameters @{
            NativePath = $NativePath
            Expected   = $Expected
        } {
            ConvertFrom-WindowsRegistryNativePath $NativePath |
                Should -BeExactly $Expected
        }
    }

    It 'Should return null for an absent ancestor name' {
        InModuleScope WindowsAccessControl {
            ($null -eq (ConvertFrom-WindowsRegistryNativePath $null)) | Should -BeTrue
            ($null -eq (ConvertFrom-WindowsRegistryNativePath '')) | Should -BeTrue
        }
    }

    It 'Should return null for the unsupported native form <NativePath>' -ForEach @(
        @{ NativePath = 'BOGUS\Sub' }
        @{ NativePath = '\MACHINE\SOFTWARE' }
        @{ NativePath = '\\server\MACHINE\SOFTWARE' }
    ) {
        InModuleScope WindowsAccessControl -Parameters @{
            NativePath = $NativePath
        } {
            ($null -eq (ConvertFrom-WindowsRegistryNativePath $NativePath)) |
                Should -BeTrue
        }
    }
}

Describe 'Get-WindowsRegistryKeyInheritanceSource' -Tag 'Unit', 'WindowsOnly' {
    It 'Should skip the native lookup for the <RegistryView> view' -ForEach @(
        @{ RegistryView = 'Registry32'; NativeObjectType = 12 }
        @{ RegistryView = 'Registry64'; NativeObjectType = 13 }
    ) {
        InModuleScope WindowsAccessControl -Parameters @{
            NativeObjectType = $NativeObjectType
        } {
            Mock Initialize-WindowsAccessControlNativeType {}

            $target = [pscustomobject]@{
                ObjectType       = 'RegistryKey'
                NativePath       = 'MACHINE\SOFTWARE\Contoso'
                NativeObjectType = $NativeObjectType
            }
            $result = Get-WindowsRegistryKeyInheritanceSource `
                -Target $target `
                -SecurityDescriptor ([byte[]]@(1, 2, 3))

            $result | Should -HaveCount 0
            Should -Invoke Initialize-WindowsAccessControlNativeType -Times 0 -Exactly
        }
    }

    It 'Should reject an unsupported object type in the native entry point' {
        InModuleScope WindowsAccessControl {
            Initialize-WindowsAccessControlNativeType
            $descriptor = (Get-Acl -LiteralPath 'HKCU:\Control Panel').
                GetSecurityDescriptorBinaryForm()

            {
                [WindowsAccessControl.NativeMethods]::GetRegistryKeyAccessRuleInheritanceSources(
                    'CURRENT_USER\Control Panel',
                    [uint32]13,
                    $descriptor
                )
            } | Should -Throw -ExpectedMessage '*SE_REGISTRY_KEY*'
        }
    }
}

Describe 'ConvertTo-WindowsAclRuleObject' -Tag 'Unit', 'WindowsOnly' {    It 'Should drop an inheritance source that belongs to an explicit rule' {
        InModuleScope WindowsAccessControl {
            $ace = [System.Security.AccessControl.CommonAce]::new(
                [System.Security.AccessControl.AceFlags]::None,
                [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                131097,
                [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                $false,
                $null
            )
            $target = [pscustomobject]@{
                ObjectType = 'RegistryKey'
                Path       = 'HKLM:\SOFTWARE\Contoso\Child'
            }

            $result = ConvertTo-WindowsAclRuleObject `
                -Ace $ace `
                -Target $target `
                -RuleType 'Access' `
                -TypeName 'WindowsAccessControl.RegistryKeyAccessRule' `
                -RightsType ([System.Security.AccessControl.RegistryRights]) `
                -SupportsInheritance $true `
                -InheritedFrom 'HKLM:\SOFTWARE\Contoso'

            $result.IsInherited | Should -BeFalse
            ($null -eq $result.InheritedFrom) | Should -BeTrue
        }
    }

    It 'Should report the inheritance source of an inherited rule' {
        InModuleScope WindowsAccessControl {
            $ace = [System.Security.AccessControl.CommonAce]::new(
                [System.Security.AccessControl.AceFlags]::Inherited -bor
                    [System.Security.AccessControl.AceFlags]::ContainerInherit,
                [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                131097,
                [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                $false,
                $null
            )
            $target = [pscustomobject]@{
                ObjectType = 'RegistryKey'
                Path       = 'HKLM:\SOFTWARE\Contoso\Child'
            }

            $result = ConvertTo-WindowsAclRuleObject `
                -Ace $ace `
                -Target $target `
                -RuleType 'Access' `
                -TypeName 'WindowsAccessControl.RegistryKeyAccessRule' `
                -RightsType ([System.Security.AccessControl.RegistryRights]) `
                -SupportsInheritance $true `
                -InheritedFrom 'HKLM:\SOFTWARE\Contoso'

            $result.IsInherited | Should -BeTrue
            $result.InheritedFrom | Should -BeExactly 'HKLM:\SOFTWARE\Contoso'
        }
    }

    It 'Should leave the inheritance source empty when no source is supplied' {
        InModuleScope WindowsAccessControl {
            $ace = [System.Security.AccessControl.CommonAce]::new(
                [System.Security.AccessControl.AceFlags]::Inherited,
                [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                131097,
                [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                $false,
                $null
            )
            $target = [pscustomobject]@{ ObjectType = 'Service'; ServiceName = 'Spooler' }

            $result = ConvertTo-WindowsAclRuleObject `
                -Ace $ace `
                -Target $target `
                -RuleType 'Access' `
                -TypeName 'WindowsAccessControl.ServiceAccessRule' `
                -RightsType ([WindowsServiceRights])

            $result.IsInherited | Should -BeTrue
            ($null -eq $result.InheritedFrom) | Should -BeTrue
        }
    }
}

Describe 'Get-WindowsAclRule registry provenance failure' -Tag 'Unit', 'WindowsOnly' {
    It 'Should report rules without provenance when <Reason>' -ForEach @(
        @{
            Reason = 'the ancestor lookup fails'
            Source = { throw 'The ancestor key is unavailable.' }
        }
        @{
            Reason = 'the source count does not match the ACL'
            Source = { , [string[]]@('HKCU:\Control Panel') }
        }
    ) {
        InModuleScope WindowsAccessControl -Parameters @{ Source = $Source } {
            Mock Get-WindowsRegistryKeyInheritanceSource $Source

            $parameters = @{
                Target   = Resolve-RegistryKeyTarget -Path 'HKCU:\Control Panel'
                RuleType = 'Access'
                TypeName = 'WindowsAccessControl.RegistryKeyAccessRule'
            }
            $lookupErrors = $null
            $result = @(Get-WindowsAclRule @parameters `
                -ErrorAction SilentlyContinue `
                -ErrorVariable lookupErrors)

            $result.Count | Should -BeGreaterThan 1
            @($result | Where-Object { $null -ne $_.InheritedFrom }) | Should -HaveCount 0
            @($lookupErrors | Where-Object {
                "$_" -match 'without an inheritance source'
            }) | Should -HaveCount 1
        }
    }
}
