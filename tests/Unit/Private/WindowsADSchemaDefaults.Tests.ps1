BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module WindowsAccessControl
    $script:domainSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-11-22-33')
    $script:rootSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-44-55-66')
}

AfterAll {
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'Active Directory schema default internals' -Tag 'Unit', 'WindowsOnly' {
    It 'Should expand a domain-relative alias against the domain that owns it' {
        $expanded = & $script:module {
            param($Domain, $Root)
            ConvertTo-WindowsADAbsoluteSddl `
                -Sddl 'O:DAG:DAD:(A;;RPWP;;;DA)(A;;RPLCLORC;;;AU)(A;;RPWP;;;EA)' `
                -DomainSid $Domain `
                -RootDomainSid $Root
        } $script:domainSid $script:rootSid

        $expanded | Should -BeExactly (
            'O:S-1-5-21-11-22-33-512G:S-1-5-21-11-22-33-512' +
            'D:(A;;RPWP;;;S-1-5-21-11-22-33-512)(A;;RPLCLORC;;;AU)' +
            '(A;;RPWP;;;S-1-5-21-44-55-66-519)'
        )
    }

    It 'Should parse an expanded schema default on a machine with no domain' {
        $descriptor = & $script:module {
            param($Domain, $Root)
            [Security.AccessControl.RawSecurityDescriptor]::new(
                (ConvertTo-WindowsADAbsoluteSddl `
                    -Sddl 'D:(A;;RPWP;;;DA)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)' `
                    -DomainSid $Domain `
                    -RootDomainSid $Root)
            )
        } $script:domainSid $script:rootSid

        @($descriptor.DiscretionaryAcl.SecurityIdentifier.Value) |
            Should -Be @('S-1-5-21-11-22-33-512', 'S-1-5-10')
    }

    It 'Should replace only the trustee field of an access control entry' {
        # The rights field of this entry spells DA, and the object GUID contains
        # the letters of another alias. Neither may be rewritten.
        & $script:module {
            param($Domain)
            ConvertTo-WindowsADAbsoluteSddl `
                -Sddl 'D:(A;;DADCLCRP;;;AU)' `
                -DomainSid $Domain
        } $script:domainSid | Should -BeExactly 'D:(A;;DADCLCRP;;;AU)'
    }

    It 'Should refuse a forest-root alias when the root domain SID is unknown' {
        {
            & $script:module {
                param($Domain)
                ConvertTo-WindowsADAbsoluteSddl `
                    -Sddl 'D:(A;;RPWP;;;EA)' `
                    -DomainSid $Domain `
                    -RootDomainSid $null
            } $script:domainSid
        } | Should -Throw -ExpectedMessage '*forest-root alias*'
    }

    It 'Should escape every LDAP filter metacharacter' {
        & $script:module {
            ConvertTo-WindowsADLdapFilterValue -Value 'a(b)c*d\e'
        } | Should -BeExactly 'a\28b\29c\2ad\5ce'
    }

    It 'Should describe a schema default entry without binding it to a target' {
        $rule = & $script:module {
            $ace = [Security.AccessControl.CommonAce]::new(
                [Security.AccessControl.AceFlags]::ContainerInherit,
                [Security.AccessControl.AceQualifier]::AccessAllowed,
                16,
                [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                $false,
                $null
            )
            ConvertTo-WindowsADSchemaDefaultRuleObject `
                -Ace $ace `
                -ObjectClass 'user' `
                -Server 'dc01.example.test'
        }

        $rule.PSObject.TypeNames[0] |
            Should -BeExactly 'WindowsAccessControl.ADSchemaDefaultAccessRule'
        $rule.ObjectClass | Should -BeExactly 'user'
        $rule.SID | Should -BeExactly 'S-1-1-0'
        $rule.InheritanceType | Should -Be 'All'
        $rule.PSObject.Properties.Name | Should -Not -Contain 'DistinguishedName'
    }
}

Describe 'Active Directory object type resolution' -Tag 'Unit', 'WindowsOnly' {
    It 'Should return the empty GUID for an omitted object type' {
        $resolved = & $script:module {
            Resolve-WindowsADObjectTypeGuid -ObjectType '' -InheritedObjectType $null
        }

        $resolved.ObjectType | Should -Be ([guid]::Empty)
        $resolved.InheritedObjectType | Should -Be ([guid]::Empty)
    }

    It 'Should parse a supplied GUID without contacting a domain controller' {
        $resolved = & $script:module {
            Resolve-WindowsADObjectTypeGuid `
                -ObjectType 'bf967aba-0de6-11d0-a285-00aa003049e2' `
                -InheritedObjectType '{bf967a9c-0de6-11d0-a285-00aa003049e2}'
        }

        $resolved.ObjectType |
            Should -Be ([guid]'bf967aba-0de6-11d0-a285-00aa003049e2')
        $resolved.InheritedObjectType |
            Should -Be ([guid]'bf967a9c-0de6-11d0-a285-00aa003049e2')
    }

    It 'Should refuse a name it cannot look up rather than widening the scope' {
        {
            & $script:module {
                Resolve-WindowsADObjectTypeGuid -ObjectType 'User-Account-Control'
            }
        } | Should -Throw -ExpectedMessage '*requires a domain controller*'
    }
}

Describe 'Active Directory rights mask binding' -Tag 'Unit', 'WindowsOnly' {
    It 'Should keep a rights bit the enum cannot name' {
        $rights = & $script:module {
            $attribute = [WindowsAccessRightsTransformAttribute]::new(
                [WindowsActiveDirectoryRights]
            )
            $attribute.Transform($null, 0x10000000)
        }

        $rights | Should -BeOfType ([WindowsActiveDirectoryRights])
        [int]$rights | Should -Be 0x10000000
    }

    It 'Should still convert rights names and reject an unknown name' {
        & $script:module {
            $attribute = [WindowsAccessRightsTransformAttribute]::new(
                [WindowsActiveDirectoryRights]
            )
            [int]$attribute.Transform($null, 'ReadProperty, WriteProperty')
        } | Should -Be 0x30

        {
            & $script:module {
                $attribute = [WindowsAccessRightsTransformAttribute]::new(
                    [WindowsActiveDirectoryRights]
                )
                $attribute.Transform($null, 'NotARight')
            }
        } | Should -Throw
    }

    It 'Should not declare a rights type that would preempt the transform' {
        # A declared enum type adds ArgumentTypeConverterAttribute, which runs
        # first and refuses an unnameable mask before the transform is reached.
        foreach ($name in 'Add-ADObjectAccessRule', 'Set-ADObjectAccessRule',
            'Remove-ADObjectAccessRule') {
            $attributes = @(
                (Get-Command -Name $name -Module 'WindowsAccessControl'
                ).Parameters['AccessRights'].Attributes |
                    ForEach-Object { $_.GetType().Name }
            )

            $attributes | Should -Contain 'WindowsAccessRightsTransformAttribute'
            $attributes | Should -Not -Contain 'ArgumentTypeConverterAttribute' `
                -Because "$name must reach its rights transform"
        }
    }
}
