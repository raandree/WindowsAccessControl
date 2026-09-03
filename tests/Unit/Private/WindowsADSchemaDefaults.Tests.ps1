BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
    $script:module = Get-Module WindowsAccessControl
    $script:domainSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-11-22-33')
    $script:rootSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-44-55-66')
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

    It 'Should return the single GUID a name resolved to' {
        & $script:module {
            Select-WindowsADObjectTypeGuid `
                -Found ([guid[]]@('bf967aba-0de6-11d0-a285-00aa003049e2')) `
                -Name 'user' `
                -ParameterName 'ObjectType'
        } | Should -Be ([guid]'bf967aba-0de6-11d0-a285-00aa003049e2')
    }

    It 'Should refuse a name that matched nothing' {
        {
            & $script:module {
                Select-WindowsADObjectTypeGuid `
                    -Found ([guid[]]@()) `
                    -Name 'noSuchName' `
                    -ParameterName 'ObjectType'
            }
        } | Should -Throw -ExpectedMessage '*does not name an Active Directory schema class*'
    }

    It 'Should refuse a name that matched more than one GUID' {
        # A stock schema holds no ambiguous name, so this refusal has no live
        # path. It still has to be proven, because an ambiguous name that
        # silently picked one GUID would scope an entry to the wrong property.
        {
            & $script:module {
                Select-WindowsADObjectTypeGuid `
                    -Found ([guid[]]@(
                            'bf967aba-0de6-11d0-a285-00aa003049e2'
                            'bf967a9c-0de6-11d0-a285-00aa003049e2'
                        )) `
                    -Name 'ambiguous' `
                    -ParameterName 'ObjectType'
            }
        } | Should -Throw -ExpectedMessage '*names more than one Active Directory GUID*'
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

Describe 'Schema default subtraction' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        # A rule shaped like the two families the matcher compares. Only the six
        # fields ADR 0033 names are read, so a double carries nothing else.
        function Get-TestRule {
            param(
                [string]$SID = 'S-1-5-21-11-22-33-1105',
                [uint64]$AccessMask = 0x20,
                [string]$AccessControlType = 'Allow',
                [string]$InheritanceType = 'None',
                [guid]$ObjectTypeGuid = [guid]::Empty,
                [guid]$InheritedObjectTypeGuid = [guid]::Empty,
                [bool]$IsInherited = $false,
                [string]$Marker = ''
            )

            [pscustomobject]@{
                SID = $SID
                AccessMask = $AccessMask
                AccessControlType = $AccessControlType
                InheritanceType = $InheritanceType
                ObjectTypeGuid = $ObjectTypeGuid
                InheritedObjectTypeGuid = $InheritedObjectTypeGuid
                IsInherited = $IsInherited
                Marker = $Marker
            }
        }

        function Select-TestResult {
            param($Rule, $SchemaDefault)

            & $script:module {
                param($InputRule, $InputDefault)
                Select-WindowsADNonDefaultAccessRule `
                    -Rule ([object[]]@($InputRule)) `
                    -SchemaDefault ([object[]]@($InputDefault))
            } $Rule $SchemaDefault
        }
    }

    It 'Should drop an explicit entry the class template already grants' {
        $result = @(Select-TestResult `
                -Rule @((Get-TestRule), (Get-TestRule -SID 'S-1-5-21-11-22-33-4999' -Marker 'operator')) `
                -SchemaDefault @(Get-TestRule))

        $result | Should -HaveCount 1
        $result[0].Marker | Should -BeExactly 'operator'
    }

    It 'Should report everything when the class carries no template' {
        $result = @(Select-TestResult -Rule @(Get-TestRule) -SchemaDefault @())

        $result | Should -HaveCount 1
    }

    It 'Should refuse to match a creator placeholder in the template' {
        # Case 1. The template entry became the creating principal's own entry,
        # and nothing on the object separates that from an operator grant, so
        # the placeholder is dropped from the baseline and hides nothing. The
        # literal placeholder entry is reported for the same reason.
        $result = @(Select-TestResult `
                -Rule @(
                (Get-TestRule -SID 'S-1-5-21-11-22-33-1105' -Marker 'creator')
                (Get-TestRule -SID 'S-1-3-0' -Marker 'literal')
            ) `
                -SchemaDefault @(Get-TestRule -SID 'S-1-3-0'))

        @($result.Marker) | Should -Be @('creator', 'literal')
    }

    It 'Should still match the trustee that is not a placeholder' {
        # S-1-3-4 is OWNER RIGHTS, a real trustee in the same authority.
        $result = @(Select-TestResult `
                -Rule @(Get-TestRule -SID 'S-1-3-4') `
                -SchemaDefault @(Get-TestRule -SID 'S-1-3-4'))

        $result | Should -BeNullOrEmpty
    }

    It 'Should match SELF verbatim because the template keeps that identifier' {
        # Case 2, the direction that does match.
        $result = @(Select-TestResult `
                -Rule @(Get-TestRule -SID 'S-1-5-10') `
                -SchemaDefault @(Get-TestRule -SID 'S-1-5-10'))

        $result | Should -BeNullOrEmpty
    }

    It 'Should report a SELF entry that differs in anything but the trustee' {
        # Case 2, the over-match the security identifier alone would cause.
        $result = @(Select-TestResult `
                -Rule @(Get-TestRule -SID 'S-1-5-10' -AccessMask 0x30 -Marker 'widened') `
                -SchemaDefault @(Get-TestRule -SID 'S-1-5-10'))

        $result | Should -HaveCount 1
        $result[0].Marker | Should -BeExactly 'widened'
    }

    It 'Should ignore flags outside the inheritance semantics' {
        # Case 3. The rule objects carry an unrelated property difference and a
        # matching InheritanceType, which is all the comparison reads.
        $candidate = Get-TestRule -InheritanceType 'All' -Marker 'propagated'
        $candidate | Add-Member -NotePropertyName 'AceFlags' -NotePropertyValue 'ContainerInherit, Inherited'
        $result = @(Select-TestResult `
                -Rule @($candidate) `
                -SchemaDefault @(Get-TestRule -InheritanceType 'All'))

        $result | Should -BeNullOrEmpty
    }

    It 'Should report an entry whose inheritance semantics differ' {
        $result = @(Select-TestResult `
                -Rule @(Get-TestRule -InheritanceType 'Descendents') `
                -SchemaDefault @(Get-TestRule -InheritanceType 'All'))

        $result | Should -HaveCount 1
    }

    It 'Should never hide an inherited entry' {
        # Case 3, second part. An identical inherited entry came from an
        # ancestor, not from this object's class default.
        $result = @(Select-TestResult `
                -Rule @(Get-TestRule -IsInherited $true -Marker 'ancestor') `
                -SchemaDefault @(Get-TestRule))

        $result | Should -HaveCount 1
        $result[0].Marker | Should -BeExactly 'ancestor'
    }

    It 'Should report an entry a later template no longer describes' {
        # Case 4. Every readable form of schema drift leaves an entry that
        # matches nothing, which is the direction the bias requires.
        $result = @(Select-TestResult `
                -Rule @(Get-TestRule -AccessMask 0x10 -Marker 'older template') `
                -SchemaDefault @(Get-TestRule -AccessMask 0x20))

        $result | Should -HaveCount 1
        $result[0].Marker | Should -BeExactly 'older template'
    }

    It 'Should separate entries that differ only in one compared field' {
        $baseline = Get-TestRule `
            -ObjectTypeGuid 'bf967aba-0de6-11d0-a285-00aa003049e2' `
            -InheritedObjectTypeGuid 'bf967a9c-0de6-11d0-a285-00aa003049e2'
        $variants = @(
            Get-TestRule -SID 'S-1-5-21-11-22-33-4999' -Marker 'trustee'
            Get-TestRule -AccessMask 0x21 -Marker 'mask'
            Get-TestRule -AccessControlType 'Deny' -Marker 'type'
            Get-TestRule -InheritanceType 'Children' -Marker 'inheritance'
            Get-TestRule -ObjectTypeGuid 'bf967a9c-0de6-11d0-a285-00aa003049e2' -Marker 'objectType'
            Get-TestRule -InheritedObjectTypeGuid 'bf967aba-0de6-11d0-a285-00aa003049e2' -Marker 'inheritedObjectType'
        )

        $result = @(Select-TestResult -Rule $variants -SchemaDefault @($baseline, (Get-TestRule)))

        @($result.Marker) | Should -Be @(
            'trustee', 'mask', 'type', 'inheritance', 'objectType', 'inheritedObjectType'
        )
    }
}
