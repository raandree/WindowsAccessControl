BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module WindowsAccessControl
}

AfterAll {
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'Active Directory access-control internals' -Tag 'Unit', 'WindowsOnly' {
    It 'Should decode LDAP byte-array attribute values as UTF-8 strings' {
        & $script:module {
            $bytes = [Text.Encoding]::UTF8.GetBytes('organizationalUnit')
            ConvertFrom-WindowsADAttributeValue -Value $bytes
        } | Should -BeExactly 'organizationalUnit'
    }

    It 'Should accept only explicit DNS domain-controller authority' {
        & $script:module {
            Resolve-WindowsADServerName -Server 'dc01.example.test'
        } | Should -BeExactly 'dc01.example.test'

        foreach ($invalidServer in 'dc01', '127.0.0.1', 'localhost', 'ldap://dc01.example.test') {
            {
                & $script:module {
                    param($Server)
                    Resolve-WindowsADServerName -Server $Server
                } $invalidServer
            } | Should -Throw
        }
    }

    It 'Should compare distinguished-name boundaries without accepting siblings' {
        & $script:module {
            Test-WindowsADDistinguishedNameWithinBase `
                -DistinguishedName 'OU=Targets,DC=example,DC=test' `
                -BaseDistinguishedName 'OU=Targets,DC=example,DC=test'
        } | Should -BeTrue
        & $script:module {
            Test-WindowsADDistinguishedNameWithinBase `
                -DistinguishedName 'CN=User,OU=Targets,DC=example,DC=test' `
                -BaseDistinguishedName 'OU=Targets,DC=example,DC=test'
        } | Should -BeTrue
        & $script:module {
            Test-WindowsADDistinguishedNameWithinBase `
                -DistinguishedName 'OU=Other,DC=example,DC=test' `
                -BaseDistinguishedName 'OU=Targets,DC=example,DC=test'
        } | Should -BeFalse
    }

    It 'Should reject configuration and schema partition distinguished names' {
        $rootDse = [pscustomobject]@{
            DefaultNamingContext = 'DC=example,DC=test'
            ConfigurationNamingContext = 'CN=Configuration,DC=example,DC=test'
            SchemaNamingContext = 'CN=Schema,CN=Configuration,DC=example,DC=test'
        }

        foreach ($distinguishedName in @(
                'CN=Configuration,DC=example,DC=test'
                'CN=Services,CN=Configuration,DC=example,DC=test'
                'CN=Schema,CN=Configuration,DC=example,DC=test'
            )) {
            & $script:module {
                param($DistinguishedName, $RootDse)
                Test-WindowsADExcludedPartition `
                    -DistinguishedName $DistinguishedName `
                    -RootDse $RootDse
            } $distinguishedName $rootDse | Should -BeTrue
        }
        & $script:module {
            param($RootDse)
            Test-WindowsADExcludedPartition `
                -DistinguishedName 'OU=Lab,DC=example,DC=test' `
                -RootDse $RootDse
        } $rootDse | Should -BeFalse
    }

    It 'Should classify protected AD containers, descendants, and adminCount objects' {
        $rootDse = [pscustomobject]@{
            DefaultNamingContext = 'DC=example,DC=test'
        }
        $protectedRecords = @(
            [pscustomobject]@{
                DistinguishedName = 'CN=Server,OU=Domain Controllers,DC=example,DC=test'
                ObjectClasses = @('top', 'computer')
                AdminCount = $false
            }
            [pscustomobject]@{
                DistinguishedName = 'CN=Policies,CN=System,DC=example,DC=test'
                ObjectClasses = @('top', 'container')
                AdminCount = $false
            }
            [pscustomobject]@{
                DistinguishedName = 'CN=Admin,OU=Lab,DC=example,DC=test'
                ObjectClasses = @('top', 'user')
                AdminCount = $true
            }
            [pscustomobject]@{
                DistinguishedName = 'CN={00000000-0000-0000-0000-000000000000},OU=Lab,DC=example,DC=test'
                ObjectClasses = @('top', 'groupPolicyContainer')
                AdminCount = $false
            }
        )

        foreach ($record in $protectedRecords) {
            & $script:module {
                param($Record, $RootDse)
                Test-WindowsADProtectedTarget -Record $Record -RootDse $RootDse
            } $record $rootDse | Should -BeTrue
        }
        & $script:module {
            param($RootDse)
            Test-WindowsADProtectedTarget `
                -Record ([pscustomobject]@{
                    DistinguishedName = 'OU=Lab,DC=example,DC=test'
                    ObjectClasses = @('top', 'organizationalUnit')
                    AdminCount = $false
                }) `
                -RootDse $RootDse
        } $rootDse | Should -BeFalse
    }

    It 'Should map every AD inheritance value to the expected native ACE flags' {
        $expected = @{
            None = [int][Security.AccessControl.AceFlags]::None
            All = [int][Security.AccessControl.AceFlags]::ContainerInherit
            Descendents = (
                [int][Security.AccessControl.AceFlags]::ContainerInherit -bor
                [int][Security.AccessControl.AceFlags]::InheritOnly
            )
            SelfAndChildren = (
                [int][Security.AccessControl.AceFlags]::ContainerInherit -bor
                [int][Security.AccessControl.AceFlags]::NoPropagateInherit
            )
            Children = (
                [int][Security.AccessControl.AceFlags]::ContainerInherit -bor
                [int][Security.AccessControl.AceFlags]::InheritOnly -bor
                [int][Security.AccessControl.AceFlags]::NoPropagateInherit
            )
        }

        foreach ($name in $expected.Keys) {
            $actual = & $script:module {
                param($InheritanceType)
                ConvertTo-WindowsADAceFlag -InheritanceType $InheritanceType
            } $name
            [int]$actual | Should -Be $expected[$name]
        }
    }

    It 'Should add and exactly remove an object ACE without flattening it' {
        $sid = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        $existingObjectType = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
        $newObjectType = [guid]'bf967a9c-0de6-11d0-a285-00aa003049e2'
        $acl = [Security.AccessControl.RawAcl]::new(
            [Security.AccessControl.GenericAcl]::AclRevisionDS,
            1
        )
        $acl.InsertAce(0, [Security.AccessControl.ObjectAce]::new(
            [Security.AccessControl.AceFlags]::ContainerInherit,
            [Security.AccessControl.AceQualifier]::AccessAllowed,
            16,
            $sid,
            [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
            $existingObjectType,
            [guid]::Empty,
            $false,
            $null
        ))
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent,
            $sid,
            $sid,
            $null,
            $acl
        )
        $bytes = [byte[]]::new($descriptor.BinaryLength)
        $descriptor.GetBinaryForm($bytes, 0)

        $addedBytes = & $script:module {
            param($Descriptor, $Sid, $ObjectType)
            Invoke-WindowsADAccessRuleMutation `
                -SecurityDescriptor $Descriptor `
                -Operation Add `
                -SecurityIdentifier $Sid `
                -AccessMask 32 `
                -AccessControlType Allow `
                -InheritanceType None `
                -ObjectType $ObjectType
        } $bytes $sid $newObjectType
        $addedDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            $addedBytes,
            0
        )
        $addedDescriptor.DiscretionaryAcl.Count | Should -Be 2
        $objectTypes = @(
            $addedDescriptor.DiscretionaryAcl |
                Where-Object { $_ -is [Security.AccessControl.ObjectAce] } |
                ForEach-Object ObjectAceType
        )
        $objectTypes | Should -Contain $existingObjectType
        $objectTypes | Should -Contain $newObjectType

        $addedAce = @(
            $addedDescriptor.DiscretionaryAcl |
                Where-Object {
                    $_ -is [Security.AccessControl.ObjectAce] -and
                    $_.ObjectAceType -eq $newObjectType
                }
        )[0]
        $removedBytes = & $script:module {
            param($Descriptor, $NativeAce)
            Invoke-WindowsADAccessRuleMutation `
                -SecurityDescriptor $Descriptor `
                -Operation Remove `
                -NativeAce $NativeAce
        } $addedBytes $addedAce
        $removedDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            $removedBytes,
            0
        )
        $removedDescriptor.DiscretionaryAcl.Count | Should -Be 1
        ([Security.AccessControl.ObjectAce]$removedDescriptor.DiscretionaryAcl[0]).ObjectAceType |
            Should -Be $existingObjectType
    }

    It 'Should treat exact removal of an absent AD ACE as an idempotent no-op' {
        $sid = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        $acl = [Security.AccessControl.RawAcl]::new(
            [Security.AccessControl.GenericAcl]::AclRevisionDS,
            0
        )
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent,
            $sid,
            $sid,
            $null,
            $acl
        )
        $bytes = [byte[]]::new($descriptor.BinaryLength)
        $descriptor.GetBinaryForm($bytes, 0)
        $absentAce = [Security.AccessControl.CommonAce]::new(
            [Security.AccessControl.AceFlags]::None,
            [Security.AccessControl.AceQualifier]::AccessAllowed,
            16,
            $sid,
            $false,
            $null
        )

        $result = & $script:module {
            param($Descriptor, $NativeAce)
            Invoke-WindowsADAccessRuleMutation `
                -SecurityDescriptor $Descriptor `
                -Operation Remove `
                -NativeAce $NativeAce
        } $bytes $absentAce

        [Convert]::ToBase64String($result) |
            Should -BeExactly ([Convert]::ToBase64String($bytes))
    }

    It 'Should prevalidate every AD write target before batch dispatch' {
        InModuleScope WindowsAccessControl {
            Mock Resolve-WindowsADObjectTarget {
                param($DistinguishedName)
                [pscustomobject]@{
                    CanonicalTarget = "ADObject:DC:$DistinguishedName"
                    DistinguishedName = $DistinguishedName
                }
            }
            Mock Invoke-WindowsAccessControlBatch

            $boundParameters = @{
                Server = 'dc01.example.test'
                DistinguishedName = @(
                    'OU=One,OU=Lab,DC=example,DC=test'
                    'OU=Two,OU=Lab,DC=example,DC=test'
                )
                AllowedBaseDistinguishedName = 'OU=Lab,DC=example,DC=test'
                TimeoutSeconds = 10
                ThrottleLimit = 2
            }
            Invoke-WindowsADCommandBatch `
                -CommandName Set-ADObjectSecurityDescriptor `
                -BoundParameters $boundParameters `
                -Server $boundParameters.Server `
                -DistinguishedName $boundParameters.DistinguishedName `
                -TimeoutSeconds 10 `
                -ThrottleLimit 2 `
                -SerializeByCanonicalTarget

            Should -Invoke Resolve-WindowsADObjectTarget -Times 2 -Exactly `
                -ParameterFilter {
                    $ForWrite -and
                    $AllowedBaseDistinguishedName -eq 'OU=Lab,DC=example,DC=test'
                }
            Should -Invoke Invoke-WindowsAccessControlBatch -Times 1 -Exactly
        }
    }

    It 'Should split a distinguished name at the first unescaped comma only' {
        & $script:module {
            Get-WindowsADParentDistinguishedName `
                -DistinguishedName 'CN=User,OU=Lab,DC=example,DC=test'
        } | Should -BeExactly 'OU=Lab,DC=example,DC=test'
        & $script:module {
            Get-WindowsADParentDistinguishedName `
                -DistinguishedName 'CN=Last\, First,OU=Lab,DC=example,DC=test'
        } | Should -BeExactly 'OU=Lab,DC=example,DC=test'
        & $script:module {
            Get-WindowsADParentDistinguishedName -DistinguishedName 'DC=test'
        } | Should -BeExactly ''
    }

    It 'Should compare ACE identity without propagation flags' {
        InModuleScope WindowsAccessControl {
            $sid = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
            $objectType = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
            $explicitAce = [Security.AccessControl.ObjectAce]::new(
                [Security.AccessControl.AceFlags]::ContainerInherit -bor
                [Security.AccessControl.AceFlags]::InheritOnly,
                [Security.AccessControl.AceQualifier]::AccessAllowed,
                16,
                $sid,
                [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
                $objectType,
                [guid]::Empty,
                $false,
                $null
            )
            $inheritedAce = [Security.AccessControl.ObjectAce]::new(
                [Security.AccessControl.AceFlags]::ContainerInherit -bor
                [Security.AccessControl.AceFlags]::Inherited,
                [Security.AccessControl.AceQualifier]::AccessAllowed,
                16,
                $sid,
                [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
                $objectType,
                [guid]::Empty,
                $false,
                $null
            )
            $otherGuidAce = [Security.AccessControl.ObjectAce]::new(
                [Security.AccessControl.AceFlags]::ContainerInherit,
                [Security.AccessControl.AceQualifier]::AccessAllowed,
                16,
                $sid,
                [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
                [guid]'bf967a9c-0de6-11d0-a285-00aa003049e2',
                [guid]::Empty,
                $false,
                $null
            )

            (Get-WindowsADAceIdentity -Ace $explicitAce) |
                Should -BeExactly (Get-WindowsADAceIdentity -Ace $inheritedAce)
            (Get-WindowsADAceIdentity -Ace $explicitAce) |
                Should -Not -BeExactly (Get-WindowsADAceIdentity -Ace $otherGuidAce)
        }
    }

    It 'Should resolve inherited ACEs to the nearest explicit inheritable ancestor' {
        InModuleScope WindowsAccessControl {
            $containerInherit = [int][Security.AccessControl.AceFlags]::ContainerInherit
            $inherited = [int][Security.AccessControl.AceFlags]::Inherited
            $noPropagate = [int][Security.AccessControl.AceFlags]::NoPropagateInherit
            $buildDescriptor = {
                param($AceSpec, [switch]$Protected)

                $acl = [Security.AccessControl.RawAcl]::new(
                    [Security.AccessControl.GenericAcl]::AclRevision,
                    $AceSpec.Count
                )
                for ($index = 0; $index -lt $AceSpec.Count; $index++) {
                    $acl.InsertAce($index, [Security.AccessControl.CommonAce]::new(
                            [Security.AccessControl.AceFlags]$AceSpec[$index].Flags,
                            [Security.AccessControl.AceQualifier]::AccessAllowed,
                            [int]$AceSpec[$index].Mask,
                            [Security.Principal.SecurityIdentifier]::new($AceSpec[$index].Sid),
                            $false,
                            $null
                        ))
                }
                $controlFlags = [int][Security.AccessControl.ControlFlags]::DiscretionaryAclPresent
                if ($Protected) {
                    $controlFlags = $controlFlags -bor
                        [int][Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
                }
                $owner = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
                $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
                    [Security.AccessControl.ControlFlags]$controlFlags,
                    $owner,
                    $owner,
                    $null,
                    $acl
                )
                $bytes = [byte[]]::new($descriptor.BinaryLength)
                $descriptor.GetBinaryForm($bytes, 0)
                , $bytes
            }

            $targetBytes = & $buildDescriptor @(
                @{ Sid = 'S-1-1-0'; Mask = 16; Flags = 0 }
                @{ Sid = 'S-1-5-11'; Mask = 32; Flags = $inherited -bor $containerInherit }
                @{ Sid = 'S-1-5-32-544'; Mask = 64; Flags = $inherited -bor $containerInherit }
                @{ Sid = 'S-1-5-9'; Mask = 128; Flags = $inherited }
                @{ Sid = 'S-1-5-4'; Mask = 256; Flags = $inherited }
                @{ Sid = 'S-1-5-13'; Mask = 512; Flags = $inherited }
                @{ Sid = 'S-1-5-11'; Mask = 32; Flags = $inherited -bor $containerInherit }
            )
            $script:testAncestorDescriptor = @{
                'OU=Child,OU=Parent,DC=example,DC=test' = & $buildDescriptor @(
                    @{ Sid = 'S-1-5-11'; Mask = 32; Flags = $inherited -bor $containerInherit }
                    @{ Sid = 'S-1-5-9'; Mask = 128; Flags = $containerInherit -bor $noPropagate }
                    @{ Sid = 'S-1-5-13'; Mask = 512; Flags = 0 }
                )
                'OU=Parent,DC=example,DC=test' = & $buildDescriptor @(
                    @{ Sid = 'S-1-5-11'; Mask = 32; Flags = $containerInherit }
                    @{ Sid = 'S-1-5-4'; Mask = 256; Flags = $containerInherit -bor $noPropagate }
                )
                'DC=example,DC=test' = & $buildDescriptor @(
                    @{ Sid = 'S-1-5-32-544'; Mask = 64; Flags = $containerInherit }
                    @{ Sid = 'S-1-5-11'; Mask = 32; Flags = $containerInherit }
                )
            }
            Mock Get-WindowsADObjectRecord {
                if (-not $script:testAncestorDescriptor.ContainsKey($DistinguishedName)) {
                    throw "Unexpected ancestor read: $DistinguishedName"
                }
                [pscustomobject]@{
                    DistinguishedName = $DistinguishedName
                    SecurityDescriptor = $script:testAncestorDescriptor[$DistinguishedName]
                }
            }

            $connection = [System.DirectoryServices.Protocols.LdapConnection]::new(
                [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new(
                    'dc01.example.test', 389, $true, $false
                )
            )
            try {
                $sources = Get-WindowsADObjectInheritanceSource `
                    -Connection $connection `
                    -DistinguishedName 'CN=Obj,OU=Child,OU=Parent,DC=example,DC=test' `
                    -SecurityDescriptor $targetBytes `
                    -NamingContext 'DC=example,DC=test'
            }
            finally {
                $connection.Dispose()
                $script:testAncestorDescriptor = $null
            }

            $sources.Count | Should -Be 7
            # An explicit ACE never reports a source.
            $sources[0] | Should -BeNullOrEmpty
            # The nearest ancestor holds only an inherited copy, so the explicit
            # ACE one level higher is the origin.
            $sources[1] | Should -BeExactly 'OU=Parent,DC=example,DC=test'
            $sources[2] | Should -BeExactly 'DC=example,DC=test'
            # NoPropagateInherit still reaches one level down.
            $sources[3] | Should -BeExactly 'OU=Child,OU=Parent,DC=example,DC=test'
            # NoPropagateInherit two levels up cannot be the origin.
            $sources[4] | Should -BeNullOrEmpty
            # A non-inheritable ancestor ACE cannot be the origin.
            $sources[5] | Should -BeNullOrEmpty
            # One ancestor ACE is consumed once, so the duplicate resolves higher.
            $sources[6] | Should -BeExactly 'DC=example,DC=test'
        }
    }

    It 'Should not look above a protected ancestor DACL' {
        InModuleScope WindowsAccessControl {
            $containerInherit = [int][Security.AccessControl.AceFlags]::ContainerInherit
            $inherited = [int][Security.AccessControl.AceFlags]::Inherited
            $buildDescriptor = {
                param($AceSpec, [switch]$Protected)

                $acl = [Security.AccessControl.RawAcl]::new(
                    [Security.AccessControl.GenericAcl]::AclRevision,
                    $AceSpec.Count
                )
                for ($index = 0; $index -lt $AceSpec.Count; $index++) {
                    $acl.InsertAce($index, [Security.AccessControl.CommonAce]::new(
                            [Security.AccessControl.AceFlags]$AceSpec[$index].Flags,
                            [Security.AccessControl.AceQualifier]::AccessAllowed,
                            [int]$AceSpec[$index].Mask,
                            [Security.Principal.SecurityIdentifier]::new($AceSpec[$index].Sid),
                            $false,
                            $null
                        ))
                }
                $controlFlags = [int][Security.AccessControl.ControlFlags]::DiscretionaryAclPresent
                if ($Protected) {
                    $controlFlags = $controlFlags -bor
                        [int][Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
                }
                $owner = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
                $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
                    [Security.AccessControl.ControlFlags]$controlFlags,
                    $owner,
                    $owner,
                    $null,
                    $acl
                )
                $bytes = [byte[]]::new($descriptor.BinaryLength)
                $descriptor.GetBinaryForm($bytes, 0)
                , $bytes
            }

            $targetBytes = & $buildDescriptor @(
                @{ Sid = 'S-1-5-11'; Mask = 32; Flags = $inherited -bor $containerInherit }
            )
            $script:testAncestorDescriptor = @{
                'OU=Child,OU=Parent,DC=example,DC=test' = & $buildDescriptor @(
                    @{ Sid = 'S-1-5-11'; Mask = 32; Flags = $inherited -bor $containerInherit }
                ) -Protected
                'OU=Parent,DC=example,DC=test' = & $buildDescriptor @(
                    @{ Sid = 'S-1-5-11'; Mask = 32; Flags = $containerInherit }
                )
            }
            Mock Get-WindowsADObjectRecord {
                if (-not $script:testAncestorDescriptor.ContainsKey($DistinguishedName)) {
                    throw "Unexpected ancestor read: $DistinguishedName"
                }
                [pscustomobject]@{
                    DistinguishedName = $DistinguishedName
                    SecurityDescriptor = $script:testAncestorDescriptor[$DistinguishedName]
                }
            }

            $connection = [System.DirectoryServices.Protocols.LdapConnection]::new(
                [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new(
                    'dc01.example.test', 389, $true, $false
                )
            )
            try {
                $sources = Get-WindowsADObjectInheritanceSource `
                    -Connection $connection `
                    -DistinguishedName 'CN=Obj,OU=Child,OU=Parent,DC=example,DC=test' `
                    -SecurityDescriptor $targetBytes `
                    -NamingContext 'DC=example,DC=test'
            }
            finally {
                $connection.Dispose()
                $script:testAncestorDescriptor = $null
            }

            $sources | Should -HaveCount 1
            $sources[0] | Should -BeNullOrEmpty
            Should -Invoke Get-WindowsADObjectRecord -Times 1 -Exactly
        }
    }

    It 'Should report no inheritance source when an ancestor cannot be read' {        InModuleScope WindowsAccessControl {
            $acl = [Security.AccessControl.RawAcl]::new(
                [Security.AccessControl.GenericAcl]::AclRevision, 1
            )
            $acl.InsertAce(0, [Security.AccessControl.CommonAce]::new(
                    [Security.AccessControl.AceFlags]::Inherited,
                    [Security.AccessControl.AceQualifier]::AccessAllowed,
                    16,
                    [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                    $false,
                    $null
                ))
            $owner = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
            $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
                [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent,
                $owner, $owner, $null, $acl
            )
            $bytes = [byte[]]::new($descriptor.BinaryLength)
            $descriptor.GetBinaryForm($bytes, 0)
            Mock Get-WindowsADObjectRecord { throw 'Access is denied.' }

            $connection = [System.DirectoryServices.Protocols.LdapConnection]::new(
                [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new(
                    'dc01.example.test', 389, $true, $false
                )
            )
            try {
                $sources = Get-WindowsADObjectInheritanceSource `
                    -Connection $connection `
                    -DistinguishedName 'CN=Obj,OU=Lab,DC=example,DC=test' `
                    -SecurityDescriptor $bytes `
                    -NamingContext 'DC=example,DC=test'
            }
            finally {
                $connection.Dispose()
            }

            $sources.Count | Should -Be 1
            $sources[0] | Should -BeNullOrEmpty
        }
    }

    It 'Should report a directory GUID name only when it resolves' {
        & $script:module {
            $map = @{ 'bf967aba-0de6-11d0-a285-00aa003049e2' = 'user' }
            [pscustomobject]@{
                Known = Get-WindowsADSchemaGuidDisplayName `
                    -Guid ([guid]'BF967ABA-0DE6-11D0-A285-00AA003049E2') -SchemaGuidName $map
                Unknown = Get-WindowsADSchemaGuidDisplayName `
                    -Guid ([guid]'bf967a9c-0de6-11d0-a285-00aa003049e2') -SchemaGuidName $map
                Empty = Get-WindowsADSchemaGuidDisplayName `
                    -Guid ([guid]::Empty) -SchemaGuidName $map
                NoMap = Get-WindowsADSchemaGuidDisplayName `
                    -Guid ([guid]'bf967aba-0de6-11d0-a285-00aa003049e2') -SchemaGuidName $null
            }
        } | ForEach-Object {
            $_.Known | Should -BeExactly 'user'
            $_.Unknown | Should -BeNullOrEmpty
            $_.Empty | Should -BeNullOrEmpty
            $_.NoMap | Should -BeNullOrEmpty
        }
    }

    It 'Should resolve cached directory GUID names without contacting the server' {
        InModuleScope WindowsAccessControl {
            $originalCache = $script:WindowsADSchemaGuidNames
            $script:WindowsADSchemaGuidNames = @{
                'cn=schema,cn=configuration,dc=example,dc=test|bf967aba-0de6-11d0-a285-00aa003049e2' = 'user'
            }
            $connection = [System.DirectoryServices.Protocols.LdapConnection]::new(
                [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new(
                    'dc01.example.test', 389, $true, $false
                )
            )
            try {
                $names = Resolve-WindowsADSchemaGuidName `
                    -Connection $connection `
                    -SchemaNamingContext 'CN=Schema,CN=Configuration,DC=example,DC=test' `
                    -ConfigurationNamingContext 'CN=Configuration,DC=example,DC=test' `
                    -Guid @([guid]'bf967aba-0de6-11d0-a285-00aa003049e2', [guid]::Empty)
            }
            finally {
                $connection.Dispose()
                $script:WindowsADSchemaGuidNames = $originalCache
            }

            $names.Count | Should -Be 1
            $names['bf967aba-0de6-11d0-a285-00aa003049e2'] | Should -BeExactly 'user'
        }
    }

    It 'Should report provenance and resolved names only where they apply' {
        InModuleScope WindowsAccessControl {
            $target = [pscustomobject]@{
                Server = 'dc01.example.test'
                DistinguishedName = 'CN=Obj,OU=Lab,DC=example,DC=test'
                ObjectGuid = [guid]::NewGuid()
                CanonicalTarget = 'ADObject:DC01.EXAMPLE.TEST:GUID'
            }
            $sid = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
            $names = @{ 'bf967aba-0de6-11d0-a285-00aa003049e2' = 'user' }
            $inheritedAce = [Security.AccessControl.ObjectAce]::new(
                [Security.AccessControl.AceFlags]::Inherited,
                [Security.AccessControl.AceQualifier]::AccessAllowed,
                16,
                $sid,
                [Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent,
                [guid]::Empty,
                [guid]'bf967aba-0de6-11d0-a285-00aa003049e2',
                $false,
                $null
            )
            $explicitAce = [Security.AccessControl.CommonAce]::new(
                [Security.AccessControl.AceFlags]::None,
                [Security.AccessControl.AceQualifier]::AccessAllowed,
                16,
                $sid,
                $false,
                $null
            )

            $inheritedRule = ConvertTo-WindowsADAccessRuleObject `
                -Ace $inheritedAce `
                -Target $target `
                -InheritedFrom 'OU=Lab,DC=example,DC=test' `
                -SchemaGuidName $names
            $explicitRule = ConvertTo-WindowsADAccessRuleObject `
                -Ace $explicitAce `
                -Target $target `
                -InheritedFrom 'OU=Lab,DC=example,DC=test' `
                -SchemaGuidName $names

            $inheritedRule.InheritedFrom | Should -BeExactly 'OU=Lab,DC=example,DC=test'
            $inheritedRule.InheritedObjectTypeName | Should -BeExactly 'user'
            $inheritedRule.ObjectTypeName | Should -BeNullOrEmpty
            $explicitRule.InheritedFrom | Should -BeNullOrEmpty
        }
    }

    It 'Should accept an explicit domain controller without discovery' {
        & $script:module {
            Resolve-WindowsADServer -Server 'DC01.Example.Test'
        } | Should -BeExactly 'dc01.example.test'

        { & $script:module { Resolve-WindowsADServer -Server 'dc01' } } | Should -Throw
    }

    It 'Should pin one discovered domain controller for the whole command' {
        InModuleScope WindowsAccessControl {
            Mock Resolve-WindowsADServer { 'dc02.example.test' }
            Mock Invoke-WindowsADCommandBatch

            Get-ADObjectAccessRule -DistinguishedName 'CN=Obj,OU=Lab,DC=example,DC=test'

            Should -Invoke Resolve-WindowsADServer -Times 1 -Exactly
            Should -Invoke Invoke-WindowsADCommandBatch -Times 1 -Exactly `
                -ParameterFilter {
                    $Server -eq 'dc02.example.test' -and
                    $BoundParameters['Server'] -eq 'dc02.example.test'
                }
        }
    }

    It 'Should discover a domain controller once for a piped target set' {
        InModuleScope WindowsAccessControl {
            Mock Resolve-WindowsADServer { 'dc02.example.test' }
            Mock Invoke-WindowsADCommandBatch

            @(
                'CN=One,OU=Lab,DC=example,DC=test'
                'CN=Two,OU=Lab,DC=example,DC=test'
                'CN=Three,OU=Lab,DC=example,DC=test'
            ) | Get-ADObjectAccessRule

            Should -Invoke Invoke-WindowsADCommandBatch -Times 3 -Exactly
            Should -Invoke Resolve-WindowsADServer -Times 1 -Exactly
        }
    }

    It 'Should keep Server optional on every Active Directory command' {
        foreach ($commandName in @(
                'Get-ADObjectAccessRule'
                'Get-ADObjectSecurityDescriptor'
                'Add-ADObjectAccessRule'
                'Set-ADObjectSecurityDescriptor'
            )) {
            $command = Get-Command -Name $commandName -Module 'WindowsAccessControl'
            $command.Parameters['Server'].Attributes.Where({
                    $_ -is [System.Management.Automation.ParameterAttribute]
                }).Mandatory |
                Should -Not -Contain $true -Because "$commandName must discover a domain controller"
        }
    }
}
