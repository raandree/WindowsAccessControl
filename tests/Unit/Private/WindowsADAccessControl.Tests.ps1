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
}
