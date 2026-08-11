BeforeAll {
    Import-Module ActiveDirectory -ErrorAction Stop

    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop

    $script:domain = Get-ADDomain -ErrorAction Stop
    $script:server = [string]@(
        (Get-ADDomainController -Discover -Writable -ErrorAction Stop).HostName
    )[0]
    $script:rootDse = Get-ADRootDSE -Server $script:server -ErrorAction Stop
    $script:domainSid = $script:domain.DomainSID.Value
    # The pinned child domain controller cannot resolve the forest root
    # partition, so the expected root SID is read through a controller of that
    # domain instead.
    $script:rootDomainDns = (Get-ADForest -Server $script:server -ErrorAction Stop).RootDomain
    $script:rootDomainSid = (Get-ADDomain `
            -Identity $script:rootDomainDns `
            -ErrorAction Stop).DomainSID.Value

    # A disposable organizational unit keeps every write inside a target this
    # suite created and removes again.
    $script:baseOu = "OU=WacObjectTypeLive,$($script:domain.DistinguishedName)"
    $script:targetOu = "OU=Target,$($script:baseOu)"
    if (-not (Get-ADObject -Filter "DistinguishedName -eq '$($script:baseOu)'" -ErrorAction SilentlyContinue)) {
        $null = New-ADOrganizationalUnit `
            -Name 'WacObjectTypeLive' `
            -Path $script:domain.DistinguishedName `
            -ProtectedFromAccidentalDeletion $false `
            -Server $script:server `
            -ErrorAction Stop
    }
    if (-not (Get-ADObject -Filter "DistinguishedName -eq '$($script:targetOu)'" -ErrorAction SilentlyContinue)) {
        $null = New-ADOrganizationalUnit `
            -Name 'Target' `
            -Path $script:baseOu `
            -ProtectedFromAccidentalDeletion $false `
            -Server $script:server `
            -ErrorAction Stop
    }

    # A relative identifier no account uses keeps every assertion about entries
    # this suite wrote, clear of the entries the class default already grants.
    $script:testSid = $script:domain.DomainSID.Value + '-4999'

    # Resolve the expected GUIDs from the directory rather than hard-coding them.
    $script:userAccountControlGuid = [guid](Get-ADObject `
            -Server $script:server `
            -SearchBase $script:rootDse.schemaNamingContext `
            -LDAPFilter '(lDAPDisplayName=userAccountControl)' `
            -Properties schemaIDGUID -ErrorAction Stop).schemaIDGUID
    $script:resetPasswordGuid = [guid](Get-ADObject `
            -Server $script:server `
            -SearchBase "CN=Extended-Rights,$($script:rootDse.configurationNamingContext)" `
            -LDAPFilter '(displayName=Reset Password)' `
            -Properties rightsGuid -ErrorAction Stop).rightsGuid
    $script:userClassGuid = [guid](Get-ADObject `
            -Server $script:server `
            -SearchBase $script:rootDse.schemaNamingContext `
            -LDAPFilter '(lDAPDisplayName=user)' `
            -Properties schemaIDGUID -ErrorAction Stop).schemaIDGUID
}

AfterAll {
    if ($script:baseOu) {
        Get-ADObject -Filter "DistinguishedName -eq '$($script:baseOu)'" -ErrorAction SilentlyContinue |
            Remove-ADObject -Recursive -Confirm:$false -Server $script:server -ErrorAction SilentlyContinue
    }
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Schema default access rules' -Tag 'Lab', 'WindowsOnly' {
    It 'Should expand a domain-relative alias to a real group of this domain' {
        $rules = @(Get-ADObjectSchemaDefaultAccessRule `
                -Server $script:server -ObjectClass 'user')

        $rules | Should -Not -BeNullOrEmpty
        # The stored template names DA, CA, and RS; each has to become a
        # security identifier of the domain the pinned controller serves.
        $rules.SID | Should -Contain "$($script:domainSid)-512"
        $rules.SID | Should -Contain "$($script:domainSid)-517"
        $rules.SID | Should -Contain "$($script:domainSid)-553"
    }

    It 'Should leave an alias that does not depend on a domain to the platform' {
        $rules = @(Get-ADObjectSchemaDefaultAccessRule `
                -Server $script:server -ObjectClass 'user')

        $rules.SID | Should -Contain 'S-1-5-18'
        $rules.SID | Should -Contain 'S-1-5-10'
        $rules.SID | Should -Contain 'S-1-5-32-548'
    }

    It 'Should expand a forest-wide alias against the forest root domain' {
        # This class is the reason the forest root SID matters: its template
        # names EA, which belongs to the root domain and not to this one.
        $rules = @(Get-ADObjectSchemaDefaultAccessRule `
                -Server $script:server -ObjectClass 'domainDNS')

        $rules | Should -Not -BeNullOrEmpty
        $rules.SID | Should -Contain "$($script:rootDomainSid)-519"
        $script:rootDomainSid | Should -Not -BeExactly $script:domainSid
    }

    It 'Should resolve the object type of an entry scoped to one right' {
        $rules = @(Get-ADObjectSchemaDefaultAccessRule `
                -Server $script:server -ObjectClass 'user')
        $scoped = @($rules | Where-Object { $_.ObjectTypeGuid -ne [guid]::Empty })

        $scoped | Should -Not -BeNullOrEmpty
        @($scoped | Where-Object { -not $_.ObjectTypeName }) | Should -BeNullOrEmpty
    }

    It 'Should describe a template rather than a target' {
        $rule = @(Get-ADObjectSchemaDefaultAccessRule `
                -Server $script:server -ObjectClass 'group')[0]

        $rule.PSObject.TypeNames[0] |
            Should -BeExactly 'WindowsAccessControl.ADSchemaDefaultAccessRule'
        $rule.ObjectClass | Should -BeExactly 'group'
        $rule.PSObject.Properties.Name | Should -Not -Contain 'DistinguishedName'
    }

    It 'Should report a class that does not exist' {
        { Get-ADObjectSchemaDefaultAccessRule `
                -Server $script:server -ObjectClass 'noSuchClass' -ErrorAction Stop } |
            Should -Throw -ExpectedMessage '*did not resolve to exactly one schema class*'
    }
}

Describe 'Object type names on directory rule mutators' -Tag 'Lab', 'WindowsOnly' {
    AfterEach {
        Clear-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -ThrottleLimit 1 `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    }

    It 'Should write the entry an attribute name identifies' {
        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights ReadProperty `
            -ObjectType 'userAccountControl' `
            -ThrottleLimit 1 `
            -Confirm:$false

        $stored = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -Account $script:testSid `
                -ExcludeInherited `
                -ThrottleLimit 1)

        $stored | Should -HaveCount 1
        $stored[0].ObjectTypeGuid | Should -Be $script:userAccountControlGuid
        $stored[0].ObjectTypeName | Should -BeExactly 'userAccountControl'
    }

    It 'Should write the entry an extended right display name identifies' {
        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights ExtendedRight `
            -ObjectType 'Reset Password' `
            -ThrottleLimit 1 `
            -Confirm:$false

        $stored = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -Account $script:testSid `
                -ExcludeInherited `
                -ThrottleLimit 1)

        $stored | Should -HaveCount 1
        $stored[0].ObjectTypeGuid | Should -Be $script:resetPasswordGuid
    }

    It 'Should scope inherited application by a class name' {
        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights ReadProperty `
            -InheritanceType Descendents `
            -InheritedObjectType 'user' `
            -ThrottleLimit 1 `
            -Confirm:$false

        $stored = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -Account $script:testSid `
                -ExcludeInherited `
                -ThrottleLimit 1)

        $stored | Should -HaveCount 1
        $stored[0].InheritedObjectTypeGuid | Should -Be $script:userClassGuid
        $stored[0].InheritedObjectTypeName | Should -BeExactly 'user'
    }

    It 'Should remove exactly the entry a name identifies' {
        foreach ($objectType in 'userAccountControl', 'displayName') {
            Add-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -AllowedBaseDistinguishedName $script:baseOu `
                -Account $script:testSid `
                -AccessRights ReadProperty `
                -ObjectType $objectType `
                -ThrottleLimit 1 `
                -Confirm:$false
        }

        Remove-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights ReadProperty `
            -ObjectType 'userAccountControl' `
            -ThrottleLimit 1 `
            -Confirm:$false

        $stored = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -Account $script:testSid `
                -ExcludeInherited `
                -ThrottleLimit 1)

        $stored | Should -HaveCount 1
        $stored[0].ObjectTypeName | Should -BeExactly 'displayName'
    }

    It 'Should refuse an unresolvable name without touching the descriptor' {
        $before = Get-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -ThrottleLimit 1

        {
            Add-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -AllowedBaseDistinguishedName $script:baseOu `
                -Account $script:testSid `
                -AccessRights ReadProperty `
                -ObjectType 'ThisAttributeDoesNotExist' `
                -ThrottleLimit 1 `
                -Confirm:$false
        } | Should -Throw -ExpectedMessage '*does not name an Active Directory schema class*'

        $after = Get-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -ThrottleLimit 1

        # An unresolvable name must not fall back to the empty GUID, which would
        # grant the right on every object and property instead of one.
        $after.Sddl | Should -BeExactly $before.Sddl
    }
}

Describe 'Directory rights masks' -Tag 'Lab', 'WindowsOnly' {
    AfterEach {
        Clear-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -ThrottleLimit 1 `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    }

    It 'Should accept a mask the rights enumeration cannot name' {
        # 0x10000000 is GENERIC_ALL. The enumeration has no name for it, so a
        # declared enum type would refuse it before the command is reached.
        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights 0x10000000 `
            -ThrottleLimit 1 `
            -Confirm:$false

        $stored = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -Account $script:testSid `
                -ExcludeInherited `
                -ThrottleLimit 1)

        # Active Directory applies its generic mapping as it stores the entry,
        # so the generic bit becomes the specific rights it confers. Unlike the
        # file system, a directory entry never keeps a GENERIC_* bit. What this
        # asserts is that the mask binds and reaches the directory at all.
        $stored | Should -HaveCount 1
        $stored[0].AccessMask | Should -Be 0x000F01FF
        $stored[0].AccessRightsDisplay | Should -BeExactly 'GenericAll'
    }

    It 'Should accept a comma separated rights name list' {
        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights 'ReadProperty, WriteProperty' `
            -ThrottleLimit 1 `
            -Confirm:$false

        $stored = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -Account $script:testSid `
                -ExcludeInherited `
                -ThrottleLimit 1)

        $stored | Should -HaveCount 1
        $stored[0].AccessMask | Should -Be 0x30
    }

    It 'Should refuse a rights name that does not exist' {
        {
            Add-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -AllowedBaseDistinguishedName $script:baseOu `
                -Account $script:testSid `
                -AccessRights 'NotARight' `
                -ThrottleLimit 1 `
                -Confirm:$false
        } | Should -Throw
    }
}
