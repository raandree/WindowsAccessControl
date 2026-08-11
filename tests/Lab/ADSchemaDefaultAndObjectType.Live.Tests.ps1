BeforeAll {
    Import-Module ActiveDirectory -ErrorAction Stop

    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module WindowsAccessControl

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
    # suite created and removes again. The second target exists so the bounded
    # batch path runs with more than one worker.
    $script:baseOu = "OU=WacObjectTypeLive,$($script:domain.DistinguishedName)"
    $script:targetOu = "OU=Target,$($script:baseOu)"
    $script:secondTargetOu = "OU=Target2,$($script:baseOu)"
    if (-not (Get-ADObject -Filter "DistinguishedName -eq '$($script:baseOu)'" -ErrorAction SilentlyContinue)) {
        $null = New-ADOrganizationalUnit `
            -Name 'WacObjectTypeLive' `
            -Path $script:domain.DistinguishedName `
            -ProtectedFromAccidentalDeletion $false `
            -Server $script:server `
            -ErrorAction Stop
    }
    foreach ($targetName in 'Target', 'Target2') {
        $targetDn = "OU=$targetName,$($script:baseOu)"
        if (-not (Get-ADObject -Filter "DistinguishedName -eq '$targetDn'" -ErrorAction SilentlyContinue)) {
            $null = New-ADOrganizationalUnit `
                -Name $targetName `
                -Path $script:baseOu `
                -ProtectedFromAccidentalDeletion $false `
                -Server $script:server `
                -ErrorAction Stop
        }
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

    # A disposable unprivileged account proves the credential reaches the second
    # connection the forest-root read opens.
    $passwordText = 'Wac!' + [guid]::NewGuid().ToString('N') + 'aA1'
    $script:readerPassword = [Security.SecureString]::new()
    foreach ($character in $passwordText.ToCharArray()) {
        $script:readerPassword.AppendChar($character)
    }
    $script:readerPassword.MakeReadOnly()
    $passwordText = $null
    $script:readerName = 'WacSchemaReader'
    $existingReader = Get-ADUser -Filter "SamAccountName -eq '$($script:readerName)'" `
        -Server $script:server -ErrorAction SilentlyContinue
    if ($existingReader) {
        Remove-ADUser -Identity $existingReader -Server $script:server -Confirm:$false
    }
    $null = New-ADUser `
        -Name $script:readerName `
        -SamAccountName $script:readerName `
        -Path $script:baseOu `
        -AccountPassword $script:readerPassword `
        -Enabled $true `
        -Server $script:server `
        -ErrorAction Stop
    $script:readerCredential = [pscredential]::new(
        "$($script:domain.NetBIOSName)\$($script:readerName)",
        $script:readerPassword
    )

    # A host that serves no global catalog, for the fallback's null path.
    $script:memberServer = if ($env:WAC_DOMAIN_LAB_MEMBER) {
        $env:WAC_DOMAIN_LAB_MEMBER
    }
    else {
        $controllerNames = @(
            (Get-ADDomainController -Filter * -Server $script:server).Name
        )
        $member = Get-ADComputer -Filter * -Server $script:server |
            Where-Object { $_.Name -notin $controllerNames } |
            Select-Object -First 1
        if (-not $member) {
            throw 'The fixture domain holds no member server to probe for a missing global catalog.'
        }
        '{0}.{1}' -f $member.Name, $script:domain.DNSRoot
    }
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

    It 'Should read the forest root domain SID with an explicit credential' {
        # This class is the one that needs the forest root SID, and that read is
        # a second connection, so it is the only case that proves the caller's
        # credential reaches the global catalog rather than the pinned bind only.
        $rules = @(Get-ADObjectSchemaDefaultAccessRule `
                -Server $script:server `
                -Credential $script:readerCredential `
                -ObjectClass 'domainDNS')

        $rules.SID | Should -Contain "$($script:rootDomainSid)-519"
    }

    It 'Should return nothing for a class that carries no template' {
        # applicationSettings has no defaultSecurityDescriptor at all, which is
        # not the same as one that is present and empty.
        $rules = @(Get-ADObjectSchemaDefaultAccessRule `
                -Server $script:server -ObjectClass 'applicationSettings')

        $rules | Should -BeNullOrEmpty
    }

    It 'Should return nothing for a template that is present and empty' {
        # classSchema carries the literal template 'D:S:', so the entry count is
        # zero because the template grants nothing, not because a read failed.
        $rules = @(Get-ADObjectSchemaDefaultAccessRule `
                -Server $script:server -ObjectClass 'classSchema')

        $rules | Should -BeNullOrEmpty
    }

    It 'Should read several classes from the pipeline over one connection' {
        $rules = @('user', 'group', 'computer' |
                Get-ADObjectSchemaDefaultAccessRule -Server $script:server)

        @($rules.ObjectClass | Sort-Object -Unique) |
            Should -Be @('computer', 'group', 'user')
    }

    It 'Should expand against the served domain on a forest root controller' {
        # Every other case here runs on a child controller, where the root
        # naming context differs and the global catalog is consulted. On a forest
        # root the two contexts are the same and that second read never happens.
        $rootServer = [string]@(
            (Get-ADDomainController -Discover -DomainName $script:rootDomainDns -Writable).HostName
        )[0]
        $rules = @(Get-ADObjectSchemaDefaultAccessRule `
                -Server $rootServer -ObjectClass 'domainDNS')

        $rules.SID | Should -Contain "$($script:rootDomainSid)-519"
        $rules.SID | Should -Contain "$($script:rootDomainSid)-512"
        $rules.Server | Select-Object -Unique | Should -BeExactly $rootServer.ToLowerInvariant()
    }
}

Describe 'Schema default subtraction' -Tag 'Lab', 'WindowsOnly' {
    BeforeAll {
        # The six fields ADR 0033 compares, as one comparable string.
        function Get-WacRuleKey {
            param($Rule)

            @(
                [string]$Rule.SID
                ([uint64]$Rule.AccessMask).ToString()
                [string]$Rule.AccessControlType
                [string]$Rule.InheritanceType
                ([guid]$Rule.ObjectTypeGuid).ToString('N')
                ([guid]$Rule.InheritedObjectTypeGuid).ToString('N')
            ) -join '|'
        }

        # Everything below the trustee, so a template entry a placeholder owns
        # can be recognized on the object where its trustee has been replaced.
        function Get-WacRuleShape {
            param($Rule)

            (Get-WacRuleKey -Rule $Rule).Substring(([string]$Rule.SID).Length)
        }

        $script:placeholderSid = @('S-1-3-0', 'S-1-3-1', 'S-1-3-2', 'S-1-3-3')
        $script:ouTemplate = @(Get-ADObjectSchemaDefaultAccessRule `
                -Server $script:server -ObjectClass 'organizationalUnit')
        $script:ouTemplateKey = @(
            $script:ouTemplate |
                Where-Object { $_.SID -notin $script:placeholderSid } |
                ForEach-Object { Get-WacRuleKey -Rule $_ }
        )

        # The computer class is the one that carries creator placeholders, so
        # the refusal has a live target. The organizational unit class has none.
        $script:computerName = 'WacDefaultComp'
        $script:computerDn = "CN=$($script:computerName),$($script:targetOu)"
        if (-not (Get-ADObject -Filter "DistinguishedName -eq '$($script:computerDn)'" -ErrorAction SilentlyContinue)) {
            $null = New-ADComputer `
                -Name $script:computerName `
                -Path $script:targetOu `
                -Server $script:server `
                -ErrorAction Stop
        }
        $script:computerTemplate = @(Get-ADObjectSchemaDefaultAccessRule `
                -Server $script:server -ObjectClass 'computer')
    }

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

    It 'Should drop exactly the explicit entries the class template grants' {
        $all = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -ExcludeInherited `
                -ThrottleLimit 1)
        $filtered = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -ExcludeInherited `
                -ExcludeSchemaDefault `
                -ThrottleLimit 1)
        $fromTemplate = @($all |
                Where-Object { (Get-WacRuleKey -Rule $_) -in $script:ouTemplateKey })

        $script:ouTemplateKey | Should -Not -BeNullOrEmpty
        $fromTemplate | Should -Not -BeNullOrEmpty -Because 'a new organizational unit carries its class default as explicit entries'
        $filtered | Should -HaveCount ($all.Count - $fromTemplate.Count)
        @($filtered | Where-Object { (Get-WacRuleKey -Rule $_) -in $script:ouTemplateKey }) |
            Should -BeNullOrEmpty
    }

    It 'Should show every entry when the switch is absent' {
        # The default has to keep meaning what it meant, because this command is
        # what an operator reads to see what is really on an object.
        $default = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -ExcludeInherited `
                -ThrottleLimit 1)
        $filtered = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -ExcludeInherited `
                -ExcludeSchemaDefault `
                -ThrottleLimit 1)

        $default.Count | Should -BeGreaterThan $filtered.Count
    }

    It 'Should keep an entry an operator added' {
        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights ReadProperty `
            -ThrottleLimit 1 `
            -Confirm:$false

        $filtered = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -ExcludeInherited `
                -ExcludeSchemaDefault `
                -ThrottleLimit 1)

        @($filtered.SID) | Should -Contain $script:testSid
    }

    It 'Should never hide an inherited entry' {
        $inherited = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -ExcludeExplicit `
                -ThrottleLimit 1)
        $filtered = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -ExcludeExplicit `
                -ExcludeSchemaDefault `
                -ThrottleLimit 1)

        $inherited | Should -Not -BeNullOrEmpty
        $filtered | Should -HaveCount $inherited.Count
    }

    It 'Should drop the SELF entries the template keeps verbatim' {
        # PRINCIPAL SELF is the one alias that reaches the created object
        # unchanged, so it is the case the rule is allowed to match.
        $selfTemplate = @($script:computerTemplate | Where-Object SID -EQ 'S-1-5-10')
        $all = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:computerDn `
                -ExcludeInherited `
                -Account 'S-1-5-10' `
                -ThrottleLimit 1)
        $filtered = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:computerDn `
                -ExcludeInherited `
                -Account 'S-1-5-10' `
                -ExcludeSchemaDefault `
                -ThrottleLimit 1)
        $selfTemplateKey = @($selfTemplate | ForEach-Object { Get-WacRuleKey -Rule $_ })

        $selfTemplate | Should -Not -BeNullOrEmpty
        @($all | Where-Object { (Get-WacRuleKey -Rule $_) -in $selfTemplateKey }) |
            Should -Not -BeNullOrEmpty
        @($filtered | Where-Object { (Get-WacRuleKey -Rule $_) -in $selfTemplateKey }) |
            Should -BeNullOrEmpty
    }

    It 'Should keep the entry a creator placeholder became' {
        # Measured on this lab: every CREATOR OWNER entry of the computer class
        # template reaches the created object as the owner's own entry. Nothing
        # on the object separates that from a grant to the same principal, so
        # the placeholder is dropped from the baseline and hides nothing.
        $placeholderShape = @(
            $script:computerTemplate |
                Where-Object { $_.SID -in $script:placeholderSid } |
                ForEach-Object { Get-WacRuleShape -Rule $_ }
        )
        $filtered = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:computerDn `
                -ExcludeInherited `
                -ExcludeSchemaDefault `
                -ThrottleLimit 1)
        $materialized = @(
            $filtered |
                Where-Object { $_.SID -notin $script:placeholderSid } |
                Where-Object { (Get-WacRuleShape -Rule $_) -in $placeholderShape }
        )

        $placeholderShape | Should -Not -BeNullOrEmpty
        $materialized | Should -Not -BeNullOrEmpty
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

    It 'Should replace only the entry that shares the named object type' {
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

        Set-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights WriteProperty `
            -ObjectType 'userAccountControl' `
            -ThrottleLimit 1 `
            -Confirm:$false

        $stored = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -Account $script:testSid `
                -ExcludeInherited `
                -ThrottleLimit 1)

        $stored | Should -HaveCount 2
        $replaced = @($stored | Where-Object ObjectTypeName -EQ 'userAccountControl')
        $untouched = @($stored | Where-Object ObjectTypeName -EQ 'displayName')
        $replaced | Should -HaveCount 1
        $replaced[0].AccessMask | Should -Be 0x20
        $untouched | Should -HaveCount 1
        $untouched[0].AccessMask | Should -Be 0x10
    }

    It 'Should resolve the name once for every target of a bounded batch' {
        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName @($script:targetOu, $script:secondTargetOu) `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights ReadProperty `
            -ObjectType 'userAccountControl' `
            -ThrottleLimit 2 `
            -Confirm:$false

        foreach ($target in $script:targetOu, $script:secondTargetOu) {
            $stored = @(Get-ADObjectAccessRule `
                    -Server $script:server `
                    -DistinguishedName $target `
                    -Account $script:testSid `
                    -ExcludeInherited `
                    -ThrottleLimit 1)

            $stored | Should -HaveCount 1
            $stored[0].ObjectTypeGuid | Should -Be $script:userAccountControlGuid
        }

        Clear-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:secondTargetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -ThrottleLimit 1 `
            -Confirm:$false
    }

    It 'Should resolve an attribute and an extended right by common name' {
        # The filters match the display name or the common name. Every other
        # case here uses the display form, so the common form is unproven.
        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights ReadProperty `
            -ObjectType 'User-Account-Control' `
            -ThrottleLimit 1 `
            -Confirm:$false
        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights ExtendedRight `
            -ObjectType 'User-Force-Change-Password' `
            -ThrottleLimit 1 `
            -Confirm:$false

        $stored = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -Account $script:testSid `
                -ExcludeInherited `
                -ThrottleLimit 1)

        @($stored.ObjectTypeGuid | Sort-Object) |
            Should -Be @($script:userAccountControlGuid, $script:resetPasswordGuid |
                Sort-Object)
    }

    It 'Should resolve both object type names over one connection' {
        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights ReadProperty `
            -InheritanceType Descendents `
            -ObjectType 'userAccountControl' `
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
        $stored[0].ObjectTypeGuid | Should -Be $script:userAccountControlGuid
        $stored[0].InheritedObjectTypeGuid | Should -Be $script:userClassGuid
    }

    It 'Should refuse a name carrying filter metacharacters' {
        # The value is escaped before it reaches the filter, so this has to come
        # back as an unresolved name and not as a directory syntax error.
        {
            Add-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -AllowedBaseDistinguishedName $script:baseOu `
                -Account $script:testSid `
                -AccessRights ReadProperty `
                -ObjectType 'user*(name)' `
                -ThrottleLimit 1 `
                -Confirm:$false
        } | Should -Throw -ExpectedMessage '*does not name an Active Directory schema class*'
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

    It 'Should accept a hexadecimal mask on replace and on removal' {
        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights '0x00000010' `
            -ThrottleLimit 1 `
            -Confirm:$false

        # Set and Remove share the transform with Add and had never used it.
        Set-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights '0x00000030' `
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

        Remove-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:baseOu `
            -Account $script:testSid `
            -AccessRights 0x30 `
            -ThrottleLimit 1 `
            -Confirm:$false

        @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -Account $script:testSid `
                -ExcludeInherited `
                -ThrottleLimit 1) | Should -BeNullOrEmpty
    }
}

Describe 'Forest root SID sources' -Tag 'Lab', 'WindowsOnly' {
    It 'Should report no SID when the server holds no global catalog' {
        # The fallback opens the global catalog port of the same server. A host
        # that serves no catalog has to yield null so the caller refuses,
        # instead of an exception or a SID from somewhere else.
        $sid = & $script:module {
            param($Server, $NamingContext)
            Get-WindowsADNamingContextSid `
                -UseGlobalCatalog `
                -Server $Server `
                -NamingContext $NamingContext `
                -TimeoutSeconds 5
        } $script:memberServer $script:rootDse.rootDomainNamingContext

        $sid | Should -BeNullOrEmpty
    }

    It 'Should read the SID when the server holds a global catalog' {
        $sid = & $script:module {
            param($Server, $NamingContext)
            Get-WindowsADNamingContextSid `
                -UseGlobalCatalog `
                -Server $Server `
                -NamingContext $NamingContext `
                -TimeoutSeconds 10
        } $script:server $script:rootDse.rootDomainNamingContext

        $sid.Value | Should -BeExactly $script:rootDomainSid
    }
}

Describe 'Desired state carrying an object type' -Tag 'Lab', 'WindowsOnly' {
    It 'Should converge a managed rule scoped to one object type' {
        # The resource passes a GUID into a parameter that now takes a string,
        # so this proves the value survives that round trip instead of
        # collapsing to the empty GUID, which would manage every property.
        $state = & $script:module {
            param($Server, $Target, $Base, $Sid, $ObjectTypeGuid)

            $resource = [WindowsAccessControlADObjectAccessRule]::new()
            $resource.Server = $Server
            $resource.DistinguishedName = $Target
            $resource.AllowedBaseDistinguishedName = $Base
            $resource.Account = $Sid
            $resource.AccessRights = [WindowsActiveDirectoryRights]::ReadProperty
            $resource.AccessControlType =
                [Security.AccessControl.AccessControlType]::Allow
            $resource.ObjectType = $ObjectTypeGuid
            $resource.Ensure = [WindowsAccessControlDscEnsure]::Present

            $initial = $resource.Test()
            $resource.Set()
            $afterSet = $resource.Test()
            [pscustomobject]@{ Initial = $initial; AfterSet = $afterSet }
        } $script:server $script:targetOu $script:baseOu $script:testSid `
            $script:userAccountControlGuid.ToString()

        $state.Initial | Should -BeFalse
        $state.AfterSet | Should -BeTrue

        $stored = @(Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -Account $script:testSid `
                -ExcludeInherited `
                -ThrottleLimit 1)

        $stored | Should -HaveCount 1
        $stored[0].ObjectTypeGuid | Should -Be $script:userAccountControlGuid

        $removed = & $script:module {
            param($Server, $Target, $Base, $Sid, $ObjectTypeGuid)

            $resource = [WindowsAccessControlADObjectAccessRule]::new()
            $resource.Server = $Server
            $resource.DistinguishedName = $Target
            $resource.AllowedBaseDistinguishedName = $Base
            $resource.Account = $Sid
            $resource.AccessRights = [WindowsActiveDirectoryRights]::ReadProperty
            $resource.AccessControlType =
                [Security.AccessControl.AccessControlType]::Allow
            $resource.ObjectType = $ObjectTypeGuid
            $resource.Ensure = [WindowsAccessControlDscEnsure]::Absent
            $resource.Set()
            $resource.Test()
        } $script:server $script:targetOu $script:baseOu $script:testSid `
            $script:userAccountControlGuid.ToString()

        $removed | Should -BeTrue
    }

    It 'Should refuse a name where the resource cannot resolve one' {
        # The commands resolve a name over their connection. A resource property
        # is parsed before any connection exists, so it stays GUID only rather
        # than guessing.
        {
            & $script:module {
                $resource = [WindowsAccessControlADObjectAccessRule]::new()
                $resource.ParseGuid('userAccountControl', 'ObjectType')
            }
        } | Should -Throw -ExpectedMessage '*must be empty or a GUID*'
    }
}
