BeforeAll {
    Import-Module ActiveDirectory -ErrorAction Stop
    Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop

    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module WindowsAccessControl
    $script:domain = Get-ADDomain -ErrorAction Stop
    $script:server = [string]@(
        (Get-ADDomainController -Discover -Writable -ErrorAction Stop).HostName
    )[0]
    $rootDse = Get-ADRootDSE -Server $script:server -ErrorAction Stop
    $script:configurationDn = $rootDse.ConfigurationNamingContext
    $script:schemaDn = $rootDse.SchemaNamingContext
    $script:rootOu = "OU=WindowsAccessControlLab,$($script:domain.DistinguishedName)"
    $script:targetOu = "OU=Targets,$($script:rootOu)"
    $script:operator = Get-ADUser -Identity 'WacLabOperator' -Properties Enabled -ErrorAction Stop
    $script:testSid = (Get-ADUser -Identity 'WacLabUser' -ErrorAction Stop).SID.Value
    $script:originalDescriptor = Get-ADObjectSecurityDescriptor `
        -Server $script:server `
        -DistinguishedName $script:targetOu `
        -ThrottleLimit 1

    $passwordText = 'Wac!' + [guid]::NewGuid().ToString('N') + 'aA1'
    $script:password = [Security.SecureString]::new()
    foreach ($character in $passwordText.ToCharArray()) {
        $script:password.AppendChar($character)
    }
    $script:password.MakeReadOnly()
    $passwordText = $null
    Set-ADAccountPassword `
        -Identity $script:operator `
        -Reset `
        -NewPassword $script:password `
        -ErrorAction Stop
    Enable-ADAccount -Identity $script:operator -ErrorAction Stop
    $script:credential = [pscredential]::new(
        "$($script:domain.NetBIOSName)\$($script:operator.SamAccountName)",
        $script:password
    )

    $domainAdminSid = "$($script:domain.DomainSID.Value)-512"
    $isDomainAdmin = Get-ADGroupMember `
        -Identity $domainAdminSid `
        -Recursive `
        -ErrorAction Stop |
        Where-Object SID -EQ $script:operator.SID
    if ($isDomainAdmin) {
        throw 'The delegated AD test operator must not be a Domain Admin.'
    }

    $acl = Get-Acl -Path "AD:\$($script:targetOu)" -ErrorAction Stop
    $delegationRule = [DirectoryServices.ActiveDirectoryAccessRule]::new(
        $script:operator.SID,
        [DirectoryServices.ActiveDirectoryRights]::WriteDacl,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $null = $acl.AddAccessRule($delegationRule)
    Set-Acl -Path "AD:\$($script:targetOu)" -AclObject $acl -ErrorAction Stop
    $script:delegatedDescriptor = Get-ADObjectSecurityDescriptor `
        -Server $script:server `
        -DistinguishedName $script:targetOu `
        -ThrottleLimit 1
}

AfterAll {
    try {
        if ($script:originalDescriptor) {
            Set-ADObjectSecurityDescriptor `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -AllowedBaseDistinguishedName $script:targetOu `
                -Sddl $script:originalDescriptor.Sddl `
                -ThrottleLimit 1 `
                -Confirm:$false
            $restored = Get-ADObjectSecurityDescriptor `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -ThrottleLimit 1
            if ($restored.Sddl -cne $script:originalDescriptor.Sddl) {
                throw 'The disposable Active Directory object DACL was not restored.'
            }
        }
    }
    finally {
        if ($script:operator) {
            Disable-ADAccount -Identity $script:operator -ErrorAction SilentlyContinue
        }
        if ($script:password) {
            $script:password.Dispose()
        }
        $script:credential = $null
        $script:password = $null
        Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Active Directory object DACL commands' `
    -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    AfterEach {
        Set-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Sddl $script:delegatedDescriptor.Sddl `
            -ThrottleLimit 1 `
            -Confirm:$false
    }

    It 'Should use signed and sealed LDAP and deduplicate immutable targets' {
        $connection = & $script:module {
            param(
                [string]$Server,
                [pscredential]$Credential
            )
            New-WindowsADConnection `
                -Server $Server `
                -Credential $Credential `
                -TimeoutSeconds 10
        } $script:server $script:credential
        try {
            $connection.AuthType | Should -Be (
                [DirectoryServices.Protocols.AuthType]::Kerberos
            )
            $connection.SessionOptions.Signing | Should -BeTrue
            $connection.SessionOptions.Sealing | Should -BeTrue
            $connection.SessionOptions.ReferralChasing | Should -Be (
                [DirectoryServices.Protocols.ReferralChasingOptions]::None
            )
        }
        finally {
            $connection.Dispose()
        }

        $result = Get-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName @($script:targetOu, $script:targetOu.ToUpperInvariant()) `
            -Credential $script:credential
        $result | Should -HaveCount 1
        $result.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.ADObjectSecurityDescriptor'
        $result.ObjectGuid | Should -Not -Be ([guid]::Empty)
        $result.BinarySecurityDescriptor.Length | Should -BeGreaterThan 0
    }

    It 'Should report ACE provenance and resolved GUID names through a discovered domain controller' {
        $inherited = @(
            Get-ADObjectAccessRule `
                -DistinguishedName $script:targetOu `
                -ExcludeExplicit `
                -ThrottleLimit 1
        )

        $inherited | Should -Not -BeNullOrEmpty
        @($inherited.Server | Sort-Object -Unique) | Should -HaveCount 1
        $inherited[0].Server | Should -BeLike "*.$($script:domain.DNSRoot)"
        $inherited[0].Server | Should -BeExactly $inherited[0].Server.ToLowerInvariant()
        @($inherited | Where-Object { -not $_.InheritedFrom }) | Should -BeNullOrEmpty
        foreach ($rule in $inherited) {
            $rule.InheritedFrom | Should -Not -BeExactly $script:targetOu
            $script:targetOu | Should -BeLike "*$($rule.InheritedFrom)"
        }
        @(
            $inherited |
                Where-Object { $_.ObjectTypeGuid -ne [guid]::Empty -and -not $_.ObjectTypeName }
        ) | Should -BeNullOrEmpty
        @(
            $inherited |
                Where-Object {
                    $_.InheritedObjectTypeGuid -ne [guid]::Empty -and
                    -not $_.InheritedObjectTypeName
                }
        ) | Should -BeNullOrEmpty

        $explicit = @(
            Get-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $script:targetOu `
                -ExcludeInherited `
                -ThrottleLimit 1
        )
        @($explicit | Where-Object InheritedFrom) | Should -BeNullOrEmpty
    }

    It 'Should reject configuration and schema partition reads' {
        foreach ($distinguishedName in @(
                $script:configurationDn
                $script:schemaDn
            )) {
            {
                Get-ADObjectSecurityDescriptor `
                    -Server $script:server `
                    -DistinguishedName $distinguishedName `
                    -Credential $script:credential `
                    -ThrottleLimit 1 `
                    -ErrorAction Stop
            } | Should -Throw
            {
                Get-ADObjectAccessRule `
                    -Server $script:server `
                    -DistinguishedName $distinguishedName `
                    -Credential $script:credential `
                    -ThrottleLimit 1 `
                    -ErrorAction Stop
            } | Should -Throw
        }
    }

    It 'Should honor WhatIf under the delegated non-Domain-Admin identity' {
        $before = Get-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -Credential $script:credential `
            -ThrottleLimit 1

        Set-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Sddl 'D:(A;;RP;;;WD)' `
            -Credential $script:credential `
            -ThrottleLimit 1 `
            -WhatIf
        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Credential $script:credential `
            -Account $script:testSid `
            -AccessRights ReadProperty `
            -ThrottleLimit 1 `
            -WhatIf

        $after = Get-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -Credential $script:credential `
            -ThrottleLimit 1
        $after.Sddl | Should -BeExactly $before.Sddl
    }

    It 'Should add and exactly remove an object-specific ACE with rollback fidelity' {
        $objectType = [guid]'bf967953-0de6-11d0-a285-00aa003049e2'
        $inheritedObjectType = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
        $before = Get-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -Credential $script:credential `
            -ThrottleLimit 1

        $added = Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Credential $script:credential `
            -Account $script:testSid `
            -AccessRights WriteProperty `
            -InheritanceType Children `
            -ObjectType $objectType `
            -InheritedObjectType $inheritedObjectType `
            -ThrottleLimit 1 `
            -PassThru `
            -Confirm:$false

        $added | Should -Not -BeNullOrEmpty
        $added.SID | Should -Be $script:testSid
        $added.AccessRights.ToString() | Should -Be 'WriteProperty'
        $added.InheritanceType.ToString() | Should -Be 'Children'
        $added.ObjectTypeGuid | Should -Be $objectType
        $added.InheritedObjectTypeGuid | Should -Be $inheritedObjectType
        $added.NativeAce | Should -BeOfType ([Security.AccessControl.ObjectAce])

        $queried = Get-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -Credential $script:credential `
            -Account $script:testSid `
            -ExcludeInherited `
            -ThrottleLimit 1 |
            Where-Object ObjectTypeGuid -EQ $objectType
        $queried | Should -HaveCount 1

        $removed = $queried | Remove-ADObjectAccessRule `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Credential $script:credential `
            -TimeoutSeconds 10 `
            -PassThru `
            -Confirm:$false
        $removed.SID | Should -Be $script:testSid

        $after = Get-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -Credential $script:credential `
            -ThrottleLimit 1
        $after.Sddl | Should -BeExactly $before.Sddl
    }

    It 'Should reject protected, out-of-bound, and stale-object writes' {
        {
            Set-ADObjectSecurityDescriptor `
                -Server $script:server `
                -DistinguishedName $script:domain.DistinguishedName `
                -AllowedBaseDistinguishedName $script:targetOu `
                -Sddl $script:delegatedDescriptor.Sddl `
                -ThrottleLimit 1 `
                -WhatIf `
                -ErrorAction Stop
        } | Should -Throw

        $rule = Get-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -Credential $script:credential `
            -ExcludeInherited `
            -ThrottleLimit 1 |
            Select-Object -First 1
        $staleRule = $rule.PSObject.Copy()
        $staleRule.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.ADObjectAccessRule')
        $staleRule.ObjectGuid = [guid]::NewGuid()
        {
            $staleRule | Remove-ADObjectAccessRule `
                -AllowedBaseDistinguishedName $script:targetOu `
                -Credential $script:credential `
                -TimeoutSeconds 10 `
                -WhatIf `
                -ErrorAction Stop
        } | Should -Throw
    }

    It 'Should replace same-scope rules and preserve a different object scope' {
        $objectType = [guid]'bf967953-0de6-11d0-a285-00aa003049e2'
        $before = Get-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -Credential $script:credential `
            -ThrottleLimit 1

        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Credential $script:credential `
            -Account $script:testSid `
            -AccessRights ReadProperty `
            -ThrottleLimit 1 `
            -Confirm:$false
        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Credential $script:credential `
            -Account $script:testSid `
            -AccessRights ReadProperty `
            -ObjectType $objectType `
            -ThrottleLimit 1 `
            -Confirm:$false

        Set-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Credential $script:credential `
            -Account $script:testSid `
            -AccessRights WriteProperty `
            -ThrottleLimit 1 `
            -Confirm:$false

        $rules = @(Get-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -Credential $script:credential `
            -Account $script:testSid `
            -ExcludeInherited `
            -ThrottleLimit 1)
        $common = @($rules | Where-Object ObjectTypeGuid -EQ ([guid]::Empty))
        $scoped = @($rules | Where-Object ObjectTypeGuid -EQ $objectType)

        $common | Should -HaveCount 1
        $common[0].AccessRights.ToString() | Should -Be 'WriteProperty'
        $scoped | Should -HaveCount 1
        $scoped[0].AccessRights.ToString() | Should -Be 'ReadProperty'

        Clear-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Credential $script:credential `
            -Account $script:testSid `
            -ThrottleLimit 1 `
            -Confirm:$false

        $after = Get-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -Credential $script:credential `
            -ThrottleLimit 1
        $after.Sddl | Should -BeExactly $before.Sddl
    }

    It 'Should subtract rights and purge an account without touching other rules' {
        $before = Get-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -Credential $script:credential `
            -ThrottleLimit 1
        $beforeCount = @(Get-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -Credential $script:credential `
            -ExcludeInherited `
            -ThrottleLimit 1).Count

        Add-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Credential $script:credential `
            -Account $script:testSid `
            -AccessRights 'ReadProperty, WriteProperty' `
            -ThrottleLimit 1 `
            -Confirm:$false

        Remove-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Credential $script:credential `
            -Account $script:testSid `
            -AccessRights WriteProperty `
            -RemovalMode Rights `
            -ThrottleLimit 1 `
            -Confirm:$false

        $subtracted = @(Get-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -Credential $script:credential `
            -Account $script:testSid `
            -ExcludeInherited `
            -ThrottleLimit 1)
        $subtracted | Should -HaveCount 1
        $subtracted[0].AccessRights.ToString() | Should -Be 'ReadProperty'

        $purged = @(Remove-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -AllowedBaseDistinguishedName $script:targetOu `
            -Credential $script:credential `
            -Account $script:testSid `
            -RemovalMode All `
            -ThrottleLimit 1 `
            -PassThru `
            -Confirm:$false)

        $purged | Should -HaveCount 1
        $purged[0].SID | Should -Be $script:testSid

        $remaining = @(Get-ADObjectAccessRule `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -Credential $script:credential `
            -ExcludeInherited `
            -ThrottleLimit 1)
        $remaining | Should -HaveCount $beforeCount

        $after = Get-ADObjectSecurityDescriptor `
            -Server $script:server `
            -DistinguishedName $script:targetOu `
            -Credential $script:credential `
            -ThrottleLimit 1
        $after.Sddl | Should -BeExactly $before.Sddl
    }

    It 'Should reject a clear that would leave the object unmanageable' {
        # Use a disposable child OU. Protecting the shared target OU and then
        # removing its only manage grant would lock the fixture out of its own
        # restore path.
        $gateOu = "OU=WacGateTest,$($script:targetOu)"
        $null = New-ADOrganizationalUnit `
            -Name 'WacGateTest' `
            -Path $script:targetOu `
            -Server $script:server `
            -ProtectedFromAccidentalDeletion:$false `
            -ErrorAction Stop
        try {
            $protectedSddl = 'D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)'
            Set-ADObjectSecurityDescriptor `
                -Server $script:server `
                -DistinguishedName $gateOu `
                -AllowedBaseDistinguishedName $script:targetOu `
                -Sddl $protectedSddl `
                -ThrottleLimit 1 `
                -Confirm:$false

            $before = Get-ADObjectSecurityDescriptor `
                -Server $script:server `
                -DistinguishedName $gateOu `
                -ThrottleLimit 1

            {
                Clear-ADObjectAccessRule `
                    -Server $script:server `
                    -DistinguishedName $gateOu `
                    -AllowedBaseDistinguishedName $script:targetOu `
                    -ThrottleLimit 1 `
                    -Confirm:$false `
                    -ErrorAction Stop
            } | Should -Throw -ExpectedMessage '*no principal with WriteDacl*'

            $unchanged = Get-ADObjectSecurityDescriptor `
                -Server $script:server `
                -DistinguishedName $gateOu `
                -ThrottleLimit 1
            $unchanged.Sddl | Should -BeExactly $before.Sddl
        }
        finally {
            Remove-ADOrganizationalUnit `
                -Identity $gateOu `
                -Server $script:server `
                -Confirm:$false `
                -ErrorAction SilentlyContinue
        }
    }

    It 'Should reject a staged write whose target changed after the read' {
        $raceOu = "OU=WacRaceTest,$($script:targetOu)"
        $null = New-ADOrganizationalUnit `
            -Name 'WacRaceTest' `
            -Path $script:targetOu `
            -Server $script:server `
            -ProtectedFromAccidentalDeletion:$false `
            -ErrorAction Stop
        try {
            $target = & $script:module {
                param($Server, $DistinguishedName, $Base)
                Resolve-WindowsADObjectTarget `
                    -Server $Server `
                    -DistinguishedName $DistinguishedName `
                    -AllowedBaseDistinguishedName $Base `
                    -TimeoutSeconds 10 `
                    -ForWrite
            } $script:server $raceOu $script:targetOu

            # Commit a competing change after the descriptor was staged.
            Add-ADObjectAccessRule `
                -Server $script:server `
                -DistinguishedName $raceOu `
                -AllowedBaseDistinguishedName $script:targetOu `
                -Account $script:testSid `
                -AccessRights ReadProperty `
                -ThrottleLimit 1 `
                -Confirm:$false

            {
                & $script:module {
                    param($Target, $Base)
                    $staged = Invoke-WindowsADAccessRuleMutation `
                        -SecurityDescriptor $Target.BinarySecurityDescriptor `
                        -Operation Add `
                        -SecurityIdentifier (
                            [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
                        ) `
                        -AccessMask ([int][WindowsActiveDirectoryRights]::ReadProperty)
                    Set-WindowsADObjectSecurityDescriptor `
                        -Target $Target `
                        -AllowedBaseDistinguishedName $Base `
                        -TimeoutSeconds 10 `
                        -SecurityDescriptor $staged `
                        -ExpectedSecurityDescriptor $Target.BinarySecurityDescriptor
                } $target $script:targetOu
            } | Should -Throw -ExpectedMessage '*changed after it was read*'
        }
        finally {
            Remove-ADOrganizationalUnit `
                -Identity $raceOu `
                -Server $script:server `
                -Confirm:$false `
                -ErrorAction SilentlyContinue
        }
    }
}
