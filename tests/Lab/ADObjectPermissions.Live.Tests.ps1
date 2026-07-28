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
}
