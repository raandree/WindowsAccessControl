BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module -Name 'WindowsAccessControl'
    $script:canonicalTarget =
        'CertificatePrivateKey:Cng:Machine:' + ('A1B2C3D4' * 8)
    $script:providerName = 'Microsoft Software Key Storage Provider'
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Certificate private-key backup record' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        function Get-TestPrivateKeyDescriptor {
            param(
                [string]$Server = [Environment]::MachineName,
                [string]$ProviderName = 'Microsoft Software Key Storage Provider',
                [string]$KeyName = 'WacUnitKey',
                [string]$KeyScope = 'Machine',
                [string]$Thumbprint = '0123456789ABCDEF0123456789ABCDEF01234567',
                [string]$CanonicalTarget =
                    ('CertificatePrivateKey:Cng:Machine:' + ('A1B2C3D4' * 8)),
                [int]$Sections = 4,
                [string]$Sddl = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
            )

            $descriptor = [pscustomobject]@{
                ObjectType            = 'CertificatePrivateKey'
                Path                  = $Thumbprint
                Server                = $Server
                ProviderName          = $ProviderName
                KeyName               = $KeyName
                UniqueName            = 'container-file-name'
                KeyScope              = $KeyScope
                CertificateThumbprint = $Thumbprint
                CanonicalTarget       = $CanonicalTarget
                Sections              = $Sections
                Sddl                  = $Sddl
            }
            $descriptor.PSObject.TypeNames.Insert(
                0, 'WindowsAccessControl.CertificatePrivateKeySecurityDescriptor'
            )
            $descriptor.PSObject.TypeNames.Add(
                'WindowsAccessControl.SecurityDescriptor'
            )
            $descriptor
        }
    }

    It 'Should bind the record to version 2, its computer, and its key selector' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestPrivateKeyDescriptor
            Expected   = $script:canonicalTarget
        } {
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $Descriptor

            $record.RecordVersion | Should -Be 2
            $record.ObjectFamily | Should -BeExactly 'CertificatePrivateKey'
            $record.Server | Should -BeExactly ([Environment]::MachineName)
            $record.ProviderName |
                Should -BeExactly 'Microsoft Software Key Storage Provider'
            $record.KeyName | Should -BeExactly 'WacUnitKey'
            $record.KeyScope | Should -BeExactly 'Machine'
            $record.Target | Should -BeExactly 'WacUnitKey'
            $record.CanonicalTarget | Should -BeExactly $Expected
            $record.CertificateThumbprint |
                Should -BeExactly '0123456789ABCDEF0123456789ABCDEF01234567'

            $restored = ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $record
            $restored.RecordVersion | Should -Be 2
            $restored.ProviderName |
                Should -BeExactly 'Microsoft Software Key Storage Provider'
            $restored.KeyName | Should -BeExactly 'WacUnitKey'
            $restored.KeyScope | Should -BeExactly 'Machine'
        }
    }

    It 'Should never carry certificate or private-key material' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestPrivateKeyDescriptor
        } {
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $Descriptor

            $json = $record | ConvertTo-Json -Depth 8
            $json | Should -Not -Match 'BEGIN [A-Z ]*PRIVATE KEY'
            $json | Should -Not -Match 'RawData|Modulus|Exponent|"PrivateKey"'
            @($record.PSObject.Properties.Name) | Should -Not -Contain 'UniqueName'
            @($record.PSObject.Properties.Name) | Should -Not -Contain 'Certificate'
        }
    }

    It 'Should reject a private-key backup that selects another section' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestPrivateKeyDescriptor -Sections 5 `
                -Sddl 'O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
        } {
            {
                ConvertTo-WindowsSecurityDescriptorBackupRecord -InputObject $Descriptor
            } | Should -Throw '*selects only the access section*'
        }
    }

    It 'Should reject a private-key backup without <Property>' -ForEach @(
        @{ Property = 'Server'; Splat = @{ Server = '' } }
        @{ Property = 'ProviderName'; Splat = @{ ProviderName = '' } }
        @{ Property = 'KeyName'; Splat = @{ KeyName = '' } }
        @{ Property = 'a supported KeyScope'; Splat = @{ KeyScope = 'Session' } }
    ) {
        $descriptor = Get-TestPrivateKeyDescriptor @Splat
        InModuleScope WindowsAccessControl -Parameters @{ Descriptor = $descriptor } {
            {
                ConvertTo-WindowsSecurityDescriptorBackupRecord -InputObject $Descriptor
            } | Should -Throw '*requires a server identity, provider, key name, and key scope*'
        }
    }

    It 'Should not change the digest of another version 2 family' {
        InModuleScope WindowsAccessControl {
            # The four private-key fields are hashed for that family only, so
            # every enterprise record written before this increment keeps
            # validating.
            $record = [pscustomobject]@{
                RecordVersion         = 2
                ObjectFamily          = 'TaskFolder'
                Target                = '\WindowsAccessControlLab'
                Path                  = $null
                CanonicalTarget       = 'TaskFolder:WACNODE:\WINDOWSACCESSCONTROLLAB'
                ItemType              = $null
                RegistryView          = $null
                ProcessId             = $null
                CreationTimeFileTime  = $null
                Server                = 'WACNODE'
                ShareName             = $null
                DistinguishedName     = $null
                ObjectGuid            = $null
                DomainNamingContext   = $null
                ProviderName          = $null
                KeyName               = $null
                KeyScope              = $null
                CertificateThumbprint = $null
                Sections              = 4
                Sddl                  = 'D:(A;;0x00000021;;;WD)'
            }
            $baseline = Get-WindowsSecurityDescriptorRecordHash -Record $record

            $record.ProviderName = 'Microsoft Software Key Storage Provider'
            $record.KeyName = 'WacUnitKey'
            $record.KeyScope = 'Machine'
            $record.CertificateThumbprint = '0123456789ABCDEF0123456789ABCDEF01234567'
            $withKeyFields = Get-WindowsSecurityDescriptorRecordHash -Record $record

            (-join @($withKeyFields | ForEach-Object { $_.ToString('X2') })) |
                Should -BeExactly (-join @($baseline | ForEach-Object { $_.ToString('X2') }))
        }
    }

    It 'Should detect a tampered <Property>' -ForEach @(
        @{ Property = 'ProviderName'; Value = 'Microsoft Smart Card Key Storage Provider' }
        @{ Property = 'KeyName'; Value = 'AnotherKey' }
        @{ Property = 'KeyScope'; Value = 'User' }
        @{ Property = 'Server'; Value = 'OTHERNODE' }
        @{ Property = 'CertificateThumbprint'; Value = 'FEDCBA9876543210FEDCBA9876543210FEDCBA98' }
    ) {
        $descriptor = Get-TestPrivateKeyDescriptor
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor    = $descriptor
            PropertyName  = $Property
            PropertyValue = $Value
        } {
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $Descriptor
            $record.$PropertyName = $PropertyValue

            {
                ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $record
            } | Should -Throw '*integrity validation failed*'
        }
    }
}

Describe 'Certificate private-key record validation' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        function New-TestPrivateKeyRecord {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
                'PSUseShouldProcessForStateChangingFunctions',
                '',
                Justification = 'This Pester fixture only builds an in-memory record.'
            )]
            param([hashtable]$Override = @{})

            $values = @{
                RecordVersion         = 2
                ObjectFamily          = 'CertificatePrivateKey'
                Target                = 'WacUnitKey'
                Path                  = $null
                CanonicalTarget       =
                    ('CertificatePrivateKey:Cng:Machine:' + ('A1B2C3D4' * 8))
                ItemType              = $null
                RegistryView          = $null
                ProcessId             = $null
                CreationTimeFileTime  = $null
                Server                = [Environment]::MachineName
                ShareName             = $null
                DistinguishedName     = $null
                ObjectGuid            = $null
                DomainNamingContext   = $null
                ProviderName          = 'Microsoft Software Key Storage Provider'
                KeyName               = 'WacUnitKey'
                KeyScope              = 'Machine'
                CertificateThumbprint = '0123456789ABCDEF0123456789ABCDEF01234567'
                Sections              = 4
                Sddl                  = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
            }
            foreach ($key in $Override.Keys) {
                $values[$key] = $Override[$key]
            }
            $record = [pscustomobject]$values
            # The digest is recomputed so each case reaches the validation rule
            # under test instead of stopping at an integrity failure.
            $hash = & $script:module {
                param($Candidate)
                Get-WindowsSecurityDescriptorRecordHash -Record $Candidate
            } $record
            $record | Add-Member -NotePropertyName Integrity -NotePropertyValue (
                [pscustomobject]@{
                    Algorithm = 'SHA256'
                    Digest    = -join @($hash | ForEach-Object { $_.ToString('X2') })
                }
            )
            $record
        }
    }

    It 'Should accept a well-formed record' {
        $record = New-TestPrivateKeyRecord
        $validated = & $script:module {
            param($Candidate)
            ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $Candidate
        } $record

        $validated.ObjectFamily | Should -BeExactly 'CertificatePrivateKey'
        $validated.KeyScope | Should -BeExactly 'Machine'
    }

    It 'Should reject <Case>' -ForEach @(
        @{
            Case     = 'a version 1 private-key record'
            Override = @{ RecordVersion = 1 }
            Message  = '*must use record version 2*'
        }
        @{
            Case     = 'a target that is not the persisted key name'
            Override = @{ Target = 'SomethingElse' }
            Message  = '*matching server, provider, key name, and key scope*'
        }
        @{
            Case     = 'a missing provider name'
            Override = @{ ProviderName = '' }
            Message  = '*matching server, provider, key name, and key scope*'
        }
        @{
            Case     = 'a key scope outside the supported set'
            Override = @{ KeyScope = 'machine' }
            Message  = '*matching server, provider, key name, and key scope*'
        }
        @{
            Case     = 'a canonical identity whose scope disagrees with the record'
            Override = @{ KeyScope = 'User' }
            Message  = '*canonical key identity that matches its key scope*'
        }
        @{
            Case     = 'a canonical identity that is not a private-key identity'
            Override = @{ CanonicalTarget = 'SmbShare:WACNODE:WACLAB' }
            Message  = '*canonical key identity that matches its key scope*'
        }
        @{
            Case     = 'a malformed evidence thumbprint'
            Override = @{ CertificateThumbprint = 'not-a-thumbprint' }
            Message  = '*malformed certificate thumbprint*'
        }
        @{
            Case     = 'a section selection other than access'
            Override = @{
                Sections = 5
                Sddl     = 'O:BAD:P(A;;FA;;;SY)'
            }
            Message  = '*selects only the access section*'
        }
        @{
            Case     = 'a null DACL'
            Override = @{ Sddl = 'O:BAG:SY' }
            Message  = '*selected non-null DACL*'
        }
    ) {
        $record = New-TestPrivateKeyRecord -Override $Override
        $expectedMessage = $Message
        {
            & $script:module {
                param($Candidate)
                ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $Candidate
            } $record
        } | Should -Throw $expectedMessage
    }

    It 'Should accept a record that carries no evidence thumbprint' {
        $record = New-TestPrivateKeyRecord -Override @{ CertificateThumbprint = '' }
        $validated = & $script:module {
            param($Candidate)
            ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $Candidate
        } $record

        $validated.CertificateThumbprint | Should -BeExactly ''
    }
}
