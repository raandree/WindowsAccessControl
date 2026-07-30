BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Enterprise backup schema version 2' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        function Get-TestSmbDescriptor {
            $descriptor = [pscustomobject]@{
                ObjectType      = 'SmbShare'
                Path            = 'WacLab$'
                ShareName       = 'WacLab$'
                Server          = 'WACMEMBER'
                CanonicalTarget = 'SmbShare:WACMEMBER:WACLAB$'
                Sections        = 4
                Sddl            = 'D:(A;;0x001200A9;;;WD)'
            }
            $descriptor.PSObject.TypeNames.Insert(
                0, 'WindowsAccessControl.SmbShareSecurityDescriptor'
            )
            $descriptor.PSObject.TypeNames.Add(
                'WindowsAccessControl.SecurityDescriptor'
            )
            $descriptor
        }

        function Get-TestADDescriptor {
            $descriptor = [pscustomobject]@{
                ObjectType           = 'ADObject'
                Path                 = 'CN=Test,OU=Targets,DC=contoso,DC=test'
                Server               = 'dc01.contoso.test'
                DistinguishedName    = 'CN=Test,OU=Targets,DC=contoso,DC=test'
                ObjectGuid           = [guid]'2f1d6c4a-6b6f-4a0e-9d02-3a1f9f0a1234'
                DefaultNamingContext = 'DC=contoso,DC=test'
                CanonicalTarget      =
                    'ADObject:DC01.CONTOSO.TEST:2F1D6C4A-6B6F-4A0E-9D02-3A1F9F0A1234'
                Sections             = 4
                Sddl                 = 'D:(A;;0x00000010;;;WD)'
            }
            $descriptor.PSObject.TypeNames.Insert(
                0, 'WindowsAccessControl.ADObjectSecurityDescriptor'
            )
            $descriptor.PSObject.TypeNames.Add(
                'WindowsAccessControl.SecurityDescriptor'
            )
            $descriptor
        }
    }

    It 'Should bind an SMB share record to record version 2 and its server' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestSmbDescriptor
        } {
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $Descriptor

            $record.RecordVersion | Should -Be 2
            $record.ObjectFamily | Should -BeExactly 'SmbShare'
            $record.Server | Should -BeExactly 'WACMEMBER'
            $record.ShareName | Should -BeExactly 'WacLab$'
            $record.Target | Should -BeExactly 'WacLab$'
            $record.CanonicalTarget | Should -BeExactly 'SmbShare:WACMEMBER:WACLAB$'

            $restored = ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $record
            $restored.RecordVersion | Should -Be 2
            $restored.Server | Should -BeExactly 'WACMEMBER'
            $restored.ShareName | Should -BeExactly 'WacLab$'
        }
    }

    It 'Should bind a directory record to its server, domain, and object GUID' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestADDescriptor
        } {
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $Descriptor

            $record.RecordVersion | Should -Be 2
            $record.ObjectFamily | Should -BeExactly 'ADObject'
            $record.Server | Should -BeExactly 'dc01.contoso.test'
            $record.DistinguishedName |
                Should -BeExactly 'CN=Test,OU=Targets,DC=contoso,DC=test'
            $record.ObjectGuid |
                Should -BeExactly '2F1D6C4A-6B6F-4A0E-9D02-3A1F9F0A1234'
            $record.DomainNamingContext | Should -BeExactly 'DC=contoso,DC=test'

            $restored = ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $record
            $restored.ObjectGuid |
                Should -Be ([guid]'2f1d6c4a-6b6f-4a0e-9d02-3a1f9f0a1234')
            $restored.DomainNamingContext | Should -BeExactly 'DC=contoso,DC=test'
        }
    }

    It 'Should reject an enterprise record downgraded to record version 1' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestSmbDescriptor
        } {
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $Descriptor
            $record.RecordVersion = 1

            {
                ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $record
            } | Should -Throw '*record version 2*'
        }
    }

    It 'Should reject a local family that claims record version 2' {
        InModuleScope WindowsAccessControl {
            $descriptor = [pscustomobject]@{
                ObjectType      = 'Service'
                ServiceName     = 'BITS'
                CanonicalTarget = 'Service:Local:BITS'
                Sections        = 4
                Sddl            = 'D:(A;;0x00000004;;;WD)'
            }
            $descriptor.PSObject.TypeNames.Insert(
                0, 'WindowsAccessControl.SecurityDescriptor'
            )
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $descriptor
            $record.RecordVersion | Should -Be 1
            $record.RecordVersion = 2

            {
                ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $record
            } | Should -Throw '*record version 1*'
        }
    }

    It 'Should detect a tampered enterprise server identity' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestSmbDescriptor
        } {
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $Descriptor
            $record.Server = 'OTHERSERVER'
            $record.CanonicalTarget = 'SmbShare:OTHERSERVER:WACLAB$'

            {
                ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $record
            } | Should -Throw '*integrity validation failed*'
        }
    }

    It 'Should reject a directory record outside its recorded domain partition' {
        InModuleScope WindowsAccessControl {
            $descriptor = [pscustomobject]@{
                ObjectType           = 'ADObject'
                Server               = 'dc01.contoso.test'
                DistinguishedName    = 'CN=Test,OU=Targets,DC=fabrikam,DC=test'
                ObjectGuid           = [guid]'2f1d6c4a-6b6f-4a0e-9d02-3a1f9f0a1234'
                DefaultNamingContext = 'DC=contoso,DC=test'
                CanonicalTarget      =
                    'ADObject:DC01.CONTOSO.TEST:2F1D6C4A-6B6F-4A0E-9D02-3A1F9F0A1234'
                Sections             = 4
                Sddl                 = 'D:(A;;0x00000010;;;WD)'
            }
            $descriptor.PSObject.TypeNames.Insert(
                0, 'WindowsAccessControl.SecurityDescriptor'
            )
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $descriptor

            {
                ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $record
            } | Should -Throw '*recorded domain partition*'
        }
    }

    It 'Should raise the envelope schema version for enterprise records' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestSmbDescriptor
            Root       = $TestDrive
        } {
            $destination = Join-Path $Root 'enterprise-backup.json'

            $Descriptor | Backup-WindowsSecurityDescriptor `
                -DestinationPath $destination `
                -Confirm:$false

            $document = Get-Content -LiteralPath $destination -Raw | ConvertFrom-Json
            $document.SchemaVersion | Should -Be 2
            $document.Records[0].RecordVersion | Should -Be 2
        }
    }

    It 'Should reject a version 2 record inside a version 1 envelope' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestSmbDescriptor
            Root       = $TestDrive
        } {
            $destination = Join-Path $Root 'downgraded-backup.json'

            $Descriptor | Backup-WindowsSecurityDescriptor `
                -DestinationPath $destination `
                -Confirm:$false
            $document = Get-Content -LiteralPath $destination -Raw | ConvertFrom-Json
            $document.SchemaVersion = 1
            $document | ConvertTo-Json -Depth 8 |
                Set-Content -LiteralPath $destination -Encoding utf8

            {
                Restore-WindowsSecurityDescriptor `
                    -BackupPath $destination `
                    -Confirm:$false
            } | Should -Throw '*schema version 1*'
        }
    }

    It 'Should require an allowed base to restore directory records' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestADDescriptor
            Root       = $TestDrive
        } {
            $destination = Join-Path $Root 'directory-backup.json'

            $Descriptor | Backup-WindowsSecurityDescriptor `
                -DestinationPath $destination `
                -Confirm:$false

            {
                Restore-WindowsSecurityDescriptor `
                    -BackupPath $destination `
                    -Confirm:$false
            } | Should -Throw '*AllowedBaseDistinguishedName*'
        }
    }

    It 'Should refuse to restore a share captured on another computer' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestSmbDescriptor
            Root       = $TestDrive
        } {
            $destination = Join-Path $Root 'foreign-share-backup.json'

            $Descriptor | Backup-WindowsSecurityDescriptor `
                -DestinationPath $destination `
                -Confirm:$false

            {
                Restore-WindowsSecurityDescriptor `
                    -BackupPath $destination `
                    -Confirm:$false
            } | Should -Throw '*captured on another server*'
        }
    }

    It 'Should reject the same directory object captured through two controllers' {
        $first = Get-TestADDescriptor
        $second = Get-TestADDescriptor
        $second.Server = 'dc02.contoso.test'
        $second.CanonicalTarget =
            'ADObject:DC02.CONTOSO.TEST:2F1D6C4A-6B6F-4A0E-9D02-3A1F9F0A1234'

        InModuleScope WindowsAccessControl -Parameters @{
            First  = $first
            Second = $second
            Root   = $TestDrive
        } {
            {
                @($First, $Second) | Backup-WindowsSecurityDescriptor `
                    -DestinationPath (Join-Path $Root 'duplicate.json') `
                    -Confirm:$false
            } | Should -Throw '*duplicate records*'
        }
    }

    It 'Should reject an enterprise descriptor that selects another section' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestSmbDescriptor
        } {
            $Descriptor.Sections = 5
            $Descriptor.Sddl = 'O:BAD:(A;;0x001200A9;;;WD)'

            {
                ConvertTo-WindowsSecurityDescriptorBackupRecord `
                    -InputObject $Descriptor
            } | Should -Throw '*access section*'
        }
    }

    It 'Should not surface unauthenticated enterprise fields on a version 1 record' {
        InModuleScope WindowsAccessControl {
            $descriptor = [pscustomobject]@{
                ObjectType      = 'Service'
                ServiceName     = 'BITS'
                CanonicalTarget = 'Service:Local:BITS'
                Sections        = 4
                Sddl            = 'D:(A;;0x00000004;;;WD)'
            }
            $descriptor.PSObject.TypeNames.Insert(
                0, 'WindowsAccessControl.SecurityDescriptor'
            )
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $descriptor
            $record.Server = 'INJECTED'
            $record.ShareName = 'INJECTED'
            $record.DistinguishedName = 'CN=Injected,DC=contoso,DC=test'
            $record.DomainNamingContext = 'DC=contoso,DC=test'

            $restored = ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $record

            $restored.Server | Should -BeNullOrEmpty
            $restored.ShareName | Should -BeNullOrEmpty
            $restored.DistinguishedName | Should -BeNullOrEmpty
            $restored.DomainNamingContext | Should -BeNullOrEmpty
        }
    }
}
