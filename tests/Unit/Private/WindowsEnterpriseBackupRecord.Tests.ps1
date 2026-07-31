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

        function Get-TestScheduledTaskDescriptor {
            param(
                [string]$Server = [Environment]::MachineName.ToUpperInvariant()
            )

            $descriptor = [pscustomobject]@{
                ObjectType      = 'ScheduledTask'
                Path            = '\WindowsAccessControlLab\Fixture'
                TaskPath        = '\WindowsAccessControlLab'
                TaskName        = 'Fixture'
                Server          = $Server
                CanonicalTarget = 'ScheduledTask:{0}:\WINDOWSACCESSCONTROLLAB\FIXTURE' -f
                    $Server
                Sections        = 4
                Sddl            = 'D:(A;;0x00000020;;;WD)'
            }
            $descriptor.PSObject.TypeNames.Insert(
                0, 'WindowsAccessControl.ScheduledTaskSecurityDescriptor'
            )
            $descriptor.PSObject.TypeNames.Add(
                'WindowsAccessControl.SecurityDescriptor'
            )
            $descriptor
        }

        function Get-TestTaskFolderDescriptor {
            $server = [Environment]::MachineName.ToUpperInvariant()
            $descriptor = [pscustomobject]@{
                ObjectType      = 'TaskFolder'
                Path            = '\WindowsAccessControlLab'
                TaskPath        = '\WindowsAccessControlLab'
                TaskName        = $null
                Server          = $server
                CanonicalTarget = 'TaskFolder:{0}:\WINDOWSACCESSCONTROLLAB' -f $server
                Sections        = 4
                Sddl            = 'D:(A;;0x00000021;;;WD)'
            }
            $descriptor.PSObject.TypeNames.Insert(
                0, 'WindowsAccessControl.TaskFolderSecurityDescriptor'
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

    It 'Should bind a registered-task record to its server and split identity' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestScheduledTaskDescriptor
        } {
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $Descriptor

            $record.RecordVersion | Should -Be 2
            $record.ObjectFamily | Should -BeExactly 'ScheduledTask'
            $record.Server | Should -BeExactly (
                [Environment]::MachineName.ToUpperInvariant()
            )
            $record.Target | Should -BeExactly '\WindowsAccessControlLab\Fixture'

            $restored = ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $record
            $restored.TaskPath | Should -BeExactly '\WindowsAccessControlLab'
            $restored.TaskName | Should -BeExactly 'Fixture'
        }
    }

    It 'Should bind a task-folder record without a leaf task name' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestTaskFolderDescriptor
        } {
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $Descriptor

            $record.RecordVersion | Should -Be 2
            $record.ObjectFamily | Should -BeExactly 'TaskFolder'

            $restored = ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $record
            $restored.TaskPath | Should -BeExactly '\WindowsAccessControlLab'
            $restored.TaskName | Should -BeNullOrEmpty
        }
    }

    It 'Should reject a Task Scheduler record whose canonical identity was retargeted' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestScheduledTaskDescriptor
        } {
            $Descriptor.CanonicalTarget = 'ScheduledTask:{0}:\OTHER\FIXTURE' -f
                [Environment]::MachineName.ToUpperInvariant()
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $Descriptor

            {
                ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $record
            } | Should -Throw '*matching server and task identity*'
        }
    }

    It 'Should reject a registered-task record that names the root task folder' {
        InModuleScope WindowsAccessControl {
            $server = [Environment]::MachineName.ToUpperInvariant()
            $descriptor = [pscustomobject]@{
                ObjectType      = 'ScheduledTask'
                Path            = '\Fixture'
                TaskPath        = '\'
                TaskName        = 'Fixture'
                Server          = $server
                CanonicalTarget = 'ScheduledTask:{0}:\FIXTURE' -f $server
                Sections        = 4
                Sddl            = 'D:(A;;0x00000020;;;WD)'
            }
            $descriptor.PSObject.TypeNames.Insert(
                0, 'WindowsAccessControl.SecurityDescriptor'
            )
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $descriptor

            {
                ConvertFrom-WindowsSecurityDescriptorBackupRecord -Record $record
            } | Should -Throw '*root task folder*'
        }
    }

    It 'Should require an allowed root path to restore Task Scheduler records' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestTaskFolderDescriptor
            Root       = $TestDrive
        } {
            $destination = Join-Path $Root 'task-backup.json'

            $Descriptor | Backup-WindowsSecurityDescriptor `
                -DestinationPath $destination `
                -Confirm:$false

            {
                Restore-WindowsSecurityDescriptor `
                    -BackupPath $destination `
                    -Confirm:$false
            } | Should -Throw '*AllowedRootPath*'
        }
    }

    It 'Should refuse to restore a task captured on another computer' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestScheduledTaskDescriptor -Server 'OTHERHOST'
            Root       = $TestDrive
        } {
            $destination = Join-Path $Root 'foreign-task-backup.json'

            $Descriptor | Backup-WindowsSecurityDescriptor `
                -DestinationPath $destination `
                -Confirm:$false

            {
                Restore-WindowsSecurityDescriptor `
                    -BackupPath $destination `
                    -AllowedRootPath '\WindowsAccessControlLab' `
                    -Confirm:$false
            } | Should -Throw '*captured on another computer*'
        }
    }

    It 'Should reject a Task Scheduler descriptor that selects another section' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestTaskFolderDescriptor
        } {
            $Descriptor.Sections = 5
            $Descriptor.Sddl = 'O:BAD:(A;;0x00000021;;;WD)'

            {
                ConvertTo-WindowsSecurityDescriptorBackupRecord `
                    -InputObject $Descriptor
            } | Should -Throw '*access section*'
        }
    }

    It 'Should restore a contained task folder through its own write path' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestTaskFolderDescriptor
            Root       = $TestDrive
        } {
            $destination = Join-Path $Root 'task-folder-restore.json'
            $Descriptor | Backup-WindowsSecurityDescriptor `
                -DestinationPath $destination `
                -Confirm:$false
            $expectedSddl = (Get-Content -LiteralPath $destination -Raw |
                ConvertFrom-Json).Records[0].Sddl
            Mock Resolve-WindowsTaskSchedulerTarget {
                [pscustomobject]@{
                    ObjectType      = 'TaskFolder'
                    Path            = $Descriptor.Path
                    TaskPath        = $Descriptor.TaskPath
                    CanonicalTarget = $Descriptor.CanonicalTarget
                }
            }
            Mock Get-TaskFolderSecurityDescriptor { $Descriptor }
            Mock Set-TaskFolderSecurityDescriptor

            Restore-WindowsSecurityDescriptor `
                -BackupPath $destination `
                -AllowedRootPath '\WindowsAccessControlLab' `
                -Confirm:$false

            Should -Invoke Resolve-WindowsTaskSchedulerTarget -Exactly -Times 1 `
                -ParameterFilter {
                    $ForWrite -and $AllowedRootPath -eq '\WindowsAccessControlLab'
                }
            Should -Invoke Set-TaskFolderSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $Path -eq '\WindowsAccessControlLab' -and
                        $Sddl -ceq $expectedSddl -and
                        $AllowedRootPath -eq '\WindowsAccessControlLab'
                }
        }
    }

    It 'Should restore a registered task through its split identity' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestScheduledTaskDescriptor
            Root       = $TestDrive
        } {
            $destination = Join-Path $Root 'scheduled-task-restore.json'
            $Descriptor | Backup-WindowsSecurityDescriptor `
                -DestinationPath $destination `
                -Confirm:$false
            $expectedSddl = (Get-Content -LiteralPath $destination -Raw |
                ConvertFrom-Json).Records[0].Sddl
            Mock Resolve-WindowsTaskSchedulerTarget {
                [pscustomobject]@{
                    ObjectType      = 'ScheduledTask'
                    Path            = $Descriptor.Path
                    TaskPath        = $Descriptor.TaskPath
                    TaskName        = $Descriptor.TaskName
                    CanonicalTarget = $Descriptor.CanonicalTarget
                }
            }
            Mock Get-ScheduledTaskSecurityDescriptor { $Descriptor }
            Mock Set-ScheduledTaskSecurityDescriptor

            Restore-WindowsSecurityDescriptor `
                -BackupPath $destination `
                -AllowedRootPath '\WindowsAccessControlLab' `
                -Confirm:$false

            Should -Invoke Get-ScheduledTaskSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $TaskPath -eq '\WindowsAccessControlLab' -and $TaskName -eq 'Fixture'
                }
            Should -Invoke Set-ScheduledTaskSecurityDescriptor -Exactly -Times 1 `
                -ParameterFilter {
                    $TaskPath -eq '\WindowsAccessControlLab' -and
                        $TaskName -eq 'Fixture' -and
                        $Sddl -ceq $expectedSddl
                }
        }
    }

    It 'Should reject a Task Scheduler record whose live target was retargeted' {
        InModuleScope WindowsAccessControl -Parameters @{
            Descriptor = Get-TestTaskFolderDescriptor
            Root       = $TestDrive
        } {
            $destination = Join-Path $Root 'task-folder-retargeted.json'
            $Descriptor | Backup-WindowsSecurityDescriptor `
                -DestinationPath $destination `
                -Confirm:$false
            Mock Resolve-WindowsTaskSchedulerTarget {
                [pscustomobject]@{
                    ObjectType      = 'TaskFolder'
                    Path            = '\Other'
                    TaskPath        = '\Other'
                    CanonicalTarget = 'TaskFolder:{0}:\OTHER' -f
                        [Environment]::MachineName.ToUpperInvariant()
                }
            }
            Mock Get-TaskFolderSecurityDescriptor { $Descriptor }
            Mock Set-TaskFolderSecurityDescriptor

            {
                Restore-WindowsSecurityDescriptor `
                    -BackupPath $destination `
                    -AllowedRootPath '\WindowsAccessControlLab' `
                    -Confirm:$false
            } | Should -Throw '*does not match its canonical identity*'
            Should -Invoke Set-TaskFolderSecurityDescriptor -Exactly -Times 0
        }
    }
}
