# Versioned backup prevalidation and restore safety (FR-10, NFR-6, NFR-8, ADR 0005).
BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
}

Describe 'Restore-NTFSItemSecurityDescriptor' -Tag 'Integration', 'WindowsOnly' {
    It 'Should restore the selected descriptor sections from JSON backup' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'restore.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'restore.json'
        Set-Content -LiteralPath $testFile -Value 'test'
        Add-NTFSAccessRule -LiteralPath $testFile -Account 'S-1-1-0' -AccessRights Read
        Backup-NTFSItemSecurityDescriptor -LiteralPath $testFile -DestinationPath $backupPath -Sections Access
        Get-NTFSAccessRule -LiteralPath $testFile -Account 'S-1-1-0' -ExcludeInherited |
            Remove-NTFSAccessRule -Confirm:$false

        Restore-NTFSItemSecurityDescriptor -BackupPath $backupPath -Confirm:$false

        Get-NTFSAccessRule -LiteralPath $testFile -Account 'S-1-1-0' -ExcludeInherited |
            Should -HaveCount 1
    }

    It 'Should restore a valid historical schema one document' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'historical-restore.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'historical-restore.json'
        Set-Content -LiteralPath $testFile -Value 'historical'
        Add-NTFSAccessRule -LiteralPath $testFile `
            -Account 'S-1-1-0' `
            -AccessRights Read
        $sddl = (Get-NTFSItemSecurityDescriptor `
            -LiteralPath $testFile `
            -Sections Access).Sddl
        @{
            SchemaVersion = 1
            CreatedUtc    = [DateTime]::UtcNow.ToString('o')
            Records       = @(
                @{
                    Path     = [System.IO.Path]::GetFullPath($testFile)
                    ItemType = 'File'
                    Sections = 2
                    Sddl     = $sddl
                }
            )
        } | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $backupPath -Encoding utf8
        Get-NTFSAccessRule -LiteralPath $testFile `
            -Account 'S-1-1-0' `
            -ExcludeInherited |
            Remove-NTFSAccessRule -Confirm:$false

        Restore-NTFSItemSecurityDescriptor `
            -BackupPath $backupPath `
            -Confirm:$false

        Get-NTFSAccessRule -LiteralPath $testFile `
            -Account 'S-1-1-0' `
            -ExcludeInherited |
            Should -HaveCount 1
    }

    It 'Should validate every record before persisting any descriptor' {
        $firstFile = Join-Path -Path $TestDrive -ChildPath 'atomic-first.txt'
        $secondFile = Join-Path -Path $TestDrive -ChildPath 'atomic-second.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'atomic.json'
        Set-Content -LiteralPath $firstFile -Value 'first'
        Set-Content -LiteralPath $secondFile -Value 'second'
        Add-NTFSAccessRule -LiteralPath $firstFile -Account 'S-1-1-0' -AccessRights Read
        Add-NTFSAccessRule -LiteralPath $secondFile -Account 'S-1-1-0' -AccessRights Read
        Get-Item -LiteralPath $firstFile, $secondFile |
            Backup-NTFSItemSecurityDescriptor -DestinationPath $backupPath -Sections Access
        Get-NTFSAccessRule -LiteralPath $firstFile -Account 'S-1-1-0' -ExcludeInherited |
            Remove-NTFSAccessRule -Confirm:$false
        Get-NTFSAccessRule -LiteralPath $secondFile -Account 'S-1-1-0' -ExcludeInherited |
            Remove-NTFSAccessRule -Confirm:$false

        $backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
        $backup.Records[1].Sections = 99
        $backup | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath -Encoding utf8

        {
            Restore-NTFSItemSecurityDescriptor -BackupPath $backupPath -Confirm:$false
        } | Should -Throw -ExpectedMessage '*invalid sections*'
        Get-NTFSAccessRule -LiteralPath $firstFile -Account 'S-1-1-0' -ExcludeInherited |
            Should -BeNullOrEmpty
    }

    It 'Should reject unsupported schemas and malformed records' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'invalid-record.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'invalid-record.json'
        Set-Content -LiteralPath $testFile -Value 'test'

        @{
            SchemaVersion = 2
            Records       = @()
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath -Encoding utf8
        {
            Restore-NTFSItemSecurityDescriptor -BackupPath $backupPath -Confirm:$false
        } | Should -Throw -ExpectedMessage '*not a supported*'

        @{
            SchemaVersion = 1
            Records       = @(
                @{
                    Path     = $testFile
                    ItemType = 'File'
                    Sections = 4
                    Sddl     = 'not-valid-sddl'
                }
            )
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath -Encoding utf8
        {
            Restore-NTFSItemSecurityDescriptor -BackupPath $backupPath -Confirm:$false
        } | Should -Throw
    }

    It 'Should reject incomplete, missing, mismatched, and duplicate targets' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'metadata-target.txt'
        $missingFile = Join-Path -Path $TestDrive -ChildPath 'missing-target.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'metadata.json'
        Set-Content -LiteralPath $testFile -Value 'test'
        $sddl = (Get-Acl -LiteralPath $testFile).GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::Access
        )

        @{
            SchemaVersion = 1
            Records       = @(
                @{
                    Path     = $testFile
                    ItemType = 'File'
                    Sections = 4
                    Sddl     = ''
                }
            )
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath -Encoding utf8
        {
            Restore-NTFSItemSecurityDescriptor -BackupPath $backupPath -Confirm:$false
        } | Should -Throw -ExpectedMessage '*invalid security descriptor record*'

        @{
            SchemaVersion = 1
            Records       = @(
                @{
                    Path     = $missingFile
                    ItemType = 'File'
                    Sections = 4
                    Sddl     = $sddl
                }
            )
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath -Encoding utf8
        {
            Restore-NTFSItemSecurityDescriptor -BackupPath $backupPath -Confirm:$false
        } | Should -Throw

        @{
            SchemaVersion = 1
            Records       = @(
                @{
                    Path     = $testFile
                    ItemType = 'Directory'
                    Sections = 4
                    Sddl     = $sddl
                }
            )
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath -Encoding utf8
        {
            Restore-NTFSItemSecurityDescriptor -BackupPath $backupPath -Confirm:$false
        } | Should -Throw -ExpectedMessage '*does not match*'

        $duplicateRecord = @{
            Path     = $testFile
            ItemType = 'File'
            Sections = 4
            Sddl     = $sddl
        }
        @{
            SchemaVersion = 1
            Records       = @($duplicateRecord, $duplicateRecord)
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath -Encoding utf8
        {
            Restore-NTFSItemSecurityDescriptor -BackupPath $backupPath -Confirm:$false
        } | Should -Throw -ExpectedMessage '*duplicate records*'
    }
}
