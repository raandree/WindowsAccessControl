BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
}

Describe 'Backup-NTFSItemSecurityDescriptor' -Tag 'Integration', 'WindowsOnly' {
    It 'Should write a versioned JSON backup for every pipeline item' {
        $first = Join-Path -Path $TestDrive -ChildPath 'first.txt'
        $second = Join-Path -Path $TestDrive -ChildPath 'second.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'permissions.json'
        Set-Content -LiteralPath $first -Value 'first'
        Set-Content -LiteralPath $second -Value 'second'

        Get-Item -LiteralPath $first, $second |
            Backup-NTFSItemSecurityDescriptor -DestinationPath $backupPath

        $backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
        $backup.SchemaVersion | Should -Be 1
        $backup.Format | Should -Be 'WindowsAccessControl.SecurityDescriptorBackup'
        $backup.Records | Should -HaveCount 2
        $backup.Records[0].ObjectFamily | Should -Be 'FileSystem'
        $backup.Records[0].Sections | Should -Be 7
        $backup.Records[0].Integrity.Algorithm | Should -Be 'SHA256'
        $backup.Records[0].Integrity.Digest | Should -Match '^[0-9A-F]{64}$'
        $backup.Records[0].Sddl | Should -Not -BeNullOrEmpty
        $backup.Records[1].Sddl | Should -Not -BeNullOrEmpty
    }

    It 'Should read a deduplicated batch and write one backup envelope' {
        $first = Join-Path -Path $TestDrive -ChildPath 'batch-first.txt'
        $second = Join-Path -Path $TestDrive -ChildPath 'batch-second.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'batch-permissions.json'
        Set-Content -LiteralPath $first -Value 'first'
        Set-Content -LiteralPath $second -Value 'second'
        $wildcard = Join-Path -Path $TestDrive -ChildPath 'batch-*.txt'
        $before = Get-WindowsAccessControlMetric `
            -CommandName 'Backup-NTFSItemSecurityDescriptor' `
            -ObjectFamily 'FileSystem'
        $beforeOperations = if ($before) { $before.OperationCount } else { 0 }
        $beforeTargets = if ($before) { $before.TargetCount } else { 0 }
        $beforeSuccesses = if ($before) { $before.SuccessCount } else { 0 }

        $records = @(Backup-NTFSItemSecurityDescriptor `
            -Path @($first, $wildcard) `
            -DestinationPath $backupPath `
            -ThrottleLimit 2 `
            -PassThru)
        $backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
        $after = Get-WindowsAccessControlMetric `
            -CommandName 'Backup-NTFSItemSecurityDescriptor' `
            -ObjectFamily 'FileSystem'

        $records | Should -HaveCount 2
        $backup.Records | Should -HaveCount 2
        @($backup.Records.CanonicalTarget | Sort-Object -Unique) | Should -HaveCount 2
        $after.OperationCount - $beforeOperations | Should -Be 1
        $after.TargetCount - $beforeTargets | Should -Be 2
        $after.SuccessCount - $beforeSuccesses | Should -Be 2
        $after.FailureCount | Should -Be 0
    }

    It 'Should refuse to overwrite an existing backup without Force' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'no-clobber.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'existing.json'
        Set-Content -LiteralPath $testFile -Value 'test'
        Set-Content -LiteralPath $backupPath -Value 'existing backup'

        {
            Backup-NTFSItemSecurityDescriptor `
                -LiteralPath $testFile `
                -DestinationPath $backupPath
        } | Should -Throw -ExpectedMessage '*already exists*'
        Get-Content -LiteralPath $backupPath -Raw | Should -Match '^existing backup'
    }

    It 'Should overwrite an existing backup only when Force is used' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'force.txt'
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'force.json'
        Set-Content -LiteralPath $testFile -Value 'test'
        Set-Content -LiteralPath $backupPath -Value 'existing backup'

        Backup-NTFSItemSecurityDescriptor `
            -LiteralPath $testFile `
            -DestinationPath $backupPath `
            -Force

        (Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json).SchemaVersion |
            Should -Be 1
    }
}
