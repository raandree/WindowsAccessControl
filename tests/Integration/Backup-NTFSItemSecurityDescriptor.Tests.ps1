BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
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
        $backup.Records | Should -HaveCount 2
        $backup.Records[0].Sddl | Should -Not -BeNullOrEmpty
        $backup.Records[1].Sddl | Should -Not -BeNullOrEmpty
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