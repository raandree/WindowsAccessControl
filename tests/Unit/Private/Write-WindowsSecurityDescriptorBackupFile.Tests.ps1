BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module -Name 'WindowsAccessControl'
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Write-WindowsSecurityDescriptorBackupFile' -Tag 'Unit', 'WindowsOnly' {
    It 'Should atomically create and replace a backup without temporary files' {
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'atomic.json'

        & $script:module {
            param($Path)
            Write-WindowsSecurityDescriptorBackupFile `
                -Path $Path `
                -Content 'first' `
                -DestinationExists $false
        } $backupPath
        Get-Content -LiteralPath $backupPath -Raw | Should -BeExactly 'first'

        & $script:module {
            param($Path)
            Write-WindowsSecurityDescriptorBackupFile `
                -Path $Path `
                -Content 'second' `
                -DestinationExists $true
        } $backupPath
        Get-Content -LiteralPath $backupPath -Raw | Should -BeExactly 'second'
        Get-ChildItem -LiteralPath $TestDrive -Filter '.atomic.json.*.tmp' |
            Should -BeNullOrEmpty
    }

    It 'Should remove the temporary file when replacement fails' {
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'missing.json'

        {
            & $script:module {
                param($Path)
                Write-WindowsSecurityDescriptorBackupFile `
                    -Path $Path `
                    -Content 'not written' `
                    -DestinationExists $true
            } $backupPath
        } | Should -Throw
        $backupPath | Should -Not -Exist
        Get-ChildItem -LiteralPath $TestDrive -Filter '.missing.json.*.tmp' |
            Should -BeNullOrEmpty
    }
}
