BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Remove-NTFSAccessRule' -Tag 'Integration', 'WindowsOnly' {
    It 'Should remove an exact rule received through the pipeline' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'remove.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        Add-NTFSAccessRule -LiteralPath $testFile -Account $script:currentSid -AccessRights Read

        Get-NTFSAccessRule -LiteralPath $testFile -Account $script:currentSid -ExcludeInherited |
            Remove-NTFSAccessRule -Confirm:$false

        Get-NTFSAccessRule -LiteralPath $testFile -Account $script:currentSid -ExcludeInherited |
            Should -BeNullOrEmpty
    }

    It 'Should purge every explicit rule for an account without requiring AccessRights' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'purge-all.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        Add-NTFSAccessRule -LiteralPath $testFile -Account 'S-1-1-0' -AccessRights Read
        Add-NTFSAccessRule -LiteralPath $testFile -Account 'S-1-1-0' -AccessRights Write

        Remove-NTFSAccessRule -LiteralPath $testFile `
            -Account 'S-1-1-0' `
            -RemovalMode All `
            -Confirm:$false

        Get-NTFSAccessRule -LiteralPath $testFile -Account 'S-1-1-0' -ExcludeInherited |
            Should -BeNullOrEmpty
    }

    It 'Should subtract only the requested rights in Rights mode' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'subtract-rights.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        Add-NTFSAccessRule -LiteralPath $testFile `
            -Account $script:currentSid `
            -AccessRights ReadAndExecute

        Remove-NTFSAccessRule -LiteralPath $testFile `
            -Account $script:currentSid `
            -AccessRights ExecuteFile `
            -RemovalMode Rights `
            -Confirm:$false

        $result = Get-NTFSAccessRule -LiteralPath $testFile `
            -Account $script:currentSid `
            -ExcludeInherited
        [int]($result.AccessRights -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile) |
            Should -Be 0
        ($result.AccessRights -band [System.Security.AccessControl.FileSystemRights]::Read) |
            Should -Be ([System.Security.AccessControl.FileSystemRights]::Read)
    }

    It 'Should return purged access rules with PassThru' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'pass-thru.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        Add-NTFSAccessRule -LiteralPath $testFile -Account 'S-1-1-0' -AccessRights Read

        $removed = Remove-NTFSAccessRule -LiteralPath $testFile `
            -Account 'S-1-1-0' `
            -RemovalMode All `
            -PassThru `
            -Confirm:$false

        $removed | Should -HaveCount 1
        $removed.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.AccessRule'
        $removed.SID | Should -Be 'S-1-1-0'
    }
}