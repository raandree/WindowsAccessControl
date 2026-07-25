BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'Set-NTFSAccessRule' -Tag 'Integration', 'WindowsOnly' {
    It 'Should replace access rules for the same identity and qualifier' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'replace.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        Add-NTFSAccessRule -LiteralPath $testFile -Account $script:currentSid -AccessRights Read

        Set-NTFSAccessRule -LiteralPath $testFile -Account $script:currentSid -AccessRights Write

        $result = Get-NTFSAccessRule -LiteralPath $testFile -Account $script:currentSid -ExcludeInherited
        $result | Should -HaveCount 1
        ($result.AccessRights -band [System.Security.AccessControl.FileSystemRights]::WriteData) |
            Should -Be ([System.Security.AccessControl.FileSystemRights]::WriteData)
        [int]($result.AccessRights -band [System.Security.AccessControl.FileSystemRights]::ReadData) |
            Should -Be 0
    }
}