BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Copy-NTFSItemSecurityDescriptor' -Tag 'Integration', 'WindowsOnly' {
    It 'Should copy only the selected DACL through destination pipeline input' {
        $source = Join-Path -Path $TestDrive -ChildPath 'source.txt'
        $destination = Join-Path -Path $TestDrive -ChildPath 'destination.txt'
        Set-Content -LiteralPath $source -Value 'source'
        Set-Content -LiteralPath $destination -Value 'destination'
        Add-NTFSAccessRule -LiteralPath $source -Account 'S-1-1-0' -AccessRights Read

        Get-Item -LiteralPath $destination |
            Copy-NTFSItemSecurityDescriptor -SourceLiteralPath $source -Sections Access -Confirm:$false

        $result = Get-NTFSAccessRule -LiteralPath $destination -Account 'S-1-1-0' -ExcludeInherited
        $result | Should -HaveCount 1
        ($result.AccessRights -band [System.Security.AccessControl.FileSystemRights]::Read) |
            Should -Be ([System.Security.AccessControl.FileSystemRights]::Read)
    }
}