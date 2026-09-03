BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
}

Describe 'Disable-NTFSItemInheritance' -Tag 'Integration', 'WindowsOnly' {
    It 'Should preserve inherited access rules as explicit rules by default' {
        $parent = Join-Path -Path $TestDrive -ChildPath 'disable-parent'
        $null = New-Item -Path $parent -ItemType Directory
        $testFile = Join-Path -Path $parent -ChildPath 'child.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $inheritedCount = @(Get-NTFSAccessRule -LiteralPath $testFile -ExcludeExplicit).Count

        Disable-NTFSItemInheritance -LiteralPath $testFile

        (Get-NTFSItemInheritance -LiteralPath $testFile).AccessInheritanceEnabled | Should -BeFalse
        @(Get-NTFSAccessRule -LiteralPath $testFile -ExcludeInherited).Count |
            Should -BeGreaterOrEqual $inheritedCount
        Get-NTFSAccessRule -LiteralPath $testFile -ExcludeExplicit | Should -BeNullOrEmpty
    }
}