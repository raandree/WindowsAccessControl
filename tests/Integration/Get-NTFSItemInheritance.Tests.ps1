BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
}

Describe 'Get-NTFSItemInheritance' -Tag 'Integration', 'WindowsOnly' {
    It 'Should report that a new child file inherits access rules' {
        $parent = Join-Path -Path $TestDrive -ChildPath 'inheritance-parent'
        $null = New-Item -Path $parent -ItemType Directory
        $testFile = Join-Path -Path $parent -ChildPath 'child.txt'
        Set-Content -LiteralPath $testFile -Value 'test'

        $result = Get-NTFSItemInheritance -LiteralPath $testFile

        $result.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.Inheritance'
        $result.AccessInheritanceEnabled | Should -BeTrue
        $result.AccessRulesProtected | Should -BeFalse
    }
}