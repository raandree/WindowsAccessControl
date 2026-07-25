BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'Get-NTFSItemInheritance' -Tag 'Integration', 'WindowsOnly' {
    It 'Should report that a new child file inherits access rules' {
        $parent = Join-Path -Path $TestDrive -ChildPath 'inheritance-parent'
        $null = New-Item -Path $parent -ItemType Directory
        $testFile = Join-Path -Path $parent -ChildPath 'child.txt'
        Set-Content -LiteralPath $testFile -Value 'test'

        $result = Get-NTFSItemInheritance -LiteralPath $testFile

        $result.PSObject.TypeNames | Should -Contain 'NTFSPermission.Inheritance'
        $result.AccessInheritanceEnabled | Should -BeTrue
        $result.AccessRulesProtected | Should -BeFalse
    }
}