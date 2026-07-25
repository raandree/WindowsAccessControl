BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'Enable-NTFSItemInheritance' -Tag 'Integration', 'WindowsOnly' {
    It 'Should re-enable access-rule inheritance through pipeline input' {
        $parent = Join-Path -Path $TestDrive -ChildPath 'enable-parent'
        $null = New-Item -Path $parent -ItemType Directory
        $testFile = Join-Path -Path $parent -ChildPath 'child.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        Disable-NTFSItemInheritance -LiteralPath $testFile

        Get-Item -LiteralPath $testFile | Enable-NTFSItemInheritance

        (Get-NTFSItemInheritance -LiteralPath $testFile).AccessInheritanceEnabled | Should -BeTrue
    }
}