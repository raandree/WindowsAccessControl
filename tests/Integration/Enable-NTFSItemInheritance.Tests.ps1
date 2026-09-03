# Access and audit inheritance contract (FR-8, NFR-3).
BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
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

    It 'Should remove explicit access rules when requested' {
        $parent = Join-Path -Path $TestDrive -ChildPath 'remove-explicit-parent'
        $null = New-Item -Path $parent -ItemType Directory
        $testFile = Join-Path -Path $parent -ChildPath 'child.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $orphanedSid = 'S-1-5-21-4242424242-4242424242-4242424242-4242'
        Add-NTFSAccessRule -LiteralPath $testFile -Account $orphanedSid -AccessRights Read
        Disable-NTFSItemInheritance -LiteralPath $testFile

        Enable-NTFSItemInheritance -LiteralPath $testFile -RemoveExplicitRules

        (Get-NTFSItemInheritance -LiteralPath $testFile).AccessInheritanceEnabled | Should -BeTrue
        Get-NTFSAccessRule -LiteralPath $testFile -ExcludeInherited | Should -BeNullOrEmpty
    }
}
