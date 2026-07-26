BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module -Name WindowsAccessControl
}

AfterAll {
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'NTFS AppliesTo conversion' -Tag 'Unit', 'WindowsOnly' {
    It 'Should round-trip <AppliesTo> through inheritance and propagation flags' -ForEach @(
        @{ AppliesTo = 'ThisFolderOnly' }
        @{ AppliesTo = 'ThisFolderSubfoldersAndFiles' }
        @{ AppliesTo = 'ThisFolderAndSubfolders' }
        @{ AppliesTo = 'ThisFolderAndFiles' }
        @{ AppliesTo = 'SubfoldersAndFilesOnly' }
        @{ AppliesTo = 'SubfoldersOnly' }
        @{ AppliesTo = 'FilesOnly' }
        @{ AppliesTo = 'ThisFolderSubfoldersAndFilesOneLevel' }
        @{ AppliesTo = 'ThisFolderAndSubfoldersOneLevel' }
        @{ AppliesTo = 'ThisFolderAndFilesOneLevel' }
        @{ AppliesTo = 'SubfoldersAndFilesOnlyOneLevel' }
        @{ AppliesTo = 'SubfoldersOnlyOneLevel' }
        @{ AppliesTo = 'FilesOnlyOneLevel' }
    ) {
        $label = & $script:module {
            param($AppliesTo)
            $flags = ConvertFrom-NTFSAppliesTo -AppliesTo $AppliesTo
            ConvertTo-NTFSAppliesTo `
                -InheritanceFlags $flags.InheritanceFlags `
                -PropagationFlags $flags.PropagationFlags
        } $AppliesTo

        $label | Should -Be $AppliesTo
    }

    It 'Should map <AppliesTo> to inherit-only, no-propagate one level' -ForEach @(
        @{ AppliesTo = 'SubfoldersAndFilesOnlyOneLevel'; InheritanceInt = 3 }
        @{ AppliesTo = 'SubfoldersOnlyOneLevel'; InheritanceInt = 1 }
        @{ AppliesTo = 'FilesOnlyOneLevel'; InheritanceInt = 2 }
    ) {
        $flags = & $script:module {
            param($AppliesTo)
            ConvertFrom-NTFSAppliesTo -AppliesTo $AppliesTo
        } $AppliesTo

        [int]$flags.InheritanceFlags | Should -Be $InheritanceInt
        [int]$flags.PropagationFlags | Should -Be 3
    }
}
