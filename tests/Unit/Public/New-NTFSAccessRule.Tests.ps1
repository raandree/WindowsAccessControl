BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
}

Describe 'New-NTFSAccessRule' -Tag 'Unit', 'WindowsOnly' {
    It 'Should create a reusable rule with Explorer-style scope' {
        $result = New-NTFSAccessRule -Account 'S-1-1-0' -AccessRights Read -AppliesTo FilesOnly

        $result.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.AccessRule'
        $result.SID | Should -Be 'S-1-1-0'
        $result.AppliesTo | Should -Be 'FilesOnly'
        $result.InheritanceFlags | Should -Be ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
        $result.PropagationFlags | Should -Be ([System.Security.AccessControl.PropagationFlags]::InheritOnly)
    }

    It 'Should bind a hexadecimal literal mask the enumeration cannot name' {
        # A hexadecimal literal is the one form the engine converts before the
        # rights transformation attribute runs. The same value written as a
        # variable or a decimal literal always bound, which is why this defect
        # survived the tests that already covered unnameable masks.
        $result = New-NTFSAccessRule -Account 'S-1-1-0' -AccessRights 0x10000000

        [int]$result.AccessRights | Should -Be 0x10000000
    }

    It 'Should still refuse an unknown rights name' {
        { New-NTFSAccessRule -Account 'S-1-1-0' -AccessRights 'NotARight' } |
            Should -Throw -ExpectedMessage '*NotARight*FileSystemRights*'
    }
}