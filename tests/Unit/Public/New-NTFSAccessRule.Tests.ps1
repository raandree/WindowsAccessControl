BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'New-NTFSAccessRule' -Tag 'Unit', 'WindowsOnly' {
    It 'Should create a reusable rule with Explorer-style scope' {
        $result = New-NTFSAccessRule -Account 'S-1-1-0' -AccessRights Read -AppliesTo FilesOnly

        $result.PSObject.TypeNames | Should -Contain 'NTFSPermission.AccessRule'
        $result.SID | Should -Be 'S-1-1-0'
        $result.AppliesTo | Should -Be 'FilesOnly'
        $result.InheritanceFlags | Should -Be ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
        $result.PropagationFlags | Should -Be ([System.Security.AccessControl.PropagationFlags]::InheritOnly)
    }
}