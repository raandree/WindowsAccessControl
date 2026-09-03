BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
}

Describe 'New-NTFSAuditRule' -Tag 'Unit', 'WindowsOnly' {
    It 'Should create a reusable failure-audit rule' {
        $result = New-NTFSAuditRule -Account 'S-1-1-0' -AccessRights Read -AuditFlags Failure -AppliesTo FilesOnly

        $result.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.AuditRule'
        $result.SID | Should -Be 'S-1-1-0'
        $result.AuditFlags | Should -Be ([System.Security.AccessControl.AuditFlags]::Failure)
        $result.AppliesTo | Should -Be 'FilesOnly'
    }

    It 'Should bind a hexadecimal literal mask the enumeration cannot name' {
        $result = New-NTFSAuditRule -Account 'S-1-1-0' -AccessRights 0x10000000 -AuditFlags Failure

        [int]$result.AccessRights | Should -Be 0x10000000
    }

    It 'Should still refuse an unknown rights name' {
        { New-NTFSAuditRule -Account 'S-1-1-0' -AccessRights 'NotARight' -AuditFlags Failure } |
            Should -Throw -ExpectedMessage '*NotARight*FileSystemRights*'
    }
}