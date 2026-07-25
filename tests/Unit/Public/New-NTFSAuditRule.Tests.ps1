BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'New-NTFSAuditRule' -Tag 'Unit', 'WindowsOnly' {
    It 'Should create a reusable failure-audit rule' {
        $result = New-NTFSAuditRule -Account 'S-1-1-0' -AccessRights Read -AuditFlags Failure -AppliesTo FilesOnly

        $result.PSObject.TypeNames | Should -Contain 'NTFSPermission.AuditRule'
        $result.SID | Should -Be 'S-1-1-0'
        $result.AuditFlags | Should -Be ([System.Security.AccessControl.AuditFlags]::Failure)
        $result.AppliesTo | Should -Be 'FilesOnly'
    }
}