BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'NTFS array-target command contract' -Tag 'Unit', 'WindowsOnly' {
    It 'Should expose ThrottleLimit on <Name>' -ForEach @(
        @{ Name = 'Add-NTFSAccessRule' }
        @{ Name = 'Add-NTFSAuditRule' }
        @{ Name = 'Backup-NTFSItemSecurityDescriptor' }
        @{ Name = 'Clear-NTFSAccessRule' }
        @{ Name = 'Clear-NTFSAuditRule' }
        @{ Name = 'Copy-NTFSItemSecurityDescriptor' }
        @{ Name = 'Disable-NTFSItemInheritance' }
        @{ Name = 'Enable-NTFSItemInheritance' }
        @{ Name = 'Get-NTFSAccessRule' }
        @{ Name = 'Get-NTFSAuditRule' }
        @{ Name = 'Get-NTFSItemEffectiveAccess' }
        @{ Name = 'Get-NTFSItemInheritance' }
        @{ Name = 'Get-NTFSItemOwner' }
        @{ Name = 'Get-NTFSItemSecurityDescriptor' }
        @{ Name = 'Remove-NTFSAccessRule' }
        @{ Name = 'Remove-NTFSAuditRule' }
        @{ Name = 'Set-NTFSAccessRule' }
        @{ Name = 'Set-NTFSAuditRule' }
        @{ Name = 'Set-NTFSItemOwner' }
        @{ Name = 'Test-NTFSItemAcl' }
    ) {
        (Get-Command -Name $Name -Module WindowsAccessControl).
            Parameters.ContainsKey('ThrottleLimit') | Should -BeTrue
    }
}
