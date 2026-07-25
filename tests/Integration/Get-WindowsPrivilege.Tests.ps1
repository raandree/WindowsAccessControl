# Read-only process-token privilege inventory (FR-14, NFR-9, ADR 0007).
BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Get-WindowsPrivilege' -Tag 'Integration', 'WindowsOnly' {
    It 'Should list structured privileges held by the current process token' {
        $privileges = @(Get-WindowsPrivilege)
        $changeNotify = $privileges | Where-Object Name -eq 'SeChangeNotifyPrivilege'

        $privileges | Should -Not -BeNullOrEmpty
        $changeNotify | Should -Not -BeNullOrEmpty
        $changeNotify.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.Privilege'
        $changeNotify.Enabled | Should -BeOfType ([bool])
        $changeNotify.EnabledByDefault | Should -BeOfType ([bool])
    }
}
