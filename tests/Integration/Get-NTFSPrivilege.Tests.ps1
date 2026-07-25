BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'Get-NTFSPrivilege' -Tag 'Integration', 'WindowsOnly' {
    It 'Should list structured privileges held by the current process token' {
        $privileges = @(Get-NTFSPrivilege)
        $changeNotify = $privileges | Where-Object Name -eq 'SeChangeNotifyPrivilege'

        $privileges | Should -Not -BeNullOrEmpty
        $changeNotify | Should -Not -BeNullOrEmpty
        $changeNotify.PSObject.TypeNames | Should -Contain 'NTFSPermission.Privilege'
        $changeNotify.Enabled | Should -BeOfType ([bool])
        $changeNotify.EnabledByDefault | Should -BeOfType ([bool])
    }
}
