BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'Test-NTFSPrivilege' -Tag 'Integration', 'WindowsOnly' {
    It 'Should report the enabled state of a process token privilege' {
        Test-NTFSPrivilege -Name 'SeChangeNotifyPrivilege' | Should -BeOfType ([bool])
    }
}