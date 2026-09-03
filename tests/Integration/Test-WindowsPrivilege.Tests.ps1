BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
}

Describe 'Test-WindowsPrivilege' -Tag 'Integration', 'WindowsOnly' {
    It 'Should report the enabled state of a process token privilege' {
        Test-WindowsPrivilege -Name 'SeChangeNotifyPrivilege' | Should -BeOfType ([bool])
    }
}