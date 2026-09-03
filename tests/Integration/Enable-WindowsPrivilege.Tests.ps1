BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
}

Describe 'Enable-WindowsPrivilege' -Tag 'Integration', 'WindowsOnly' {
    It 'Should enable a privilege held by the isolated test process' {
        $wasEnabled = Test-WindowsPrivilege -Name 'SeChangeNotifyPrivilege'
        try {
            Disable-WindowsPrivilege -Name 'SeChangeNotifyPrivilege' -Confirm:$false
            Enable-WindowsPrivilege -Name 'SeChangeNotifyPrivilege' -Confirm:$false
            Test-WindowsPrivilege -Name 'SeChangeNotifyPrivilege' | Should -BeTrue
        } finally {
            if ($wasEnabled) {
                Enable-WindowsPrivilege -Name 'SeChangeNotifyPrivilege' -Confirm:$false
            } else {
                Disable-WindowsPrivilege -Name 'SeChangeNotifyPrivilege' -Confirm:$false
            }
        }
    }
}