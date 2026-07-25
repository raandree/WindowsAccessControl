BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'Enable-NTFSPrivilege' -Tag 'Integration', 'WindowsOnly' {
    It 'Should enable a privilege held by the isolated test process' {
        $wasEnabled = Test-NTFSPrivilege -Name 'SeChangeNotifyPrivilege'
        try {
            Disable-NTFSPrivilege -Name 'SeChangeNotifyPrivilege' -Confirm:$false
            Enable-NTFSPrivilege -Name 'SeChangeNotifyPrivilege' -Confirm:$false
            Test-NTFSPrivilege -Name 'SeChangeNotifyPrivilege' | Should -BeTrue
        } finally {
            if ($wasEnabled) {
                Enable-NTFSPrivilege -Name 'SeChangeNotifyPrivilege' -Confirm:$false
            } else {
                Disable-NTFSPrivilege -Name 'SeChangeNotifyPrivilege' -Confirm:$false
            }
        }
    }
}