BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'Disable-NTFSPrivilege' -Tag 'Integration', 'WindowsOnly' {
    It 'Should disable a privilege held by the isolated test process' {
        $wasEnabled = Test-NTFSPrivilege -Name 'SeChangeNotifyPrivilege'
        try {
            Disable-NTFSPrivilege -Name 'SeChangeNotifyPrivilege' -Confirm:$false
            Test-NTFSPrivilege -Name 'SeChangeNotifyPrivilege' | Should -BeFalse
        } finally {
            if ($wasEnabled) {
                Enable-NTFSPrivilege -Name 'SeChangeNotifyPrivilege' -Confirm:$false
            }
        }
    }

    It 'Should treat a privilege absent from the token as already disabled' {
        $absentPrivilege = @(
            'SeTcbPrivilege'
            'SeCreateTokenPrivilege'
            'SeTrustedCredManAccessPrivilege'
        ) | Where-Object { -not (Test-NTFSPrivilege -Name $_) } | Select-Object -First 1
        $absentPrivilege | Should -Not -BeNullOrEmpty

        {
            Disable-NTFSPrivilege -Name $absentPrivilege -Confirm:$false
        } | Should -Not -Throw
        Test-NTFSPrivilege -Name $absentPrivilege | Should -BeFalse
    }
}