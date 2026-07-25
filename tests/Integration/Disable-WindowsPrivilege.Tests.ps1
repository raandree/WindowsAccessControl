BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Disable-WindowsPrivilege' -Tag 'Integration', 'WindowsOnly' {
    It 'Should disable a privilege held by the isolated test process' {
        $wasEnabled = Test-WindowsPrivilege -Name 'SeChangeNotifyPrivilege'
        try {
            Disable-WindowsPrivilege -Name 'SeChangeNotifyPrivilege' -Confirm:$false
            Test-WindowsPrivilege -Name 'SeChangeNotifyPrivilege' | Should -BeFalse
        } finally {
            if ($wasEnabled) {
                Enable-WindowsPrivilege -Name 'SeChangeNotifyPrivilege' -Confirm:$false
            }
        }
    }

    It 'Should treat a privilege absent from the token as already disabled' {
        $absentPrivilege = @(
            'SeTcbPrivilege'
            'SeCreateTokenPrivilege'
            'SeTrustedCredManAccessPrivilege'
        ) | Where-Object { -not (Test-WindowsPrivilege -Name $_) } | Select-Object -First 1
        $absentPrivilege | Should -Not -BeNullOrEmpty

        {
            Disable-WindowsPrivilege -Name $absentPrivilege -Confirm:$false
        } | Should -Not -Throw
        Test-WindowsPrivilege -Name $absentPrivilege | Should -BeFalse
    }
}