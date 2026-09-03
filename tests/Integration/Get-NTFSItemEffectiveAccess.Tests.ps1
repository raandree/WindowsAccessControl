# Bounded SID-derived Authz effective-access calculation (FR-13).
BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

Describe 'Get-NTFSItemEffectiveAccess' -Tag 'Integration', 'WindowsOnly' {
    It 'Should evaluate current-user access with the Windows Authz API' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'effective-access.txt'
        Set-Content -LiteralPath $testFile -Value 'test'

        $result = Get-Item -LiteralPath $testFile |
            Get-NTFSItemEffectiveAccess -Account $script:currentSid -AccessRights Read

        $result.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.EffectiveAccess'
        $result.SID | Should -Be $script:currentSid
        $result.AccessMask | Should -BeGreaterThan 0
        $result.IsAllowed | Should -BeTrue
        ($result.EffectiveRights -band [System.Security.AccessControl.FileSystemRights]::Read) |
            Should -Be ([System.Security.AccessControl.FileSystemRights]::Read)
    }
}
