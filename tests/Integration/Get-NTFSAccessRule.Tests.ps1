BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Get-NTFSAccessRule' -Tag 'Integration', 'WindowsOnly' {
    It 'Should filter explicit access rules by SID' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'filter.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        Add-NTFSAccessRule -LiteralPath $testFile -Account $script:currentSid -AccessRights Read

        $result = Get-NTFSAccessRule -LiteralPath $testFile -Account $script:currentSid -ExcludeInherited

        $result | Should -HaveCount 1
        $result.SID | Should -Be $script:currentSid
        $result.IsInherited | Should -BeFalse
    }
}