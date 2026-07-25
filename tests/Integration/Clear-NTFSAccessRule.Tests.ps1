BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'Clear-NTFSAccessRule' -Tag 'Integration', 'WindowsOnly' {
    It 'Should remove every explicit rule without removing inherited rules' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'clear.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        Add-NTFSAccessRule -LiteralPath $testFile -Account $script:currentSid -AccessRights Read
        Add-NTFSAccessRule -LiteralPath $testFile -Account 'S-1-1-0' -AccessRights Read

        Clear-NTFSAccessRule -LiteralPath $testFile -Confirm:$false

        Get-NTFSAccessRule -LiteralPath $testFile -ExcludeInherited | Should -BeNullOrEmpty
        Get-NTFSAccessRule -LiteralPath $testFile -ExcludeExplicit | Should -Not -BeNullOrEmpty
    }
}