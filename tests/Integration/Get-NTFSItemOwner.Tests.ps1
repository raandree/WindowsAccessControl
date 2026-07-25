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

Describe 'Get-NTFSItemOwner' -Tag 'Integration', 'WindowsOnly' {
    It 'Should return the owner as both an account and SID' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'owner.txt'
        Set-Content -LiteralPath $testFile -Value 'test'

        $result = Get-Item -LiteralPath $testFile | Get-NTFSItemOwner

        $result.PSObject.TypeNames | Should -Contain 'NTFSPermission.Owner'
        $result.Path | Should -Be (Get-Item -LiteralPath $testFile).FullName
        $result.SID | Should -Be $script:currentSid
        $result.Account | Should -Not -BeNullOrEmpty
    }
}