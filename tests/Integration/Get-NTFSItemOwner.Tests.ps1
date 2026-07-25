BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Get-NTFSItemOwner' -Tag 'Integration', 'WindowsOnly' {
    It 'Should return the owner as both an account and SID' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'owner.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $expectedSid = (Get-Acl -LiteralPath $testFile).
            GetOwner([System.Security.Principal.SecurityIdentifier]).Value

        $result = Get-Item -LiteralPath $testFile | Get-NTFSItemOwner

        $result.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.Owner'
        $result.Path | Should -Be (Get-Item -LiteralPath $testFile).FullName
        $result.SID | Should -Be $expectedSid
        $result.Account | Should -Not -BeNullOrEmpty
    }
}