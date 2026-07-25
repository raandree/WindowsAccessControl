BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Test-NTFSItemAcl' -Tag 'Integration', 'WindowsOnly' {
    It 'Should report a normal filesystem ACL as canonical' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'canonical.txt'
        Set-Content -LiteralPath $testFile -Value 'test'

        Test-NTFSItemAcl -LiteralPath $testFile -Section Access | Should -BeTrue
        $details = Test-NTFSItemAcl -LiteralPath $testFile -Section Access -PassThru
        $details.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.AclTest'
        $details.AccessRulesCanonical | Should -BeTrue
    }

    It 'Should report an allow-before-deny DACL as noncanonical' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'noncanonical.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $security = [System.Security.AccessControl.FileSecurity]::new()
        $security.SetSecurityDescriptorSddlForm('O:SYG:SYD:(A;;FR;;;WD)(D;;FW;;;WD)')
        Mock -ModuleName WindowsAccessControl -CommandName Get-Acl -MockWith { $security }

        Test-NTFSItemAcl -LiteralPath $testFile -Section Access | Should -BeFalse
        $details = Test-NTFSItemAcl -LiteralPath $testFile -Section Access -PassThru
        $details.IsCanonical | Should -BeFalse
        $details.AccessRulesCanonical | Should -BeFalse
    }
}