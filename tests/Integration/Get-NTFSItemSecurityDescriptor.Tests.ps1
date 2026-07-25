BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'Get-NTFSItemSecurityDescriptor' -Tag 'Integration', 'WindowsOnly' {
    It 'Should return a portable SDDL descriptor from pipeline input' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'descriptor.txt'
        Set-Content -LiteralPath $testFile -Value 'test'

        $result = Get-Item -LiteralPath $testFile | Get-NTFSItemSecurityDescriptor

        $result.PSObject.TypeNames | Should -Contain 'NTFSPermission.SecurityDescriptor'
        $result.Path | Should -Be (Get-Item -LiteralPath $testFile).FullName
        $result.Sddl | Should -Match 'O:|G:|D:'
        $result.NativeSecurity | Should -BeOfType ([System.Security.AccessControl.FileSecurity])
    }
}