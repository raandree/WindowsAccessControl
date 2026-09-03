BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
}

Describe 'Get-NTFSItemSecurityDescriptor' -Tag 'Integration', 'WindowsOnly' {
    It 'Should return a portable SDDL descriptor from pipeline input' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'descriptor.txt'
        Set-Content -LiteralPath $testFile -Value 'test'

        $result = Get-Item -LiteralPath $testFile | Get-NTFSItemSecurityDescriptor

        $result.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.SecurityDescriptor'
        $result.Path | Should -Be (Get-Item -LiteralPath $testFile).FullName
        $result.Sddl | Should -Match 'O:|G:|D:'
        $result.NativeSecurity | Should -BeOfType ([System.Security.AccessControl.FileSecurity])
    }

    It 'Should keep inherited DACL ACEs marked inherited when the audit section is selected' {
        # NFR-7: the audit section needs SeSecurityPrivilege in the token.
        if (-not (@(Get-WindowsPrivilege).Name -contains 'SeSecurityPrivilege')) {
            Set-ItResult -Skipped -Because (
                'The process token does not contain SeSecurityPrivilege, which the audit section requires.'
            )
            return
        }

        # The file must inherit without any prior descriptor write, because a
        # write sets DiscretionaryAclAutoInherited and Windows then reports the
        # inherited ACEs correctly even when the SACL is requested.
        $testFile = Join-Path -Path $TestDrive -ChildPath 'inherited-dacl.txt'
        Set-Content -LiteralPath $testFile -Value 'test'

        $accessDacl = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            (Get-NTFSItemSecurityDescriptor -LiteralPath $testFile -Sections Access).Sddl
        ).GetSddlForm('Access')
        $allDacl = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            (Get-NTFSItemSecurityDescriptor -LiteralPath $testFile -Sections All).Sddl
        ).GetSddlForm('Access')

        # Guard against a vacuous comparison if the fixture ever stops inheriting.
        $accessDacl | Should -Match '\(A;[A-Z]*ID[A-Z]*;'
        $allDacl | Should -BeExactly $accessDacl
    }
}