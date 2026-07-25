BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Get-NTFSAuditRule' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:testFile = Join-Path -Path $TestDrive -ChildPath 'get-audit.txt'
        Set-Content -LiteralPath $script:testFile -Value 'test'
        $script:testSecurity = [System.Security.AccessControl.FileSecurity]::new()
        $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        $rule = [System.Security.AccessControl.FileSystemAuditRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::Read,
            [System.Security.AccessControl.AuditFlags]::Failure
        )
        $script:testSecurity.AddAuditRule($rule)
        Mock -ModuleName WindowsAccessControl -CommandName Get-Acl -MockWith { $script:testSecurity }
    }

    It 'Should return filtered explicit audit rules' {
        $result = Get-NTFSAuditRule -LiteralPath $script:testFile -Account 'S-1-1-0' -ExcludeInherited

        $result | Should -HaveCount 1
        $result.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.AuditRule'
        $result.SID | Should -Be 'S-1-1-0'
        $result.AuditFlags | Should -Be ([System.Security.AccessControl.AuditFlags]::Failure)
    }

    It 'Should surface a missing SeSecurityPrivilege error' {
        Mock -ModuleName WindowsAccessControl -CommandName Get-Acl -MockWith {
            throw [System.Security.AccessControl.PrivilegeNotHeldException]::new(
                'SeSecurityPrivilege'
            )
        }

        {
            Get-NTFSAuditRule -LiteralPath $script:testFile
        } | Should -Throw -ExceptionType ([System.Security.AccessControl.PrivilegeNotHeldException])
    }
}