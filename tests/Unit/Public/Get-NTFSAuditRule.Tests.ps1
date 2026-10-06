BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
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

    It 'Should not translate or format accounts excluded by the account filter' {
        $excludedRule = [System.Security.AccessControl.FileSystemAuditRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
            [System.Security.AccessControl.FileSystemRights]::Write,
            [System.Security.AccessControl.AuditFlags]::Success
        )
        $script:testSecurity.AddAuditRule($excludedRule)
        Mock -ModuleName WindowsAccessControl -CommandName ConvertTo-NTFSAuditRuleObject -ParameterFilter {
            $Rule.IdentityReference.Value -eq 'S-1-5-18'
        } -MockWith {
            throw 'An excluded account must not be translated or formatted.'
        }

        $parameters = @{
            LiteralPath      = $script:testFile
            Account          = 'S-1-1-0'
            ExcludeInherited = $true
            ThrottleLimit    = 1
            ErrorAction      = 'Stop'
        }
        $result = @(Get-NTFSAuditRule @parameters)

        $result | Should -HaveCount 1
        $result[0].SID | Should -Be 'S-1-1-0'
        Should -Invoke -ModuleName WindowsAccessControl -CommandName ConvertTo-NTFSAuditRuleObject -Times 0 -Exactly
    }

    It 'Should surface a missing SeSecurityPrivilege error' {
        Mock -ModuleName WindowsAccessControl -CommandName Get-Acl -MockWith {
            throw [System.Security.AccessControl.PrivilegeNotHeldException]::new(
                'SeSecurityPrivilege'
            )
        }

        InModuleScope WindowsAccessControl -Parameters @{
            TestFile = $script:testFile
        } {
            $script:WindowsAccessControlBatchWorker.Value = $true
            try {
                {
                    Get-NTFSAuditRule -LiteralPath $TestFile
                } | Should -Throw -ExceptionType (
                    [System.Security.AccessControl.PrivilegeNotHeldException]
                )
            } finally {
                $script:WindowsAccessControlBatchWorker.Value = $false
            }
        }
    }
}
