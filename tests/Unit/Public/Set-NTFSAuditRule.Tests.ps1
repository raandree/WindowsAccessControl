BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Set-NTFSAuditRule' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:testFile = Join-Path -Path $TestDrive -ChildPath 'set-audit.txt'
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
        Mock -ModuleName WindowsAccessControl -CommandName Invoke-NTFSSecurityDescriptorPersistence
    }

    It 'Should bind a hexadecimal literal mask the enumeration cannot name' {
        # A hexadecimal literal is the one form the engine converts before the
        # rights transformation attribute runs. The same value written as a
        # variable or a decimal literal always bound, which is why this defect
        # survived the tests that already covered unnameable masks.
        {
            Set-NTFSAuditRule `
                -LiteralPath $script:testFile `
                -Account 'S-1-1-0' `
                -AccessRights 0x10000000 `
                -AuditFlags Failure
        } | Should -Not -Throw
    }

    It 'Should still refuse an unknown rights name' {
        {
            Set-NTFSAuditRule `
                -LiteralPath $script:testFile `
                -Account 'S-1-1-0' `
                -AccessRights 'NotARight' `
                -AuditFlags Failure
        } | Should -Throw -ExpectedMessage '*NotARight*FileSystemRights*'
    }

    It 'Should replace audit rules for the same identity and audit flags' {
        Set-NTFSAuditRule -LiteralPath $script:testFile -Account 'S-1-1-0' -AccessRights Write -AuditFlags Failure

        $rules = @($script:testSecurity.GetAuditRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        ))
        $rules | Should -HaveCount 1
        [int]($rules[0].FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadData) |
            Should -Be 0
        ($rules[0].FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::WriteData) |
            Should -Be ([System.Security.AccessControl.FileSystemRights]::WriteData)
    }
}