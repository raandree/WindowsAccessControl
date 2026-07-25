BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Remove-NTFSAuditRule' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:testFile = Join-Path -Path $TestDrive -ChildPath 'remove-audit.txt'
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

    It 'Should remove an exact audit rule received through the pipeline' {
        Get-NTFSAuditRule -LiteralPath $script:testFile -ExcludeInherited |
            Remove-NTFSAuditRule -Confirm:$false

        @($script:testSecurity.GetAuditRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        )) | Should -BeNullOrEmpty
    }

    It 'Should purge every audit rule for an account without requiring AccessRights' {
        Remove-NTFSAuditRule -LiteralPath $script:testFile `
            -Account 'S-1-1-0' `
            -RemovalMode All `
            -Confirm:$false

        @($script:testSecurity.GetAuditRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        )) | Should -BeNullOrEmpty
    }

    It 'Should subtract only the requested audit rights in Rights mode' {
        $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        $script:testSecurity = [System.Security.AccessControl.FileSecurity]::new()
        $rule = [System.Security.AccessControl.FileSystemAuditRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
            [System.Security.AccessControl.AuditFlags]::Failure
        )
        $script:testSecurity.AddAuditRule($rule)

        Remove-NTFSAuditRule -LiteralPath $script:testFile `
            -Account 'S-1-1-0' `
            -AccessRights ExecuteFile `
            -AuditFlags Failure `
            -RemovalMode Rights `
            -Confirm:$false

        $result = @($script:testSecurity.GetAuditRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        ))
        $result | Should -HaveCount 1
        [int]($result[0].FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile) |
            Should -Be 0
        ($result[0].FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read) |
            Should -Be ([System.Security.AccessControl.FileSystemRights]::Read)
    }

    It 'Should return purged audit rules with PassThru' {
        $removed = Remove-NTFSAuditRule -LiteralPath $script:testFile `
            -Account 'S-1-1-0' `
            -RemovalMode All `
            -PassThru `
            -Confirm:$false

        $removed | Should -HaveCount 1
        $removed.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.AuditRule'
        $removed.SID | Should -Be 'S-1-1-0'
    }
}