BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'Add-NTFSAuditRule' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:testFile = Join-Path -Path $TestDrive -ChildPath 'add-audit.txt'
        Set-Content -LiteralPath $script:testFile -Value 'test'
        $script:testSecurity = [System.Security.AccessControl.FileSecurity]::new()
        Mock -ModuleName NTFSPermission -CommandName Get-Acl -MockWith { $script:testSecurity }
        Mock -ModuleName NTFSPermission -CommandName Invoke-NTFSSecurityDescriptorPersistence
    }

    It 'Should add an audit rule and persist the changed descriptor' {
        $result = Get-Item -LiteralPath $script:testFile |
            Add-NTFSAuditRule -Account 'S-1-1-0' -AccessRights Read -AuditFlags Failure -PassThru

        $rules = @($script:testSecurity.GetAuditRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        ))
        $rules | Should -HaveCount 1
        $result.AuditFlags | Should -Be ([System.Security.AccessControl.AuditFlags]::Failure)
        Should -Invoke -ModuleName NTFSPermission -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 1 -Exactly
    }

    It 'Should add audit rules for multiple accounts with one descriptor write' {
        $accounts = @('S-1-1-0', 'S-1-5-32-545')
        $addParameters = @{
            LiteralPath  = $script:testFile
            Account      = $accounts
            AccessRights = 'Read'
            AuditFlags   = 'Failure'
            PassThru     = $true
        }

        $result = @(Add-NTFSAuditRule @addParameters)
        $rules = @($script:testSecurity.GetAuditRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        ))

        $result | Should -HaveCount 2
        $rules | Should -HaveCount 2
        $invokeParameters = @{
            ModuleName  = 'NTFSPermission'
            CommandName = 'Invoke-NTFSSecurityDescriptorPersistence'
            Times       = 1
            Exactly     = $true
        }
        Should -Invoke @invokeParameters
    }

    It 'Should add one audit rule for duplicate account inputs' {
        $addParameters = @{
            LiteralPath  = $script:testFile
            Account      = @('S-1-1-0', 'S-1-1-0')
            AccessRights = 'Read'
            AuditFlags   = 'Failure'
            PassThru     = $true
        }

        $result = @(Add-NTFSAuditRule @addParameters)
        $rules = @($script:testSecurity.GetAuditRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        ))

        $result | Should -HaveCount 1
        $rules | Should -HaveCount 1
    }
}
