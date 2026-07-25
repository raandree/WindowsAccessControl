BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'Clear-NTFSAuditRule' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:testFile = Join-Path -Path $TestDrive -ChildPath 'clear-audit.txt'
        Set-Content -LiteralPath $script:testFile -Value 'test'
        $script:testSecurity = [System.Security.AccessControl.FileSecurity]::new()
        foreach ($sidValue in 'S-1-1-0', 'S-1-5-11') {
            $sid = [System.Security.Principal.SecurityIdentifier]::new($sidValue)
            $rule = [System.Security.AccessControl.FileSystemAuditRule]::new(
                $sid,
                [System.Security.AccessControl.FileSystemRights]::Read,
                [System.Security.AccessControl.AuditFlags]::Failure
            )
            $script:testSecurity.AddAuditRule($rule)
        }
        Mock -ModuleName NTFSPermission -CommandName Get-Acl -MockWith { $script:testSecurity }
        Mock -ModuleName NTFSPermission -CommandName Invoke-NTFSSecurityDescriptorPersistence
    }

    It 'Should clear every explicit audit rule' {
        Clear-NTFSAuditRule -LiteralPath $script:testFile -Confirm:$false

        @($script:testSecurity.GetAuditRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        )) | Should -BeNullOrEmpty
    }
}