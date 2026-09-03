BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
}

Describe 'Set-NTFSItemSecurityDescriptor' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:testFile = Join-Path -Path $TestDrive -ChildPath 'descriptor.txt'
        Set-Content -LiteralPath $script:testFile -Value 'test'

        $security = [System.Security.AccessControl.FileSecurity]::new()
        $security.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                [System.Security.AccessControl.FileSystemRights]::Read,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        )

        $script:descriptor = [pscustomobject]@{
            Path                 = $script:testFile
            ItemType             = 'File'
            Sections             = [System.Security.AccessControl.AccessControlSections]::Access
            Sddl                 = $security.GetSecurityDescriptorSddlForm(
                [System.Security.AccessControl.AccessControlSections]::Access
            )
            AccessRulesProtected = $false
            AuditRulesProtected  = $false
            AccessRulesCanonical = $false
            AuditRulesCanonical  = $false
            ConcurrencyToken     = 'READ-TIME-TOKEN'
            NativeSecurity       = $security
        }
        $script:descriptor.PSObject.TypeNames.Insert(
            0,
            'WindowsAccessControl.SecurityDescriptor'
        )

        Mock -ModuleName WindowsAccessControl -CommandName Invoke-NTFSSecurityDescriptorPersistence
    }

    It 'Should persist the descriptor exactly once' {
        $script:descriptor | Set-NTFSItemSecurityDescriptor

        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 1 -Exactly
    }

    It 'Should persist the descriptor selected sections' {
        $script:descriptor | Set-NTFSItemSecurityDescriptor

        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 1 -Exactly `
            -ParameterFilter {
                $Sections -eq [System.Security.AccessControl.AccessControlSections]::Access
            }
    }

    It 'Should persist ACL protection together with the selected sections' {
        $script:descriptor | Set-NTFSItemSecurityDescriptor

        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 1 -Exactly `
            -ParameterFilter { $ProtectionSection -eq 'Access' }
    }

    It 'Should not persist under WhatIf' {
        $script:descriptor | Set-NTFSItemSecurityDescriptor -WhatIf

        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should reject input that is not a security descriptor object' {
        { [pscustomobject]@{ Path = $script:testFile } | Set-NTFSItemSecurityDescriptor -ErrorAction Stop } |
            Should -Throw
    }

    It 'Should refresh the concurrency token on a pass-through descriptor' {
        $result = $script:descriptor | Set-NTFSItemSecurityDescriptor -PassThru

        $result.ConcurrencyToken | Should -Not -BeExactly 'READ-TIME-TOKEN'
        $result.ConcurrencyToken | Should -Match '^[0-9A-F]{64}$'
    }
}
