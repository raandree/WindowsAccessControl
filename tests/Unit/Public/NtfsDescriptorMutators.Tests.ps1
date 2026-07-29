BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop

    function Get-TestSecurityDescriptor {
        param(
            [System.Security.AccessControl.AccessControlSections]$Sections =
                [System.Security.AccessControl.AccessControlSections]::Access,

            [string]$ItemType = 'File'
        )

        $descriptor = [pscustomobject]@{
            Path                 = 'C:\Data\descriptor.txt'
            ItemType             = $ItemType
            Sections             = $Sections
            Sddl                 = ''
            AccessRulesProtected = $false
            AuditRulesProtected  = $false
            AccessRulesCanonical = $false
            AuditRulesCanonical  = $false
            ConcurrencyToken     = 'READ-TIME-TOKEN'
            NativeSecurity       = [System.Security.AccessControl.FileSecurity]::new()
        }
        $descriptor.PSObject.TypeNames.Insert(
            0,
            'WindowsAccessControl.SecurityDescriptor'
        )
        $descriptor
    }

    function Get-TestExplicitAccessRule {
        param([psobject]$Descriptor)

        @($Descriptor.NativeSecurity.GetAccessRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        ))
    }

    function Get-TestExplicitAuditRule {
        param([psobject]$Descriptor)

        @($Descriptor.NativeSecurity.GetAuditRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        ))
    }
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'NTFS descriptor-aware mutators' -Tag 'Unit', 'WindowsOnly' {
    Context 'Command contract' {
        It 'Should expose a SecurityDescriptor parameter set on <_>' -ForEach @(
            'Add-NTFSAccessRule'
            'Set-NTFSAccessRule'
            'Remove-NTFSAccessRule'
            'Clear-NTFSAccessRule'
            'Add-NTFSAuditRule'
            'Set-NTFSAuditRule'
            'Remove-NTFSAuditRule'
            'Clear-NTFSAuditRule'
            'Set-NTFSItemOwner'
            'Enable-NTFSItemInheritance'
            'Disable-NTFSItemInheritance'
        ) {
            $command = Get-Command -Name $_ -Module WindowsAccessControl -ErrorAction Stop

            $command.Parameters.ContainsKey('SecurityDescriptor') | Should -BeTrue
            $command.ParameterSets.Name | Should -Contain 'SecurityDescriptor'
        }
    }

    Context 'Access rule staging' {
        It 'Should stage an added access rule and return the same descriptor' {
            $descriptor = Get-TestSecurityDescriptor

            $result = $descriptor | Add-NTFSAccessRule -Account 'S-1-1-0' -AccessRights Read

            $result | Should -Be $descriptor
            $rules = Get-TestExplicitAccessRule -Descriptor $descriptor
            $rules | Should -HaveCount 1
            $rules[0].IdentityReference.Value | Should -Be 'S-1-1-0'
        }

        It 'Should refresh the descriptor projection without refreshing its token' {
            $descriptor = Get-TestSecurityDescriptor

            $null = $descriptor | Add-NTFSAccessRule -Account 'S-1-1-0' -AccessRights Read

            $descriptor.Sddl | Should -Match ';WD\)'
            $descriptor.ConcurrencyToken | Should -BeExactly 'READ-TIME-TOKEN'
        }

        It 'Should replace matching access rules in memory' {
            $descriptor = Get-TestSecurityDescriptor
            $null = $descriptor | Add-NTFSAccessRule -Account 'S-1-1-0' -AccessRights Read

            $null = $descriptor | Set-NTFSAccessRule -Account 'S-1-1-0' -AccessRights Write

            $rules = Get-TestExplicitAccessRule -Descriptor $descriptor
            $rules | Should -HaveCount 1
            $rules[0].FileSystemRights.HasFlag(
                [System.Security.AccessControl.FileSystemRights]::Write
            ) | Should -BeTrue
        }

        It 'Should remove an exact access rule in memory' {
            $descriptor = Get-TestSecurityDescriptor
            $null = $descriptor | Add-NTFSAccessRule -Account 'S-1-1-0' -AccessRights Read

            $null = $descriptor | Remove-NTFSAccessRule -Account 'S-1-1-0' -AccessRights Read

            Get-TestExplicitAccessRule -Descriptor $descriptor | Should -BeNullOrEmpty
        }

        It 'Should purge every access rule for an account in memory' {
            $descriptor = Get-TestSecurityDescriptor
            $null = $descriptor | Add-NTFSAccessRule -Account 'S-1-1-0' -AccessRights Read
            $null = $descriptor | Add-NTFSAccessRule `
                -Account 'S-1-1-0' `
                -AccessRights Write `
                -AccessControlType Deny

            $null = $descriptor | Remove-NTFSAccessRule -Account 'S-1-1-0' -RemovalMode All

            Get-TestExplicitAccessRule -Descriptor $descriptor | Should -BeNullOrEmpty
        }

        It 'Should clear every explicit access rule in memory' {
            $descriptor = Get-TestSecurityDescriptor
            $null = $descriptor | Add-NTFSAccessRule -Account 'S-1-1-0' -AccessRights Read
            $null = $descriptor | Add-NTFSAccessRule -Account 'S-1-5-18' -AccessRights FullControl

            $null = $descriptor | Clear-NTFSAccessRule

            Get-TestExplicitAccessRule -Descriptor $descriptor | Should -BeNullOrEmpty
        }
    }

    Context 'Audit rule staging' {
        It 'Should stage an added audit rule in memory' {
            $descriptor = Get-TestSecurityDescriptor -Sections Audit

            $null = $descriptor | Add-NTFSAuditRule `
                -Account 'S-1-1-0' `
                -AccessRights Read `
                -AuditFlags Failure

            $rules = Get-TestExplicitAuditRule -Descriptor $descriptor
            $rules | Should -HaveCount 1
            $rules[0].AuditFlags | Should -Be ([System.Security.AccessControl.AuditFlags]::Failure)
        }

        It 'Should replace matching audit rules in memory' {
            $descriptor = Get-TestSecurityDescriptor -Sections Audit
            $null = $descriptor | Add-NTFSAuditRule `
                -Account 'S-1-1-0' `
                -AccessRights Read `
                -AuditFlags Failure

            $null = $descriptor | Set-NTFSAuditRule `
                -Account 'S-1-1-0' `
                -AccessRights Write `
                -AuditFlags Failure

            $rules = Get-TestExplicitAuditRule -Descriptor $descriptor
            $rules | Should -HaveCount 1
            $rules[0].FileSystemRights.HasFlag(
                [System.Security.AccessControl.FileSystemRights]::Write
            ) | Should -BeTrue
        }

        It 'Should remove an exact audit rule in memory' {
            $descriptor = Get-TestSecurityDescriptor -Sections Audit
            $null = $descriptor | Add-NTFSAuditRule `
                -Account 'S-1-1-0' `
                -AccessRights Read `
                -AuditFlags Failure

            $null = $descriptor | Remove-NTFSAuditRule `
                -Account 'S-1-1-0' `
                -AccessRights Read `
                -AuditFlags Failure

            Get-TestExplicitAuditRule -Descriptor $descriptor | Should -BeNullOrEmpty
        }

        It 'Should clear every explicit audit rule in memory' {
            $descriptor = Get-TestSecurityDescriptor -Sections Audit
            $null = $descriptor | Add-NTFSAuditRule `
                -Account 'S-1-1-0' `
                -AccessRights Read `
                -AuditFlags Success

            $null = $descriptor | Clear-NTFSAuditRule

            Get-TestExplicitAuditRule -Descriptor $descriptor | Should -BeNullOrEmpty
        }
    }

    Context 'Owner and inheritance staging' {
        It 'Should set the owner in memory' {
            $descriptor = Get-TestSecurityDescriptor -Sections Owner

            $null = $descriptor | Set-NTFSItemOwner -Account 'S-1-5-18'

            $descriptor.NativeSecurity.GetOwner(
                [System.Security.Principal.SecurityIdentifier]
            ).Value | Should -Be 'S-1-5-18'
        }

        It 'Should protect the selected ACL in memory' {
            $descriptor = Get-TestSecurityDescriptor

            $null = $descriptor | Disable-NTFSItemInheritance -Section Access

            $descriptor.NativeSecurity.AreAccessRulesProtected | Should -BeTrue
            $descriptor.AccessRulesProtected | Should -BeTrue
        }

        It 'Should unprotect the selected ACL in memory' {
            $descriptor = Get-TestSecurityDescriptor
            $descriptor.NativeSecurity.SetAccessRuleProtection($true, $false)

            $null = $descriptor | Enable-NTFSItemInheritance -Section Access

            $descriptor.NativeSecurity.AreAccessRulesProtected | Should -BeFalse
        }

        It 'Should remove explicit rules while unprotecting in memory' {
            $descriptor = Get-TestSecurityDescriptor
            $null = $descriptor | Add-NTFSAccessRule -Account 'S-1-1-0' -AccessRights Read

            $null = $descriptor | Enable-NTFSItemInheritance `
                -Section Access `
                -RemoveExplicitRules

            Get-TestExplicitAccessRule -Descriptor $descriptor | Should -BeNullOrEmpty
        }
    }

    Context 'Unloaded section rejection' {
        It 'Should reject an access edit when the access section was not loaded' {
            $descriptor = Get-TestSecurityDescriptor -Sections Owner

            {
                $descriptor |
                    Add-NTFSAccessRule -Account 'S-1-1-0' -AccessRights Read -ErrorAction Stop
            } | Should -Throw -ExpectedMessage '*without the Access section*'
        }

        It 'Should reject an audit edit when the audit section was not loaded' {
            $descriptor = Get-TestSecurityDescriptor -Sections Access

            {
                $descriptor | Add-NTFSAuditRule `
                    -Account 'S-1-1-0' `
                    -AccessRights Read `
                    -AuditFlags Success `
                    -ErrorAction Stop
            } | Should -Throw -ExpectedMessage '*without the Audit section*'
        }

        It 'Should reject an owner edit when the owner section was not loaded' {
            $descriptor = Get-TestSecurityDescriptor -Sections Access

            {
                $descriptor | Set-NTFSItemOwner -Account 'S-1-5-18' -ErrorAction Stop
            } | Should -Throw -ExpectedMessage '*without the Owner section*'
        }

        It 'Should reject an inheritance edit when a selected section was not loaded' {
            $descriptor = Get-TestSecurityDescriptor -Sections Access

            {
                $descriptor | Disable-NTFSItemInheritance -Section All -ErrorAction Stop
            } | Should -Throw -ExpectedMessage '*without the Audit section*'
        }
    }
}
