# Real-item removal of access control entries the rights enum cannot name
# (FR-5, FR-11, FR-28). Nothing in this file mocks Get-Acl: every assertion
# reads the descriptor Windows actually stored.
BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop

    # 0xE0010000: DELETE plus GENERIC_READ, GENERIC_WRITE and GENERIC_EXECUTE.
    $script:genericExecuteWriteReadMask = [uint32]3758161920
    $script:genericAllMask = [uint32]0x10000000
    $script:modifyMask = [uint32]0x1301BF
    $script:authenticatedUsersSid = 'S-1-5-11'
    $script:interactiveSid = 'S-1-5-4'
    $script:orphanedSid = 'S-1-5-21-1111111111-2222222222-3333333333-4444'
    $script:orphanedGenericSid = 'S-1-5-21-1111111111-2222222222-3333333333-4445'
    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

    function script:ConvertTo-SignedAccessMask {
        param(
            [Parameter(Mandatory)]
            [uint32]$Mask
        )

        if ($Mask -gt [int]::MaxValue) {
            return [int]([int64]$Mask - 4294967296L)
        }
        [int]$Mask
    }

    function script:New-GenericAceDirectory {
        param(
            [Parameter(Mandatory)]
            [string]$Name
        )

        # A directory, not a file: canonicalization drops an inherit-only entry
        # from a file descriptor, so the fixture would never reach disk.
        $path = Join-Path -Path $TestDrive -ChildPath $Name
        $null = New-Item -Path $path -ItemType Directory -Force

        $entries = @(
            @{
                Sid        = $script:authenticatedUsersSid
                AccessMask = $script:genericExecuteWriteReadMask
                AceFlags   = 'ContainerInherit, ObjectInherit, InheritOnly'
            }
            @{
                Sid        = $script:interactiveSid
                AccessMask = $script:genericAllMask
                AceFlags   = 'ContainerInherit, ObjectInherit, InheritOnly'
            }
            @{
                Sid        = $script:orphanedSid
                AccessMask = $script:modifyMask
                AceFlags   = 'None'
            }
            @{
                Sid        = $script:orphanedGenericSid
                AccessMask = $script:genericAllMask
                AceFlags   = 'ContainerInherit, ObjectInherit, InheritOnly'
            }
        )

        $security = Get-Acl -LiteralPath $path
        $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            $security.GetSecurityDescriptorBinaryForm(),
            0
        )
        # Explicit entries precede the inherited ones, which keeps the list
        # canonical and keeps the directory reachable after a clear.
        $insertIndex = 0
        foreach ($entry in $entries) {
            $ace = [System.Security.AccessControl.CommonAce]::new(
                [System.Security.AccessControl.AceFlags]$entry.AceFlags,
                [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                (ConvertTo-SignedAccessMask -Mask $entry.AccessMask),
                [System.Security.Principal.SecurityIdentifier]::new($entry.Sid),
                $false,
                $null
            )
            $raw.DiscretionaryAcl.InsertAce($insertIndex, $ace)
            $insertIndex++
        }

        $binaryForm = [byte[]]::new($raw.BinaryLength)
        $raw.GetBinaryForm($binaryForm, 0)
        $security.SetSecurityDescriptorBinaryForm(
            $binaryForm,
            [System.Security.AccessControl.AccessControlSections]::Access
        )
        Set-Acl -LiteralPath $path -AclObject $security -ErrorAction Stop

        $path
    }

    function script:Get-StoredAce {
        param(
            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter()]
            [ValidateSet('Access', 'Audit')]
            [string]$Section = 'Access'
        )

        $security = if ($Section -eq 'Audit') {
            Get-Acl -LiteralPath $Path -Audit -ErrorAction Stop
        } else {
            Get-Acl -LiteralPath $Path -ErrorAction Stop
        }
        $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            $security.GetSecurityDescriptorBinaryForm(),
            0
        )
        if ($Section -eq 'Audit') {
            $acl = $raw.SystemAcl
        } else {
            $acl = $raw.DiscretionaryAcl
        }
        foreach ($ace in $acl) {
            [pscustomobject]@{
                Sid        = $ace.SecurityIdentifier.Value
                AccessMask = [uint32]([int64]$ace.AccessMask -band 0xFFFFFFFFL)
                AceFlags   = $ace.AceFlags
                Qualifier  = $ace.AceQualifier
            }
        }
    }
}

Describe 'NTFS generic-bit and orphaned access control entry reporting' -Tag 'Integration', 'WindowsOnly' {
    BeforeAll {
        $script:reportingPath = New-GenericAceDirectory -Name 'generic-reporting'
    }

    It 'Should store every fixture mask verbatim on disk' {
        $stored = @(Get-StoredAce -Path $script:reportingPath)

        ($stored | Where-Object Sid -EQ $script:authenticatedUsersSid).AccessMask |
            Should -Be $script:genericExecuteWriteReadMask
        ($stored | Where-Object Sid -EQ $script:interactiveSid).AccessMask |
            Should -Be $script:genericAllMask
        ($stored | Where-Object Sid -EQ $script:orphanedSid).AccessMask |
            Should -Be $script:modifyMask
        ($stored | Where-Object Sid -EQ $script:orphanedGenericSid).AccessMask |
            Should -Be $script:genericAllMask
    }

    It 'Should preserve the inherit-only propagation flags of the generic entry' {
        $stored = @(Get-StoredAce -Path $script:reportingPath)
        $entry = $stored | Where-Object Sid -EQ $script:authenticatedUsersSid

        [int]$entry.AceFlags | Should -Be (
            [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
            [int][System.Security.AccessControl.AceFlags]::ObjectInherit -bor
            [int][System.Security.AccessControl.AceFlags]::InheritOnly
        )
    }

    It 'Should report the exact mask and name the generic bits' {
        $rules = @(Get-NTFSAccessRule -LiteralPath $script:reportingPath -ExcludeInherited)

        $genericCombination = $rules | Where-Object SID -EQ $script:authenticatedUsersSid
        $genericCombination.AccessMask | Should -Be $script:genericExecuteWriteReadMask
        $genericCombination.AccessRightsDisplay |
            Should -Be 'Delete, GenericExecute, GenericWrite, GenericRead'
        $genericCombination.AppliesTo | Should -Be 'SubfoldersAndFilesOnly'

        $genericAll = $rules | Where-Object SID -EQ $script:interactiveSid
        $genericAll.AccessMask | Should -Be $script:genericAllMask
        $genericAll.AccessRightsDisplay | Should -Be 'GenericAll'
    }

    It 'Should record that Windows maps generic rights on an effective entry' {
        # An entry that is not inherit-only is mapped through the file system
        # generic mapping when the descriptor is written, so GENERIC_ALL never
        # survives on the item itself.
        $path = Join-Path -Path $TestDrive -ChildPath 'generic-effective'
        $null = New-Item -Path $path -ItemType Directory -Force
        $addParameters = @{
            LiteralPath  = $path
            Account      = $script:currentSid
            AccessRights = $script:genericAllMask
            AppliesTo    = 'ThisFolderOnly'
            Confirm      = $false
        }

        Add-NTFSAccessRule @addParameters

        $stored = @(
            Get-StoredAce -Path $path |
                Where-Object {
                    $_.Sid -eq $script:currentSid -and
                    ([int]$_.AceFlags -band
                        [int][System.Security.AccessControl.AceFlags]::Inherited) -eq 0
                }
        )
        $stored | Should -HaveCount 1
        $stored[0].AccessMask |
            Should -Be ([uint32][int][System.Security.AccessControl.FileSystemRights]::FullControl)
    }

    It 'Should return only unresolvable identifiers with an empty account' {
        $orphans = @(Get-NTFSAccessRule -LiteralPath $script:reportingPath -Orphaned)

        @($orphans.SID) | Should -Be @($script:orphanedSid, $script:orphanedGenericSid)
        foreach ($orphan in $orphans) {
            $orphan.Account | Should -BeNullOrEmpty
            $orphan.IsOrphaned | Should -BeTrue
        }
    }
}

Describe 'NTFS generic-bit and orphaned access control entry removal' -Tag 'Integration', 'WindowsOnly' {
    It 'Should purge every entry for an account without a rights mask' {
        $path = New-GenericAceDirectory -Name 'remove-purge'

        Remove-NTFSAccessRule -LiteralPath $path -Account $script:orphanedGenericSid -RemovalMode All -Confirm:$false

        $stored = @(Get-StoredAce -Path $path)
        @($stored | Where-Object Sid -EQ $script:orphanedGenericSid) | Should -BeNullOrEmpty
        @($stored | Where-Object Sid -EQ $script:orphanedSid) | Should -HaveCount 1
        @($stored | Where-Object Sid -EQ $script:authenticatedUsersSid) | Should -HaveCount 1
    }

    It 'Should remove an exact generic-bit entry from a raw numeric mask' {
        $path = New-GenericAceDirectory -Name 'remove-exact-generic'
        $removeParameters = @{
            LiteralPath  = $path
            Account      = $script:authenticatedUsersSid
            AccessRights = $script:genericExecuteWriteReadMask
            AppliesTo    = 'SubfoldersAndFilesOnly'
            RemovalMode  = 'Exact'
            Confirm      = $false
        }

        Remove-NTFSAccessRule @removeParameters

        $stored = @(Get-StoredAce -Path $path)
        @($stored | Where-Object Sid -EQ $script:authenticatedUsersSid) | Should -BeNullOrEmpty
        ($stored | Where-Object Sid -EQ $script:interactiveSid).AccessMask |
            Should -Be $script:genericAllMask
        ($stored | Where-Object Sid -EQ $script:orphanedSid).AccessMask |
            Should -Be $script:modifyMask
    }
    It 'Should accept the unsigned form of the same mask' {
        $path = New-GenericAceDirectory -Name 'remove-exact-unsigned'
        $removeParameters = @{
            LiteralPath  = $path
            Account      = $script:authenticatedUsersSid
            AccessRights = 3758161920
            AppliesTo    = 'SubfoldersAndFilesOnly'
            RemovalMode  = 'Exact'
            Confirm      = $false
        }

        Remove-NTFSAccessRule @removeParameters

        @(Get-StoredAce -Path $path | Where-Object Sid -EQ $script:authenticatedUsersSid) |
            Should -BeNullOrEmpty
    }

    It 'Should remove an orphaned entry that carries GENERIC_ALL by exact mask' {
        $path = New-GenericAceDirectory -Name 'remove-exact-orphan'
        $removeParameters = @{
            LiteralPath  = $path
            Account      = $script:orphanedGenericSid
            AccessRights = $script:genericAllMask
            AppliesTo    = 'SubfoldersAndFilesOnly'
            RemovalMode  = 'Exact'
            Confirm      = $false
        }

        Remove-NTFSAccessRule @removeParameters

        $stored = @(Get-StoredAce -Path $path)
        @($stored | Where-Object Sid -EQ $script:orphanedGenericSid) | Should -BeNullOrEmpty
        @($stored | Where-Object Sid -EQ $script:orphanedSid) | Should -HaveCount 1
    }

    It 'Should leave the list untouched when no entry matches the exact mask' {
        $path = New-GenericAceDirectory -Name 'remove-exact-absent'
        $before = @(Get-StoredAce -Path $path)
        $removeParameters = @{
            LiteralPath  = $path
            Account      = $script:orphanedGenericSid
            AccessRights = $script:genericExecuteWriteReadMask
            AppliesTo    = 'SubfoldersAndFilesOnly'
            RemovalMode  = 'Exact'
            Confirm      = $false
        }

        { Remove-NTFSAccessRule @removeParameters } | Should -Not -Throw

        $after = @(Get-StoredAce -Path $path)
        $after.Count | Should -Be $before.Count
        @($after | Where-Object Sid -EQ $script:orphanedGenericSid) | Should -HaveCount 1
    }

    It 'Should accept a hexadecimal mask supplied as a string' {
        $path = New-GenericAceDirectory -Name 'remove-exact-hex-string'
        $removeParameters = @{
            LiteralPath  = $path
            Account      = $script:authenticatedUsersSid
            AccessRights = '0xE0010000'
            AppliesTo    = 'SubfoldersAndFilesOnly'
            RemovalMode  = 'Exact'
            Confirm      = $false
        }

        Remove-NTFSAccessRule @removeParameters

        @(Get-StoredAce -Path $path | Where-Object Sid -EQ $script:authenticatedUsersSid) |
            Should -BeNullOrEmpty
    }

    It 'Should remove every orphaned entry through a pipeline round trip' {
        $path = New-GenericAceDirectory -Name 'remove-pipeline'

        Get-NTFSAccessRule -LiteralPath $path -Orphaned | Remove-NTFSAccessRule -Confirm:$false

        $stored = @(Get-StoredAce -Path $path)
        @($stored | Where-Object Sid -EQ $script:orphanedSid) | Should -BeNullOrEmpty
        @($stored | Where-Object Sid -EQ $script:orphanedGenericSid) | Should -BeNullOrEmpty
        @($stored | Where-Object Sid -EQ $script:authenticatedUsersSid) | Should -HaveCount 1
        @($stored | Where-Object Sid -EQ $script:interactiveSid) | Should -HaveCount 1
    }

    It 'Should clear every explicit entry including the generic ones' {
        $path = New-GenericAceDirectory -Name 'remove-clear'

        Clear-NTFSAccessRule -LiteralPath $path -Confirm:$false

        $stored = @(Get-StoredAce -Path $path)
        @($stored | Where-Object Sid -EQ $script:authenticatedUsersSid) | Should -BeNullOrEmpty
        @($stored | Where-Object Sid -EQ $script:interactiveSid) | Should -BeNullOrEmpty
        @($stored | Where-Object Sid -EQ $script:orphanedSid) | Should -BeNullOrEmpty
        @($stored | Where-Object Sid -EQ $script:orphanedGenericSid) | Should -BeNullOrEmpty
    }
}

Describe 'NTFS generic-bit audit entry removal' -Tag 'Integration', 'WindowsOnly', 'RequiresElevation' {
    BeforeAll {
        $script:auditSkipReason = $null
        $script:auditPrivilegeEnabled = $false
        $tokenPrivilege = @(Get-WindowsPrivilege) | Where-Object Name -EQ 'SeSecurityPrivilege'
        if (-not $tokenPrivilege) {
            $script:auditSkipReason = 'The process token does not contain SeSecurityPrivilege.'
        } elseif (-not (Test-WindowsPrivilege -Name 'SeSecurityPrivilege')) {
            try {
                Enable-WindowsPrivilege -Name 'SeSecurityPrivilege' -Confirm:$false
                $script:auditPrivilegeEnabled = $true
            } catch {
                $script:auditSkipReason =
                    "SeSecurityPrivilege could not be enabled: $($_.Exception.Message)"
            }
        }
        if (-not $script:auditSkipReason -and -not (Test-WindowsPrivilege -Name 'SeSecurityPrivilege')) {
            $script:auditSkipReason = 'SeSecurityPrivilege is not enabled.'
        }
    }

    AfterAll {
        if ($script:auditPrivilegeEnabled) {
            Disable-WindowsPrivilege -Name 'SeSecurityPrivilege' -Confirm:$false
        }
    }

    It 'Should add, report and remove a generic-bit system access control entry' {
        if ($script:auditSkipReason) {
            Set-ItResult -Skipped -Because $script:auditSkipReason
            return
        }
        $path = Join-Path -Path $TestDrive -ChildPath 'audit-generic'
        $null = New-Item -Path $path -ItemType Directory -Force
        $ruleParameters = @{
            LiteralPath  = $path
            Account      = $script:currentSid
            AccessRights = $script:genericAllMask
            AuditFlags   = 'Success'
            AppliesTo    = 'SubfoldersAndFilesOnly'
            Confirm      = $false
        }

        Add-NTFSAuditRule @ruleParameters

        $stored = @(Get-StoredAce -Path $path -Section Audit | Where-Object Sid -EQ $script:currentSid)
        $stored | Should -HaveCount 1
        $stored[0].AccessMask | Should -Be $script:genericAllMask

        $auditRule = @(Get-NTFSAuditRule -LiteralPath $path -Account $script:currentSid -ExcludeInherited)
        $auditRule | Should -HaveCount 1
        $auditRule[0].AccessMask | Should -Be $script:genericAllMask
        $auditRule[0].AccessRightsDisplay | Should -Be 'GenericAll'

        Remove-NTFSAuditRule @ruleParameters

        @(Get-StoredAce -Path $path -Section Audit | Where-Object Sid -EQ $script:currentSid) |
            Should -BeNullOrEmpty
    }

    It 'Should remove a generic-bit system access control entry through a pipeline round trip' {
        if ($script:auditSkipReason) {
            Set-ItResult -Skipped -Because $script:auditSkipReason
            return
        }
        $path = Join-Path -Path $TestDrive -ChildPath 'audit-generic-pipeline'
        $null = New-Item -Path $path -ItemType Directory -Force
        $addParameters = @{
            LiteralPath  = $path
            Account      = $script:currentSid
            AccessRights = $script:genericExecuteWriteReadMask
            AuditFlags   = 'Success'
            AppliesTo    = 'SubfoldersAndFilesOnly'
            Confirm      = $false
        }

        Add-NTFSAuditRule @addParameters
        Get-NTFSAuditRule -LiteralPath $path -Account $script:currentSid -ExcludeInherited |
            Remove-NTFSAuditRule -Confirm:$false

        @(Get-StoredAce -Path $path -Section Audit | Where-Object Sid -EQ $script:currentSid) |
            Should -BeNullOrEmpty
    }
}
