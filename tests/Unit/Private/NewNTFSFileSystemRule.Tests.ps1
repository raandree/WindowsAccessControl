# Mask-range construction contract for NTFS rule creation (FR-28).
BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module -Name WindowsAccessControl
    $script:testSid = 'S-1-5-11'
    $script:genericAllMask = 0x10000000
}

AfterAll {
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'New-NTFSFileSystemRule' -Tag 'Unit', 'WindowsOnly' {
    It 'Should keep the framework Synchronize normalization for an allow rule' {
        $mask = & $script:module {
            param($Sid)
            $rule = New-NTFSFileSystemRule `
                -SecurityIdentifier ([System.Security.Principal.SecurityIdentifier]::new($Sid)) `
                -AccessRights ([System.Security.AccessControl.FileSystemRights]::Modify) `
                -AccessControlType Allow
            [int]$rule.FileSystemRights
        } $script:testSid

        $mask | Should -Be (
            [int][System.Security.AccessControl.FileSystemRights]::Modify -bor
            [int][System.Security.AccessControl.FileSystemRights]::Synchronize
        )
    }

    It 'Should keep the framework Synchronize normalization for a deny rule' {
        $mask = & $script:module {
            param($Sid)
            $rule = New-NTFSFileSystemRule `
                -SecurityIdentifier ([System.Security.Principal.SecurityIdentifier]::new($Sid)) `
                -AccessRights ([System.Security.AccessControl.FileSystemRights]::Modify) `
                -AccessControlType Deny
            [int]$rule.FileSystemRights
        } $script:testSid

        ($mask -band [int][System.Security.AccessControl.FileSystemRights]::Synchronize) |
            Should -Be 0
    }

    It 'Should build a rule verbatim for the <Name> mask the enum cannot name' -ForEach @(
        @{ Name = 'GENERIC_ALL'; Mask = 0x10000000 }
        @{ Name = 'GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE and DELETE'; Mask = 0xE0010000 }
        @{ Name = 'ACCESS_SYSTEM_SECURITY'; Mask = 0x01000000 }
    ) {
        $result = & $script:module {
            param($Sid, $Mask)
            $rule = New-NTFSFileSystemRule `
                -SecurityIdentifier ([System.Security.Principal.SecurityIdentifier]::new($Sid)) `
                -AccessRights $Mask `
                -AccessControlType Allow
            [int]$rule.FileSystemRights
        } $script:testSid $Mask

        $result | Should -Be ([int]$Mask)
    }

    It 'Should build an audit rule verbatim for a generic mask' {
        $result = & $script:module {
            param($Sid, $Mask)
            $rule = New-NTFSFileSystemRule `
                -SecurityIdentifier ([System.Security.Principal.SecurityIdentifier]::new($Sid)) `
                -AccessRights $Mask `
                -AuditFlags Success
            [pscustomobject]@{
                Mask       = [int]$rule.FileSystemRights
                AuditFlags = $rule.AuditFlags
                TypeName   = $rule.GetType().Name
            }
        } $script:testSid $script:genericAllMask

        $result.Mask | Should -Be 0x10000000
        $result.AuditFlags | Should -Be ([System.Security.AccessControl.AuditFlags]::Success)
        $result.TypeName | Should -Be 'FileSystemAuditRule'
    }

    It 'Should accept the unsigned form of a generic mask' {
        $result = & $script:module {
            param($Sid, $Mask)
            $rule = New-NTFSFileSystemRule `
                -SecurityIdentifier ([System.Security.Principal.SecurityIdentifier]::new($Sid)) `
                -AccessRights $Mask `
                -AccessControlType Allow
            [int]$rule.FileSystemRights
        } $script:testSid 3758161920

        $result | Should -Be 0xE0010000
    }

    It 'Should accept a hexadecimal mask supplied as a string' {
        $result = & $script:module {
            param($Sid, $Mask)
            $rule = New-NTFSFileSystemRule `
                -SecurityIdentifier ([System.Security.Principal.SecurityIdentifier]::new($Sid)) `
                -AccessRights $Mask `
                -AccessControlType Allow
            [int]$rule.FileSystemRights
        } $script:testSid '0xE0010000'

        $result | Should -Be 0xE0010000
    }

    It 'Should reject a mask that does not fit in 32 bits' {
        {
            & $script:module {
                param($Sid, $Mask)
                New-NTFSFileSystemRule `
                    -SecurityIdentifier ([System.Security.Principal.SecurityIdentifier]::new($Sid)) `
                    -AccessRights $Mask `
                    -AccessControlType Allow
            } $script:testSid 4294967296
        } | Should -Throw
    }

    It 'Should still reject an unknown rights name' {
        {
            & $script:module {
                param($Sid)
                New-NTFSFileSystemRule `
                    -SecurityIdentifier ([System.Security.Principal.SecurityIdentifier]::new($Sid)) `
                    -AccessRights 'NotARight' `
                    -AccessControlType Allow
            } $script:testSid
        } | Should -Throw
    }

    It 'Should build a rule from a hexadecimal literal mask' {
        # Every other mask case here passes the value through a variable, and a
        # variable always bound. A hexadecimal literal is the one form the
        # engine converts before the rights transformation attribute runs.
        $result = & $script:module {
            param($Sid)
            $rule = New-NTFSFileSystemRule `
                -SecurityIdentifier ([System.Security.Principal.SecurityIdentifier]::new($Sid)) `
                -AccessRights 0x10000000 `
                -AccessControlType Allow
            [int]$rule.FileSystemRights
        } $script:testSid

        $result | Should -Be 0x10000000
    }
}
