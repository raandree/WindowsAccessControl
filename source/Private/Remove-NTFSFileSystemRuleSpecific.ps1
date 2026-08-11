function Remove-NTFSFileSystemRuleSpecific {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemSecurity]$Security,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.AuthorizationRule]$Rule
    )

    $isAuditRule = $Rule -is [System.Security.AccessControl.FileSystemAuditRule]
    $mask = [int]$Rule.FileSystemRights
    $isNameableMask = $mask -ge 0 -and
        $mask -le [int][System.Security.AccessControl.FileSystemRights]::FullControl

    if ($isNameableMask) {
        if ($isAuditRule) {
            $Security.RemoveAuditRuleSpecific($Rule)
        } else {
            $Security.RemoveAccessRuleSpecific($Rule)
        }
        return
    }

    # When no stored entry matches, the framework rebuilds the rule through the
    # public rights constructor, which rejects a mask the enum cannot name. Match
    # the stored entry on the raw list instead so an absent entry is a no-op.
    $sections = if ($isAuditRule) {
        [System.Security.AccessControl.AccessControlSections]::Audit
    } else {
        [System.Security.AccessControl.AccessControlSections]::Access
    }
    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $Security.GetSecurityDescriptorBinaryForm(),
        0
    )
    # Assign inside the branches: an access control list flowing out of an if
    # expression is unrolled into its entries.
    if ($isAuditRule) {
        $acl = $descriptor.SystemAcl
    } else {
        $acl = $descriptor.DiscretionaryAcl
    }
    if (-not $acl) {
        return
    }

    $aceFlags = 0
    if (($Rule.InheritanceFlags -band
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) -ne 0) {
        $aceFlags = $aceFlags -bor [int][System.Security.AccessControl.AceFlags]::ContainerInherit
    }
    if (($Rule.InheritanceFlags -band
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0) {
        $aceFlags = $aceFlags -bor [int][System.Security.AccessControl.AceFlags]::ObjectInherit
    }
    if (($Rule.PropagationFlags -band
            [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit) -ne 0) {
        $aceFlags = $aceFlags -bor [int][System.Security.AccessControl.AceFlags]::NoPropagateInherit
    }
    if (($Rule.PropagationFlags -band
            [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
        $aceFlags = $aceFlags -bor [int][System.Security.AccessControl.AceFlags]::InheritOnly
    }
    if ($isAuditRule) {
        if (($Rule.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success) -ne 0) {
            $aceFlags = $aceFlags -bor [int][System.Security.AccessControl.AceFlags]::SuccessfulAccess
        }
        if (($Rule.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Failure) -ne 0) {
            $aceFlags = $aceFlags -bor [int][System.Security.AccessControl.AceFlags]::FailedAccess
        }
        $qualifier = [System.Security.AccessControl.AceQualifier]::SystemAudit
    } elseif ($Rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
        $qualifier = [System.Security.AccessControl.AceQualifier]::AccessDenied
    } else {
        $qualifier = [System.Security.AccessControl.AceQualifier]::AccessAllowed
    }
    $securityIdentifier = [System.Security.Principal.SecurityIdentifier]$Rule.IdentityReference

    $removed = $false
    for ($index = $acl.Count - 1; $index -ge 0; $index--) {
        $ace = $acl[$index]
        $qualifiedAce = $ace -as [System.Security.AccessControl.QualifiedAce]
        $knownAce = $ace -as [System.Security.AccessControl.KnownAce]
        if (-not $qualifiedAce -or -not $knownAce -or
            ([int]$ace.AceFlags -band
                [int][System.Security.AccessControl.AceFlags]::Inherited) -ne 0 -or
            $qualifiedAce.AceQualifier -ne $qualifier -or
            $qualifiedAce.SecurityIdentifier -ne $securityIdentifier -or
            $knownAce.AccessMask -ne $mask -or
            [int]$ace.AceFlags -ne $aceFlags) {
            continue
        }
        $acl.RemoveAce($index)
        $removed = $true
        break
    }
    if (-not $removed) {
        return
    }

    $updatedForm = [byte[]]::new($descriptor.BinaryLength)
    $descriptor.GetBinaryForm($updatedForm, 0)
    $Security.SetSecurityDescriptorBinaryForm($updatedForm, $sections)
}
