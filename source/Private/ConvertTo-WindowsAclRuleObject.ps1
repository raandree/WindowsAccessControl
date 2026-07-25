function ConvertTo-WindowsAclRuleObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.GenericAce]$Ace,

        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [ValidateSet('Access', 'Audit')]
        [string]$RuleType,

        [Parameter(Mandatory)]
        [string]$TypeName
    )

    $qualifiedAce = $Ace -as [System.Security.AccessControl.QualifiedAce]
    $knownAce = $Ace -as [System.Security.AccessControl.KnownAce]
    $securityIdentifier = if ($qualifiedAce) {
        $qualifiedAce.SecurityIdentifier
    } else {
        $null
    }
    $account = $null
    $isOrphaned = $false
    if ($securityIdentifier) {
        try {
            $account = $securityIdentifier.Translate(
                [System.Security.Principal.NTAccount]
            ).Value
        } catch [System.Security.Principal.IdentityNotMappedException] {
            $isOrphaned = $true
        }
    }

    $accessControlType = $null
    $auditFlagMask = 0
    if ($qualifiedAce) {
        $accessControlType = switch ($qualifiedAce.AceQualifier) {
            AccessAllowed { [System.Security.AccessControl.AccessControlType]::Allow }
            AccessDenied { [System.Security.AccessControl.AccessControlType]::Deny }
        }
    }
    if (([int]$Ace.AceFlags -band
        [int][System.Security.AccessControl.AceFlags]::SuccessfulAccess) -ne 0) {
        $auditFlagMask = $auditFlagMask -bor
            [int][System.Security.AccessControl.AuditFlags]::Success
    }
    if (([int]$Ace.AceFlags -band
        [int][System.Security.AccessControl.AceFlags]::FailedAccess) -ne 0) {
        $auditFlagMask = $auditFlagMask -bor
            [int][System.Security.AccessControl.AuditFlags]::Failure
    }

    $inheritFlags = [int]$Ace.AceFlags -band (
        [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
        [int][System.Security.AccessControl.AceFlags]::InheritOnly -bor
        [int][System.Security.AccessControl.AceFlags]::NoPropagateInherit
    )
    $appliesTo = switch ([int]$inheritFlags) {
        0 { 'ThisKeyOnly' }
        ([int][System.Security.AccessControl.AceFlags]::ContainerInherit) {
            'ThisKeyAndSubkeys'
        }
        ([int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
            [int][System.Security.AccessControl.AceFlags]::InheritOnly) {
            'SubkeysOnly'
        }
        ([int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
            [int][System.Security.AccessControl.AceFlags]::NoPropagateInherit) {
            'ThisKeyAndSubkeysOneLevel'
        }
        ([int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
            [int][System.Security.AccessControl.AceFlags]::InheritOnly -bor
            [int][System.Security.AccessControl.AceFlags]::NoPropagateInherit) {
            'SubkeysOnlyOneLevel'
        }
        default { 'Custom' }
    }

    $result = [pscustomobject]@{
        ObjectType         = $Target.ObjectType
        Path               = $Target.Path
        NativePath         = $Target.NativePath
        CanonicalTarget    = $Target.CanonicalTarget
        RegistryView       = $Target.RegistryView
        RuleType           = $RuleType
        Account            = $account
        SID                = if ($securityIdentifier) { $securityIdentifier.Value } else { $null }
        IsOrphaned         = $isOrphaned
        AccessMask         = if ($knownAce) { [int]$knownAce.AccessMask } else { $null }
        AccessRights       = if ($knownAce) {
            [System.Security.AccessControl.RegistryRights]$knownAce.AccessMask
        } else {
            $null
        }
        AccessControlType  = $accessControlType
        AuditFlags         = [System.Security.AccessControl.AuditFlags]$auditFlagMask
        AppliesTo          = $appliesTo
        IsInherited        = ([int]$Ace.AceFlags -band (
            [int][System.Security.AccessControl.AceFlags]::Inherited
        )) -ne 0
        NativeAce          = $Ace
    }
    $result.PSObject.TypeNames.Insert(0, $TypeName)
    $result.PSObject.TypeNames.Add('WindowsAccessControl.Rule')
    $result
}
