function ConvertTo-WindowsCngKeyAccessRuleObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.GenericAce]$Ace,

        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [string]$TypeName
    )

    $qualifiedAce = $Ace -as [Security.AccessControl.QualifiedAce]
    $knownAce = $Ace -as [Security.AccessControl.KnownAce]
    if (-not $qualifiedAce -or -not $knownAce -or
        $qualifiedAce.AceQualifier -notin @(
            [Security.AccessControl.AceQualifier]::AccessAllowed,
            [Security.AccessControl.AceQualifier]::AccessDenied
        )) {
        return
    }

    $account = $null
    $isOrphaned = $false
    try {
        $account = $qualifiedAce.SecurityIdentifier.Translate(
            [Security.Principal.NTAccount]
        ).Value
    }
    catch [Security.Principal.IdentityNotMappedException] {
        $isOrphaned = $true
    }

    $effectiveMask = ConvertTo-WindowsCryptoKeyEffectiveMask `
        -AccessMask ([long]$knownAce.AccessMask)
    $result = [pscustomobject]@{
        ObjectType            = $Target.ObjectType
        Path                  = $Target.Path
        Server                = $Target.Server
        ProviderName          = $Target.ProviderName
        KeyName               = $Target.KeyName
        KeyScope              = $Target.KeyScope
        CertificateThumbprint = $Target.CertificateThumbprint
        CanonicalTarget       = $Target.CanonicalTarget
        RuleType              = 'Access'
        Account               = $account
        SID                   = $qualifiedAce.SecurityIdentifier.Value
        IsOrphaned            = $isOrphaned
        AccessMask            = [uint64]([int64]$knownAce.AccessMask -band 0xFFFFFFFFL)
        EffectiveAccessMask   = [uint64]$effectiveMask
        AccessRights          = [Enum]::ToObject([WindowsCryptoKeyRights], $effectiveMask)
        AccessControlType     = if ($qualifiedAce.AceQualifier -eq
            [Security.AccessControl.AceQualifier]::AccessDenied) {
            [Security.AccessControl.AccessControlType]::Deny
        }
        else {
            [Security.AccessControl.AccessControlType]::Allow
        }
        IsInherited           = ([int]$Ace.AceFlags -band
            [int][Security.AccessControl.AceFlags]::Inherited) -ne 0
        AceFlags              = $Ace.AceFlags
        IdentityReference     = $qualifiedAce.SecurityIdentifier
        NativeAce             = $Ace
    }
    $result.PSObject.TypeNames.Insert(0, $TypeName)
    $result.PSObject.TypeNames.Add('WindowsAccessControl.Rule')
    $result
}
