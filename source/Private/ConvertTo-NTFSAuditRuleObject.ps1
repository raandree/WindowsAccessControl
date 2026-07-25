function ConvertTo-NTFSAuditRuleObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemAuditRule]$Rule,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Path
    )

    $securityIdentifier = [System.Security.Principal.SecurityIdentifier]$Rule.IdentityReference
    $account = $null
    $isOrphaned = $false
    try {
        $account = $securityIdentifier.Translate([System.Security.Principal.NTAccount]).Value
    } catch [System.Security.Principal.IdentityNotMappedException] {
        $isOrphaned = $true
    }

    $appliesToParameters = @{
        InheritanceFlags = $Rule.InheritanceFlags
        PropagationFlags = $Rule.PropagationFlags
    }
    $appliesTo = ConvertTo-NTFSAppliesTo @appliesToParameters

    $result = [pscustomobject]@{
        Path             = $Path
        Account          = $account
        SID              = $securityIdentifier.Value
        AccessRights     = $Rule.FileSystemRights
        AuditFlags       = $Rule.AuditFlags
        AppliesTo        = $appliesTo
        InheritanceFlags = $Rule.InheritanceFlags
        PropagationFlags = $Rule.PropagationFlags
        IsInherited      = $Rule.IsInherited
        IsOrphaned       = $isOrphaned
        NativeRule       = $Rule
    }
    $result.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.AuditRule')
    $result
}