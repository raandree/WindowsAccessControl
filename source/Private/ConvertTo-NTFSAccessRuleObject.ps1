function ConvertTo-NTFSAccessRuleObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemAccessRule]$Rule,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Path,

        [Parameter()]
        [AllowNull()]
        [string]$InheritedFrom
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
    $inheritedFromPath = if (
        $Rule.IsInherited -and
        -not [string]::IsNullOrEmpty($InheritedFrom)
    ) {
        $InheritedFrom
    } else {
        $null
    }

    $accessMask = [uint64]([int64][int]$Rule.FileSystemRights -band 0xFFFFFFFFL)
    $accessRightsDisplay = ConvertTo-WindowsAccessRightsDisplay `
        -AccessMask $accessMask `
        -RightsType ([System.Security.AccessControl.FileSystemRights])

    $result = [pscustomobject]@{
        Path                = $Path
        Account             = $account
        SID                 = $securityIdentifier.Value
        AccessMask          = $accessMask
        AccessRights        = $Rule.FileSystemRights
        AccessRightsDisplay = $accessRightsDisplay
        AccessControlType   = $Rule.AccessControlType
        AppliesTo           = $appliesTo
        InheritanceFlags    = $Rule.InheritanceFlags
        PropagationFlags    = $Rule.PropagationFlags
        IsInherited         = $Rule.IsInherited
        InheritedFrom       = $inheritedFromPath
        IsOrphaned          = $isOrphaned
        NativeRule          = $Rule
    }
    $result.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.AccessRule')
    $result
}
