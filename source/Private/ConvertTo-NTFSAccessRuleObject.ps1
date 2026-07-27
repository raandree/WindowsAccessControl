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

    $result = [pscustomobject]@{
        Path              = $Path
        Account           = $account
        SID               = $securityIdentifier.Value
        AccessRights      = $Rule.FileSystemRights
        AccessControlType = $Rule.AccessControlType
        AppliesTo         = $appliesTo
        InheritanceFlags  = $Rule.InheritanceFlags
        PropagationFlags  = $Rule.PropagationFlags
        IsInherited       = $Rule.IsInherited
        InheritedFrom     = $inheritedFromPath
        IsOrphaned        = $isOrphaned
        NativeRule        = $Rule
    }
    $result.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.AccessRule')
    $result
}
