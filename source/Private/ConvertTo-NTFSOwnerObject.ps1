function ConvertTo-NTFSOwnerObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.ObjectSecurity]$Security,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $securityIdentifier = $Security.GetOwner([System.Security.Principal.SecurityIdentifier])
    $account = $null
    $isOrphaned = $false
    try {
        $account = $securityIdentifier.Translate([System.Security.Principal.NTAccount]).Value
    } catch [System.Security.Principal.IdentityNotMappedException] {
        $isOrphaned = $true
    }

    $result = [pscustomobject]@{
        Path       = $Path
        Account    = $account
        SID        = $securityIdentifier.Value
        IsOrphaned = $isOrphaned
    }
    $result.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.Owner')
    $result
}