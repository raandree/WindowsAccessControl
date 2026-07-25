function Resolve-WindowsIdentity {
    <#
    .SYNOPSIS
        Resolves Windows account names and security identifiers.

    .DESCRIPTION
        Converts account names or SID strings into structured identity objects
        containing both forms where Windows can translate them. A valid but
        orphaned SID is returned with IsResolved set to false.

    .PARAMETER Identity
        One or more account names, identity references, or SID strings to
        resolve. Values can be supplied through the pipeline.

    .EXAMPLE
        'BUILTIN\Users', 'S-1-1-0' | Resolve-WindowsIdentity

        Resolves the built-in Users and Everyone identities.

    .INPUTS
        System.String
        System.Security.Principal.IdentityReference

    .OUTPUTS
        WindowsAccessControl.Identity
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [object[]]$Identity
    )

    process {
        foreach ($identityValue in $Identity) {
            $securityIdentifier = Resolve-WindowsIdentityReference -Identity $identityValue
            $account = $null
            $isResolved = $true
            try {
                $account = $securityIdentifier.Translate([System.Security.Principal.NTAccount]).Value
            } catch [System.Security.Principal.IdentityNotMappedException] {
                $isResolved = $false
            }

            $result = [pscustomobject]@{
                Account           = $account
                SID               = $securityIdentifier.Value
                IsResolved        = $isResolved
                IdentityReference = $securityIdentifier
            }
            $result.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.Identity')
            $result
        }
    }
}