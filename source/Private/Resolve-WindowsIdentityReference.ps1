function Resolve-WindowsIdentityReference {
    [CmdletBinding()]
    [OutputType([System.Security.Principal.SecurityIdentifier])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Identity
    )

    process {
        try {
            if ($Identity -is [System.Security.Principal.SecurityIdentifier]) {
                $Identity
            } elseif ($Identity -is [System.Security.Principal.IdentityReference]) {
                $Identity.Translate([System.Security.Principal.SecurityIdentifier])
            } elseif ([string]$Identity -match '^S-\d(?:-\d+)+$') {
                [System.Security.Principal.SecurityIdentifier]::new([string]$Identity)
            } else {
                $account = [System.Security.Principal.NTAccount]::new([string]$Identity)
                $account.Translate([System.Security.Principal.SecurityIdentifier])
            }
        } catch [System.Security.Principal.IdentityNotMappedException] {
            throw [System.ArgumentException]::new(
                "Identity '$Identity' could not be resolved to a security identifier.",
                $_.Exception
            )
        }
    }
}