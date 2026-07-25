function Resolve-WindowsIdentityReference {
    [CmdletBinding()]
    [OutputType([System.Security.Principal.SecurityIdentifier])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Identity
    )

    process {
        $identityValue = $Identity
        if ($identityValue -isnot [System.Security.Principal.IdentityReference]) {
            foreach ($propertyName in 'IdentityReference', 'SID', 'Account') {
                $property = $identityValue.PSObject.Properties[$propertyName]
                if ($property -and $null -ne $property.Value -and
                    -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                    $identityValue = $property.Value
                    break
                }
            }
        }

        try {
            if ($identityValue -is [System.Security.Principal.SecurityIdentifier]) {
                $identityValue
            } elseif ($identityValue -is [System.Security.Principal.IdentityReference]) {
                $identityValue.Translate([System.Security.Principal.SecurityIdentifier])
            } elseif ([string]$identityValue -match '^S-\d(?:-\d+)+$') {
                [System.Security.Principal.SecurityIdentifier]::new([string]$identityValue)
            } else {
                $account = [System.Security.Principal.NTAccount]::new([string]$identityValue)
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
