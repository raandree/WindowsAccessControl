function Test-WindowsADProtectedTarget {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Record,

        [Parameter(Mandatory)]
        [pscustomobject]$RootDse
    )

    if ($Record.DistinguishedName.Equals(
            $RootDse.DefaultNamingContext,
            [StringComparison]::OrdinalIgnoreCase
        ) -or $Record.AdminCount -or
        'groupPolicyContainer' -in $Record.ObjectClasses) {
        return $true
    }
    foreach ($protectedBase in @(
            "CN=System,$($RootDse.DefaultNamingContext)"
            "OU=Domain Controllers,$($RootDse.DefaultNamingContext)"
        )) {
        if (Test-WindowsADDistinguishedNameWithinBase `
                -DistinguishedName $Record.DistinguishedName `
                -BaseDistinguishedName $protectedBase) {
            return $true
        }
    }
    $false
}
