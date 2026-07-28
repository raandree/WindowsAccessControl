function Test-WindowsADDistinguishedNameWithinBase {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseDistinguishedName
    )

    $DistinguishedName.Equals(
        $BaseDistinguishedName,
        [StringComparison]::OrdinalIgnoreCase
    ) -or $DistinguishedName.EndsWith(
        ",$BaseDistinguishedName",
        [StringComparison]::OrdinalIgnoreCase
    )
}
