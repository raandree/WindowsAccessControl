function Test-WindowsADExcludedPartition {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedName,

        [Parameter(Mandatory)]
        [pscustomobject]$RootDse
    )

    foreach ($excludedNamingContext in @(
            $RootDse.ConfigurationNamingContext
            $RootDse.SchemaNamingContext
        )) {
        if (-not [string]::IsNullOrWhiteSpace([string]$excludedNamingContext) -and
            (Test-WindowsADDistinguishedNameWithinBase `
                -DistinguishedName $DistinguishedName `
                -BaseDistinguishedName ([string]$excludedNamingContext))) {
            return $true
        }
    }
    $false
}
