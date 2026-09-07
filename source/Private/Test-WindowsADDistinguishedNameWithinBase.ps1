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

    $candidate = $DistinguishedName
    while (-not [string]::IsNullOrEmpty($candidate)) {
        if ($candidate.Equals($BaseDistinguishedName, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
        $candidate = Get-WindowsADParentDistinguishedName -DistinguishedName $candidate
    }
    $false
}
