function Get-WindowsADParentDistinguishedName {
    <#
        .SYNOPSIS
            Returns the parent distinguished name of an Active Directory object.

        .DESCRIPTION
            Splits at the first unescaped comma so relative names that contain
            an escaped comma are not split inside a component. Returns an empty
            string when the value has no parent.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedName
    )

    for ($index = 0; $index -lt $DistinguishedName.Length; $index++) {
        if ($DistinguishedName[$index] -ne ',') {
            continue
        }
        $backslashes = 0
        for ($scan = $index - 1; $scan -ge 0 -and $DistinguishedName[$scan] -eq '\'; $scan--) {
            $backslashes++
        }
        if ($backslashes % 2 -eq 0) {
            return $DistinguishedName.Substring($index + 1).TrimStart()
        }
    }
    ''
}
