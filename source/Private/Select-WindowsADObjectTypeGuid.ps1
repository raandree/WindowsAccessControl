function Select-WindowsADObjectTypeGuid {
    <#
        .SYNOPSIS
            Reduces a name lookup to exactly one GUID or refuses.

        .DESCRIPTION
            Returns the single GUID a name resolved to. A name that matched
            nothing, and a name that matched more than one GUID, both throw,
            because falling back to the empty GUID would widen an entry scoped
            to one object or property into one that applies to every object and
            every property.

            This decision is separate from the search that feeds it so the
            refusals can be proven. A stock schema contains no ambiguous name,
            so the second refusal is unreachable through a live lookup.
    #>
    [CmdletBinding()]
    [OutputType([guid])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [guid[]]$Found,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ParameterName
    )

    if ($Found.Count -eq 0) {
        throw "$ParameterName '$Name' does not name an Active Directory schema class, attribute, property set, validated write, or extended right."
    }
    if ($Found.Count -gt 1) {
        throw "$ParameterName '$Name' names more than one Active Directory GUID ($($Found -join ', ')). Supply the GUID instead of the name."
    }
    $Found[0]
}
