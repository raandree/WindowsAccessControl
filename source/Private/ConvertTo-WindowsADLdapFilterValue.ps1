function ConvertTo-WindowsADLdapFilterValue {
    <#
        .SYNOPSIS
            Escapes a value for safe use inside an LDAP search filter.

        .DESCRIPTION
            Applies RFC 4515 escaping so a caller-supplied name cannot alter the
            structure of the filter it is embedded in.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    -join @(
        foreach ($character in $Value.ToCharArray()) {
            switch ($character) {
                '\' { '\5c' }
                '*' { '\2a' }
                '(' { '\28' }
                ')' { '\29' }
                "`0" { '\00' }
                default { $character }
            }
        }
    )
}
