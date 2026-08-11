function Get-WindowsADNamingContextSid {
    <#
        .SYNOPSIS
            Reads the domain SID that heads a naming context.

        .DESCRIPTION
            Returns the objectSid of the naming context head, or null when the
            partition is not held by the bound domain controller. Referral
            chasing is disabled on the shared connection, so a partition from
            another domain is unreadable rather than silently redirected.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Principal.SecurityIdentifier])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$NamingContext
    )

    if ([string]::IsNullOrWhiteSpace($NamingContext)) {
        return $null
    }
    $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
        $NamingContext,
        '(objectClass=*)',
        [System.DirectoryServices.Protocols.SearchScope]::Base,
        [string[]]@('objectSid')
    )
    try {
        $response = [System.DirectoryServices.Protocols.SearchResponse](
            $Connection.SendRequest($request)
        )
    }
    catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
        return $null
    }
    if ($response.Entries.Count -ne 1) {
        return $null
    }
    $entry = $response.Entries[0]
    if (-not $entry.Attributes.Contains('objectSid')) {
        return $null
    }
    [System.Security.Principal.SecurityIdentifier]::new(
        [byte[]]$entry.Attributes['objectSid'][0],
        0
    )
}
