function Get-WindowsADNamingContextSid {
    <#
        .SYNOPSIS
            Reads the domain SID that heads a naming context.

        .DESCRIPTION
            Returns the objectSid of the naming context head, or null when it
            cannot be read. Referral chasing is disabled on the shared
            connection, so a partition the bound domain controller does not hold
            is unreadable rather than silently redirected.

            The GlobalCatalog parameter set opens a short-lived connection to
            the global catalog port of the same pinned server. A child domain
            controller does not hold the forest root partition, and its global
            catalog is the only referral-free source of that domain's SID.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Connection')]
    [OutputType([System.Security.Principal.SecurityIdentifier])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Connection')]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,

        [Parameter(Mandatory, ParameterSetName = 'GlobalCatalog')]
        [switch]$UseGlobalCatalog,

        [Parameter(Mandatory, ParameterSetName = 'GlobalCatalog')]
        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [Parameter(ParameterSetName = 'GlobalCatalog')]
        [pscredential]$Credential,

        [Parameter(ParameterSetName = 'GlobalCatalog')]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$NamingContext
    )

    if ([string]::IsNullOrWhiteSpace($NamingContext)) {
        return $null
    }
    $ownsConnection = $UseGlobalCatalog.IsPresent
    if ($ownsConnection) {
        try {
            $Connection = New-WindowsADConnection `
                -Server $Server `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds `
                -Port 3268
        }
        catch {
            return $null
        }
    }
    try {
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
    finally {
        if ($ownsConnection -and $Connection) {
            $Connection.Dispose()
        }
    }
}
