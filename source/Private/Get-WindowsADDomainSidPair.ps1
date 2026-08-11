function Get-WindowsADDomainSidPair {
    <#
        .SYNOPSIS
            Reads the security identifiers a stored schema template expands against.

        .DESCRIPTION
            Returns the security identifier of the domain the bound controller
            serves, and the one of the forest root domain. Referral chasing is
            off, so a child controller cannot read the forest root partition
            over the bound connection; the global catalog port of the same
            pinned server is the referral-free second source.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,

        [Parameter(Mandatory)]
        [pscustomobject]$RootDse,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [Parameter()]
        [pscredential]$Credential,

        [Parameter(Mandatory)]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds
    )

    $domainSid = Get-WindowsADNamingContextSid `
        -Connection $Connection `
        -NamingContext $RootDse.DefaultNamingContext
    if (-not $domainSid) {
        throw "Cannot read the domain SID of '$($RootDse.DefaultNamingContext)' from '$Server'. Schema default rules cannot be expanded without it."
    }
    $rootDomainSid = if ($RootDse.RootDomainNamingContext -and
        $RootDse.RootDomainNamingContext -ne $RootDse.DefaultNamingContext) {
        $sid = Get-WindowsADNamingContextSid `
            -Connection $Connection `
            -NamingContext $RootDse.RootDomainNamingContext
        if (-not $sid) {
            # A child domain controller does not hold the forest root
            # partition, and referral chasing is off, so the only referral-free
            # source on the same pinned server is its global catalog, which
            # carries every domain's objectSid.
            $sid = Get-WindowsADNamingContextSid `
                -NamingContext $RootDse.RootDomainNamingContext `
                -Server $Server `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds `
                -UseGlobalCatalog
        }
        $sid
    }
    else { $domainSid }

    [pscustomobject]@{
        DomainSid = $domainSid
        RootDomainSid = $rootDomainSid
    }
}
