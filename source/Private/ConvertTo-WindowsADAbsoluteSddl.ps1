function ConvertTo-WindowsADAbsoluteSddl {
    <#
        .SYNOPSIS
            Expands domain-relative SDDL aliases against explicit domain SIDs.

        .DESCRIPTION
            The .NET SDDL parser resolves domain-relative aliases such as DA or
            EA against the calling machine's own domain, and throws outright on
            a machine that has no domain. A descriptor read from another domain
            or forest must therefore have those aliases replaced with the SIDs
            of the domain that owns it before it can be parsed at all.

            Replaces only the trustee field of each access control entry and the
            owner and group prefixes, so an alias sequence that also occurs
            inside a rights or GUID field is left alone. Every alias that is not
            domain-relative is left for the platform parser to resolve.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Sddl,

        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$DomainSid,

        [Parameter()]
        [AllowNull()]
        [System.Security.Principal.SecurityIdentifier]$RootDomainSid
    )

    if (-not $RootDomainSid) {
        $RootDomainSid = $null
    }
    # MS-DTYP 2.5.1.2. Only the relative identifiers below depend on which
    # domain the descriptor belongs to; every other alias is machine-wide.
    $domainRelative = @{
        LA = 500
        LG = 501
        DA = 512
        DU = 513
        DG = 514
        DC = 515
        DD = 516
        CA = 517
        PA = 520
        CN = 522
        AP = 525
        KA = 526
        RS = 553
    }
    $rootRelative = @{
        RO = 498
        SA = 518
        EA = 519
        EK = 527
    }
    $expand = {
        param([string]$Alias)
        if ($domainRelative.ContainsKey($Alias)) {
            return '{0}-{1}' -f $DomainSid.Value, $domainRelative[$Alias]
        }
        if (-not $rootRelative.ContainsKey($Alias)) {
            return $Alias
        }
        if (-not $RootDomainSid) {
            throw "The security descriptor references the forest-root alias '$Alias', and the forest root domain SID could not be read from the selected domain controller."
        }
        '{0}-{1}' -f $RootDomainSid.Value, $rootRelative[$Alias]
    }

    $result = [regex]::Replace(
        $Sddl,
        '(?<prefix>[OG]:)(?<alias>[A-Z]{2})(?=[OGDS]:|$)',
        {
            param($match)
            '{0}{1}' -f $match.Groups['prefix'].Value,
                (& $expand $match.Groups['alias'].Value)
        }
    )
    [regex]::Replace(
        $result,
        '\((?<body>[^()]*)\)',
        {
            param($match)
            $fields = $match.Groups['body'].Value -split ';'
            if ($fields.Count -lt 6) {
                return $match.Value
            }
            $fields[5] = & $expand $fields[5]
            '({0})' -f ($fields -join ';')
        }
    )
}
