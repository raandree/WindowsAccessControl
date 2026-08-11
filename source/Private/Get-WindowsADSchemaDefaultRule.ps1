function Get-WindowsADSchemaDefaultRule {
    <#
        .SYNOPSIS
            Reads the access control entries one schema class applies to new objects.

        .DESCRIPTION
            Expands the class's stored defaultSecurityDescriptor against the
            supplied domain security identifiers and returns one rule object per
            entry. The read runs over an already-bound connection so a caller
            that is already querying an object does not open a second one.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ObjectClass,

        [Parameter(Mandatory)]
        [pscustomobject]$RootDse,

        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$DomainSid,

        [Parameter()]
        [AllowNull()]
        [System.Security.Principal.SecurityIdentifier]$RootDomainSid
    )

    $escaped = ConvertTo-WindowsADLdapFilterValue -Value $ObjectClass
    $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
        $RootDse.SchemaNamingContext,
        '(&(objectClass=classSchema)(|(lDAPDisplayName={0})(cn={0})))' -f $escaped,
        [System.DirectoryServices.Protocols.SearchScope]::OneLevel,
        [string[]]@('lDAPDisplayName', 'defaultSecurityDescriptor')
    )
    $response = [System.DirectoryServices.Protocols.SearchResponse](
        $Connection.SendRequest($request)
    )
    if ($response.Entries.Count -ne 1) {
        Write-Error `
            -Message "Object class '$ObjectClass' did not resolve to exactly one schema class on '$Server'." `
            -Category ObjectNotFound `
            -TargetObject $ObjectClass
        return
    }
    $entry = $response.Entries[0]
    $resolvedName = ConvertFrom-WindowsADAttributeValue `
        -Value $entry.Attributes['lDAPDisplayName'][0]
    if (-not $entry.Attributes.Contains('defaultSecurityDescriptor')) {
        Write-Verbose "Object class '$resolvedName' carries no defaultSecurityDescriptor."
        return
    }
    $sddl = ConvertFrom-WindowsADAttributeValue `
        -Value $entry.Attributes['defaultSecurityDescriptor'][0]
    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        (ConvertTo-WindowsADAbsoluteSddl `
            -Sddl $sddl `
            -DomainSid $DomainSid `
            -RootDomainSid $RootDomainSid)
    )
    $acl = $descriptor.DiscretionaryAcl
    if (-not $acl) {
        return
    }
    $ruleGuids = @(
        foreach ($value in $acl) {
            $objectAce = $value -as [System.Security.AccessControl.ObjectAce]
            if (-not $objectAce) { continue }
            if ($objectAce.ObjectAceFlags -band
                [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent) {
                $objectAce.ObjectAceType
            }
            if ($objectAce.ObjectAceFlags -band
                [System.Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent) {
                $objectAce.InheritedObjectAceType
            }
        }
    )
    $schemaGuidName = $null
    if ($ruleGuids.Count -gt 0) {
        try {
            $schemaGuidName = Resolve-WindowsADSchemaGuidName `
                -Connection $Connection `
                -SchemaNamingContext $RootDse.SchemaNamingContext `
                -ConfigurationNamingContext $RootDse.ConfigurationNamingContext `
                -Guid $ruleGuids
        }
        catch {
            $schemaGuidName = $null
            Write-Error `
                -Message "Cannot resolve directory schema names for '$resolvedName': $($_.Exception.Message) Rules are reported with object GUIDs only." `
                -Category ReadError `
                -TargetObject $resolvedName
        }
    }
    foreach ($ace in $acl) {
        ConvertTo-WindowsADSchemaDefaultRuleObject `
            -Ace $ace `
            -ObjectClass $resolvedName `
            -Server $Server `
            -SchemaGuidName $schemaGuidName
    }
}
