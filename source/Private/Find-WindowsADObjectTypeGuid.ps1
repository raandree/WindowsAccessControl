function Find-WindowsADObjectTypeGuid {
    <#
        .SYNOPSIS
            Looks up one schema or control-access name and returns its GUID.

        .DESCRIPTION
            Searches the schema partition for a class or attribute whose
            lDAPDisplayName or common name matches, and the Extended-Rights
            container for a control access right whose display name or common
            name matches. Returns the single GUID both searches agree on and
            throws when the name matches nothing or resolves ambiguously.
    #>
    [CmdletBinding()]
    [OutputType([guid])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SchemaNamingContext,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ConfigurationNamingContext,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ParameterName
    )

    # RFC 4515 escaping keeps a caller-supplied name from altering the filter.
    $escaped = ConvertTo-WindowsADLdapFilterValue -Value $Name

    $found = [System.Collections.Generic.List[guid]]::new()
    foreach ($search in @(
            @{
                Base = $SchemaNamingContext
                Filter = '(&(|(objectClass=classSchema)(objectClass=attributeSchema))(|(lDAPDisplayName={0})(cn={0})))' -f $escaped
                GuidAttribute = 'schemaIDGUID'
            }
            @{
                Base = "CN=Extended-Rights,$ConfigurationNamingContext"
                Filter = '(&(objectClass=controlAccessRight)(|(displayName={0})(cn={0})))' -f $escaped
                GuidAttribute = 'rightsGuid'
            }
        )) {
        $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
            $search.Base,
            $search.Filter,
            [System.DirectoryServices.Protocols.SearchScope]::OneLevel,
            [string[]]@($search.GuidAttribute)
        )
        $response = [System.DirectoryServices.Protocols.SearchResponse](
            $Connection.SendRequest($request)
        )
        foreach ($entry in $response.Entries) {
            if (-not $entry.Attributes.Contains($search.GuidAttribute)) {
                continue
            }
            $rawGuid = $entry.Attributes[$search.GuidAttribute][0]
            $entryGuid = if ($rawGuid -is [byte[]] -and $rawGuid.Length -eq 16) {
                [guid]::new([byte[]]$rawGuid)
            }
            else {
                [guid](ConvertFrom-WindowsADAttributeValue -Value $rawGuid)
            }
            if ($found -notcontains $entryGuid) {
                $found.Add($entryGuid)
            }
        }
    }

    Select-WindowsADObjectTypeGuid `
        -Found $found `
        -Name $Name `
        -ParameterName $ParameterName
}
