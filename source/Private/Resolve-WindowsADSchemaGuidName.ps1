function Resolve-WindowsADSchemaGuidName {
    <#
        .SYNOPSIS
            Resolves directory ACE GUIDs to schema and control-access names.

        .DESCRIPTION
            Returns a hashtable that maps each requested GUID, in lowercase
            registry form, to a display name. A class or attribute resolves to
            its lDAPDisplayName in the schema partition. A property set,
            validated write, or extended right resolves to the display name of
            its control-access right. A GUID that resolves to neither maps to
            null. Results are cached per forest schema for the session.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SchemaNamingContext,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ConfigurationNamingContext,

        [Parameter()]
        [guid[]]$Guid
    )

    $names = @{}
    $cachePrefix = $SchemaNamingContext.ToLowerInvariant()
    $pending = [System.Collections.Generic.List[guid]]::new()
    foreach ($value in $Guid) {
        if ($value -eq [guid]::Empty) {
            continue
        }
        $guidKey = $value.ToString('D').ToLowerInvariant()
        if ($names.ContainsKey($guidKey)) {
            continue
        }
        $cacheKey = '{0}|{1}' -f $cachePrefix, $guidKey
        if ($script:WindowsADSchemaGuidNames.ContainsKey($cacheKey)) {
            $names[$guidKey] = $script:WindowsADSchemaGuidNames[$cacheKey]
            continue
        }
        if ($pending -notcontains $value) {
            $pending.Add($value)
        }
    }
    if ($pending.Count -eq 0) {
        return $names
    }

    $chunkSize = 50
    for ($offset = 0; $offset -lt $pending.Count; $offset += $chunkSize) {
        $chunk = @(
            $pending.GetRange($offset, [Math]::Min($chunkSize, $pending.Count - $offset))
        )
        $schemaFilter = '(|{0})' -f (-join @(
                foreach ($value in $chunk) {
                    '(schemaIDGUID={0})' -f (-join @(
                            foreach ($byte in $value.ToByteArray()) { '\{0:x2}' -f $byte }
                        ))
                }
            ))
        $rightsFilter = '(|{0})' -f (-join @(
                foreach ($value in $chunk) {
                    '(rightsGuid={0})' -f $value.ToString('D')
                }
            ))

        foreach ($search in @(
                @{
                    Base = $SchemaNamingContext
                    Filter = $schemaFilter
                    Attributes = [string[]]@('lDAPDisplayName', 'cn', 'schemaIDGUID')
                    GuidAttribute = 'schemaIDGUID'
                    NameAttribute = 'lDAPDisplayName'
                }
                @{
                    Base = "CN=Extended-Rights,$ConfigurationNamingContext"
                    Filter = $rightsFilter
                    Attributes = [string[]]@('displayName', 'cn', 'rightsGuid')
                    GuidAttribute = 'rightsGuid'
                    NameAttribute = 'displayName'
                }
            )) {
            $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
                $search.Base,
                $search.Filter,
                [System.DirectoryServices.Protocols.SearchScope]::OneLevel,
                $search.Attributes
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
                $guidKey = $entryGuid.ToString('D').ToLowerInvariant()
                # The schema partition is searched first, so a class or
                # attribute name wins over a control-access right name.
                if ($names[$guidKey]) {
                    continue
                }
                $displayName = $null
                foreach ($attributeName in $search.NameAttribute, 'cn') {
                    if ($entry.Attributes.Contains($attributeName)) {
                        $displayName = ConvertFrom-WindowsADAttributeValue `
                            -Value $entry.Attributes[$attributeName][0]
                        break
                    }
                }
                $names[$guidKey] = $displayName
            }
        }
    }

    foreach ($value in $pending) {
        $guidKey = $value.ToString('D').ToLowerInvariant()
        if (-not $names.ContainsKey($guidKey)) {
            $names[$guidKey] = $null
            # A GUID can also resolve to nothing because this caller cannot read
            # the schema entry, so an unresolved result is not cached.
            continue
        }
        $script:WindowsADSchemaGuidNames['{0}|{1}' -f $cachePrefix, $guidKey] = $names[$guidKey]
    }
    $names
}
