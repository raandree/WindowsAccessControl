function Get-WindowsADRootDse {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection
    )

    $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
        '',
        '(objectClass=*)',
        [System.DirectoryServices.Protocols.SearchScope]::Base,
        [string[]]@('defaultNamingContext', 'configurationNamingContext', 'schemaNamingContext')
    )
    $response = [System.DirectoryServices.Protocols.SearchResponse](
        $Connection.SendRequest($request)
    )
    if ($response.Entries.Count -ne 1) {
        throw 'The selected domain controller did not return one RootDSE entry.'
    }
    $entry = $response.Entries[0]
    [pscustomobject]@{
        DefaultNamingContext = ConvertFrom-WindowsADAttributeValue `
            -Value $entry.Attributes['defaultNamingContext'][0]
        ConfigurationNamingContext = ConvertFrom-WindowsADAttributeValue `
            -Value $entry.Attributes['configurationNamingContext'][0]
        SchemaNamingContext = ConvertFrom-WindowsADAttributeValue `
            -Value $entry.Attributes['schemaNamingContext'][0]
    }
}
