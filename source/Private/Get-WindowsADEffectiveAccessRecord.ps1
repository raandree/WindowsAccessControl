function Get-WindowsADEffectiveAccessRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedName
    )

    # Constructed attributes are evaluated per request in the security context of
    # the bind, and a wildcard attribute request never returns them.
    $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
        $DistinguishedName,
        '(objectClass=*)',
        [System.DirectoryServices.Protocols.SearchScope]::Base,
        [string[]]@(
            'allowedAttributesEffective'
            'allowedChildClassesEffective'
            'sDRightsEffective'
        )
    )
    $response = [System.DirectoryServices.Protocols.SearchResponse](
        $Connection.SendRequest($request)
    )
    if ($response.Entries.Count -ne 1) {
        throw "Active Directory object did not resolve uniquely: '$DistinguishedName'."
    }
    $entry = $response.Entries[0]
    $values = @{}
    foreach ($attributeName in 'allowedAttributesEffective',
        'allowedChildClassesEffective',
        'sDRightsEffective') {
        $values[$attributeName] = @(
            if ($entry.Attributes.Contains($attributeName)) {
                foreach ($value in $entry.Attributes[$attributeName]) {
                    ConvertFrom-WindowsADAttributeValue -Value $value
                }
            }
        )
    }
    [pscustomobject]@{
        WritableAttribute = $values['allowedAttributesEffective']
        CreatableChildClass = $values['allowedChildClassesEffective']
        # LDAP cannot return an empty attribute, so a controller that grants no
        # descriptor section omits the attribute rather than returning zero.
        SDRightsEffective = if ($values['sDRightsEffective'].Count -gt 0) {
            [int]$values['sDRightsEffective'][0]
        }
        else { 0 }
    }
}
