function Get-WindowsADObjectRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedName,

        [Parameter()]
        [switch]$IncludeSecurityDescriptor
    )

    $attributes = [System.Collections.Generic.List[string]]::new()
    foreach ($attributeName in 'distinguishedName', 'objectGUID', 'objectClass', 'adminCount') {
        $attributes.Add($attributeName)
    }
    if ($IncludeSecurityDescriptor) {
        $attributes.Add('nTSecurityDescriptor')
    }
    $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
        $DistinguishedName,
        '(objectClass=*)',
        [System.DirectoryServices.Protocols.SearchScope]::Base,
        $attributes.ToArray()
    )
    if ($IncludeSecurityDescriptor) {
        $null = $request.Controls.Add(
            [System.DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new(
                [System.DirectoryServices.Protocols.SecurityMasks]::Dacl
            )
        )
    }
    try {
        $response = [System.DirectoryServices.Protocols.SearchResponse](
            $Connection.SendRequest($request)
        )
    }
    catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
        if ($_.Exception.Response.ResultCode -eq
            [System.DirectoryServices.Protocols.ResultCode]::NoSuchObject) {
            throw [System.Management.Automation.ItemNotFoundException]::new(
                "Active Directory object was not found: '$DistinguishedName'."
            )
        }
        throw
    }
    if ($response.Entries.Count -ne 1) {
        throw "Active Directory object did not resolve uniquely: '$DistinguishedName'."
    }
    $entry = $response.Entries[0]
    $guidBytes = [byte[]]$entry.Attributes['objectGUID'][0]
    [pscustomobject]@{
        DistinguishedName = [string]$entry.DistinguishedName
        ObjectGuid = [guid]::new($guidBytes)
        ObjectClasses = @(
            foreach ($value in $entry.Attributes['objectClass']) {
                ConvertFrom-WindowsADAttributeValue -Value $value
            }
        )
        AdminCount = (
            $entry.Attributes.Contains('adminCount') -and
            (ConvertFrom-WindowsADAttributeValue `
                -Value $entry.Attributes['adminCount'][0]) -eq '1'
        )
        SecurityDescriptor = if ($IncludeSecurityDescriptor) {
            [byte[]]$entry.Attributes['nTSecurityDescriptor'][0]
        }
        else {
            $null
        }
    }
}
