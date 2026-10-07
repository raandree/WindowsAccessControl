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
    $response = Send-WindowsADSearchRequest -Connection $Connection -Request $request
    if ($response.Entries.Count -ne 1) {
        throw "Active Directory object did not resolve uniquely: '$DistinguishedName'."
    }
    $entry = $response.Entries[0]
    if ($IncludeSecurityDescriptor -and (
            -not $entry.Attributes.Contains('nTSecurityDescriptor') -or
            $entry.Attributes['nTSecurityDescriptor'].Count -lt 1)) {
        # The controller omits the attribute instead of failing the search when
        # the bind lacks READ_CONTROL, so name the likely cause explicitly.
        throw [System.UnauthorizedAccessException]::new(
            "Active Directory returned no security descriptor for '$DistinguishedName'. The caller most likely lacks read-control access (READ_CONTROL, shown as Read permissions) on the object."
        )
    }
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
