function ConvertTo-NTFSSecurityDescriptorObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileSystemInfo]$Item,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemSecurity]$Security,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.AccessControlSections]$Sections
    )

    $result = [pscustomobject]@{
        Path                 = $Item.FullName
        ItemType             = if ($Item.PSIsContainer) { 'Directory' } else { 'File' }
        Sections             = $Sections
        Sddl                 = $null
        AccessRulesProtected = $false
        AuditRulesProtected  = $false
        AccessRulesCanonical = $false
        AuditRulesCanonical  = $false
        ConcurrencyToken     = $null
        NativeSecurity       = $Security
    }
    Update-NTFSSecurityDescriptorObject `
        -Descriptor $result `
        -RefreshConcurrencyToken
    $result.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.SecurityDescriptor')
    $result
}
