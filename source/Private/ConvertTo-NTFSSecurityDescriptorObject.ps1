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
        Sddl                 = $Security.GetSecurityDescriptorSddlForm($Sections)
        AccessRulesProtected = $Security.AreAccessRulesProtected
        AuditRulesProtected  = $Security.AreAuditRulesProtected
        AccessRulesCanonical = $Security.AreAccessRulesCanonical
        AuditRulesCanonical  = $Security.AreAuditRulesCanonical
        NativeSecurity       = $Security
    }
    $result.PSObject.TypeNames.Insert(0, 'NTFSPermission.SecurityDescriptor')
    $result
}