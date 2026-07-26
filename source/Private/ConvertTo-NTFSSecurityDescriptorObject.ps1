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

    $rawDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $Security.GetSecurityDescriptorBinaryForm(),
        0
    )
    $sddl = $rawDescriptor.GetSddlForm($Sections)
    $systemAclPresent = ([int]$rawDescriptor.ControlFlags -band
        [int][System.Security.AccessControl.ControlFlags]::SystemAclPresent) -ne 0
    if (([int]$Sections -band
        [int][System.Security.AccessControl.AccessControlSections]::Audit) -ne 0 -and
        -not $rawDescriptor.SystemAcl -and -not $systemAclPresent) {
        $sddl += 'S:NO_ACCESS_CONTROL'
    }
    $result = [pscustomobject]@{
        Path                 = $Item.FullName
        ItemType             = if ($Item.PSIsContainer) { 'Directory' } else { 'File' }
        Sections             = $Sections
        Sddl                 = $sddl
        AccessRulesProtected = $Security.AreAccessRulesProtected
        AuditRulesProtected  = $Security.AreAuditRulesProtected
        AccessRulesCanonical = $Security.AreAccessRulesCanonical
        AuditRulesCanonical  = $Security.AreAuditRulesCanonical
        NativeSecurity       = $Security
    }
    $result.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.SecurityDescriptor')
    $result
}
