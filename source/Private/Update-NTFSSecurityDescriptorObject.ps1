function Update-NTFSSecurityDescriptorObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Updates an in-memory descriptor projection only; it never touches a target.'
    )]
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [psobject]$Descriptor,

        [Parameter()]
        [switch]$RefreshConcurrencyToken
    )

    $security = [System.Security.AccessControl.FileSystemSecurity]$Descriptor.NativeSecurity
    $sections = [System.Security.AccessControl.AccessControlSections]$Descriptor.Sections
    $rawDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $security.GetSecurityDescriptorBinaryForm(),
        0
    )
    $sddl = $rawDescriptor.GetSddlForm($sections)
    $systemAclPresent = ([int]$rawDescriptor.ControlFlags -band
        [int][System.Security.AccessControl.ControlFlags]::SystemAclPresent) -ne 0
    if (([int]$sections -band
        [int][System.Security.AccessControl.AccessControlSections]::Audit) -ne 0 -and
        -not $rawDescriptor.SystemAcl -and -not $systemAclPresent) {
        $sddl += 'S:NO_ACCESS_CONTROL'
    }

    $projection = [ordered]@{
        Sddl                 = $sddl
        AccessRulesProtected = $security.AreAccessRulesProtected
        AuditRulesProtected  = $security.AreAuditRulesProtected
        AccessRulesCanonical = $security.AreAccessRulesCanonical
        AuditRulesCanonical  = $security.AreAuditRulesCanonical
    }
    if ($RefreshConcurrencyToken) {
        $projection.ConcurrencyToken =
            Get-WindowsSecurityDescriptorConcurrencyToken -Sddl $sddl
    }

    # Add-Member keeps a caller-supplied descriptor that lacks a projection
    # member from failing after its target was already written.
    foreach ($name in $projection.Keys) {
        $Descriptor | Add-Member `
            -NotePropertyName $name `
            -NotePropertyValue $projection[$name] `
            -Force
    }
}
