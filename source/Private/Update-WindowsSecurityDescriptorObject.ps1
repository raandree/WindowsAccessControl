function Update-WindowsSecurityDescriptorObject {
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

        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor,

        [Parameter()]
        [switch]$RefreshConcurrencyToken
    )

    $rawDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $SecurityDescriptor,
        0
    )
    $sections = [WindowsSecurityDescriptorSection]$Descriptor.Sections
    $managedSections = ConvertTo-WindowsAccessControlSection -Sections $sections
    $sddl = $rawDescriptor.GetSddlForm($managedSections)
    $systemAclPresent = ([int]$rawDescriptor.ControlFlags -band
        [int][System.Security.AccessControl.ControlFlags]::SystemAclPresent) -ne 0
    if (($sections -band [WindowsSecurityDescriptorSection]::Audit) -ne 0 -and
        -not $rawDescriptor.SystemAcl -and -not $systemAclPresent) {
        $sddl += 'S:NO_ACCESS_CONTROL'
    }

    $projection = [ordered]@{
        Sddl                     = $sddl
        OwnerSID                 = if ($rawDescriptor.Owner) { $rawDescriptor.Owner.Value } else { $null }
        GroupSID                 = if ($rawDescriptor.Group) { $rawDescriptor.Group.Value } else { $null }
        AccessRulesProtected     = ([int]$rawDescriptor.ControlFlags -band (
            [int][System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
        )) -ne 0
        AuditRulesProtected      = ([int]$rawDescriptor.ControlFlags -band (
            [int][System.Security.AccessControl.ControlFlags]::SystemAclProtected
        )) -ne 0
        BinarySecurityDescriptor = $SecurityDescriptor
        NativeDescriptor         = $rawDescriptor
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
