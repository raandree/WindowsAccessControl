function ConvertTo-WindowsSecurityDescriptorObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections,

        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor,

        [Parameter(Mandatory)]
        [string]$TypeName
    )

    $rawDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $SecurityDescriptor,
        0
    )
    $managedSections = ConvertTo-WindowsAccessControlSection -Sections $Sections
    $sddl = $rawDescriptor.GetSddlForm($managedSections)
    $systemAclPresent = ([int]$rawDescriptor.ControlFlags -band
        [int][System.Security.AccessControl.ControlFlags]::SystemAclPresent) -ne 0
    if (($Sections -band [WindowsSecurityDescriptorSection]::Audit) -ne 0 -and
        -not $rawDescriptor.SystemAcl -and -not $systemAclPresent) {
        $sddl += 'S:NO_ACCESS_CONTROL'
    }
    $result = [pscustomobject]@{
        ObjectType               = $Target.ObjectType
        Path                     = $Target.Path
        ServiceName              = $Target.ServiceName
        ProcessId                = $Target.ProcessId
        ProcessName              = $Target.ProcessName
        CreationTime             = $Target.CreationTime
        CreationTimeFileTime     = $Target.CreationTimeFileTime
        Handle                   = if ($Target.DescriptorSource -eq 'Handle') {
            $Target.Handle
        } else {
            [IntPtr]::Zero
        }
        NativePath               = $Target.NativePath
        CanonicalTarget          = $Target.CanonicalTarget
        RegistryView             = $Target.RegistryView
        Sections                 = $Sections
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
    $result.PSObject.TypeNames.Insert(0, $TypeName)
    $result.PSObject.TypeNames.Add('WindowsAccessControl.SecurityDescriptor')
    $result
}
