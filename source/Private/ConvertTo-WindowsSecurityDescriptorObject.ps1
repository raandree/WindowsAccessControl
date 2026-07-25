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
    $result = [pscustomobject]@{
        ObjectType               = $Target.ObjectType
        Path                     = $Target.Path
        NativePath               = $Target.NativePath
        CanonicalTarget          = $Target.CanonicalTarget
        RegistryView             = $Target.RegistryView
        Sections                 = $Sections
        Sddl                     = $rawDescriptor.GetSddlForm($managedSections)
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
