function Set-WindowsNamedSecurityDescriptor {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Public callers enforce ShouldProcess before this persistence boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$NativePath,

        [Parameter(Mandatory)]
        [int]$NativeObjectType,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections,

        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor,

        [Parameter()]
        [byte[]]$CurrentSecurityDescriptor
    )

    Initialize-WindowsAccessControlNativeType
    $managedSections = ConvertTo-WindowsAccessControlSection -Sections $Sections
    $writeDescriptor = {
        param(
            $path,
            $objectType,
            $sectionMask,
            $descriptor,
            $currentDescriptorBytes,
            $selectedSections
        )

        $currentBytes = if ($currentDescriptorBytes) {
            $currentDescriptorBytes
        } else {
            [WindowsAccessControl.NativeMethods]::GetNamedSecurityDescriptor(
                $path,
                [uint32]$objectType,
                [uint32][int]$sectionMask
            )
        }
        $currentDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            $currentBytes,
            0
        )
        $requestedDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            $descriptor,
            0
        )
        if ($currentDescriptor.GetSddlForm($selectedSections) -ceq
            $requestedDescriptor.GetSddlForm($selectedSections)) {
            return
        }

        [WindowsAccessControl.NativeMethods]::SetNamedSecurityDescriptor(
            $path,
            [uint32]$objectType,
            [uint32][int]$sectionMask,
            $descriptor
        )
    }
    $requiredPrivileges = [System.Collections.Generic.List[string]]::new()
    if (($Sections -band [WindowsSecurityDescriptorSection]::Audit) -ne 0) {
        $requiredPrivileges.Add('SeSecurityPrivilege')
    }
    if (($Sections -band (
        [WindowsSecurityDescriptorSection]::Owner -bor
        [WindowsSecurityDescriptorSection]::Group
    )) -ne 0) {
        $privilegeNames = @(
            [WindowsAccessControl.NativeMethods]::GetTokenPrivileges()
        ).Name
        if ('SeRestorePrivilege' -in $privilegeNames) {
            $requiredPrivileges.Add('SeRestorePrivilege')
        }
    }
    $arguments = [System.Collections.Generic.List[object]]::new()
    $arguments.Add($NativePath)
    $arguments.Add($NativeObjectType)
    $arguments.Add($Sections)
    $arguments.Add($SecurityDescriptor)
    $arguments.Add($CurrentSecurityDescriptor)
    $arguments.Add($managedSections)
    $argumentList = $arguments.ToArray()
    if ($requiredPrivileges.Count -gt 0) {
        $privilegeParameters = @{
            Name         = $requiredPrivileges.ToArray()
            ScriptBlock  = $writeDescriptor
            ArgumentList = $argumentList
        }
        Invoke-WithWindowsPrivilege @privilegeParameters
    } else {
        & $writeDescriptor @argumentList
    }
}
