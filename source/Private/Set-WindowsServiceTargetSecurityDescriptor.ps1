function Set-WindowsServiceTargetSecurityDescriptor {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Public service commands enforce ShouldProcess before this boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections,

        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor,

        [Parameter()]
        [byte[]]$CurrentSecurityDescriptor
    )

    if ($Target.DescriptorSource -eq 'Named') {
        $parameters = @{
            NativePath                = $Target.NativePath
            NativeObjectType          = $Target.NativeObjectType
            Sections                  = $Sections
            SecurityDescriptor        = $SecurityDescriptor
            CurrentSecurityDescriptor = $CurrentSecurityDescriptor
        }
        Set-WindowsNamedSecurityDescriptor @parameters
        return
    }

    $managedSections = ConvertTo-WindowsAccessControlSection -Sections $Sections
    if ($CurrentSecurityDescriptor) {
        $current = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            $CurrentSecurityDescriptor,
            0
        )
        $requested = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            $SecurityDescriptor,
            0
        )
        if ($current.GetSddlForm($managedSections) -ceq
            $requested.GetSddlForm($managedSections)) {
            return
        }
    }

    Initialize-WindowsAccessControlNativeType
    $writeDescriptor = {
        param($sectionMask, $descriptor)

        [WindowsAccessControl.NativeMethods]::SetServiceControlManagerSecurityDescriptor(
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
    $arguments.Add($Sections)
    $arguments.Add($SecurityDescriptor)
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
