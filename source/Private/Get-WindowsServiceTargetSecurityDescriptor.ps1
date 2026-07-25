function Get-WindowsServiceTargetSecurityDescriptor {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections
    )

    if ($Target.DescriptorSource -eq 'Named') {
        $parameters = @{
            NativePath       = $Target.NativePath
            NativeObjectType = $Target.NativeObjectType
            Sections         = $Sections
        }
        return Get-WindowsNamedSecurityDescriptor @parameters
    }

    Initialize-WindowsAccessControlNativeType
    $readDescriptor = {
        param($sectionMask)

        [WindowsAccessControl.NativeMethods]::GetServiceControlManagerSecurityDescriptor(
            [uint32][int]$sectionMask
        )
    }
    if (($Sections -band [WindowsSecurityDescriptorSection]::Audit) -ne 0) {
        $privilegeParameters = @{
            Name         = 'SeSecurityPrivilege'
            ScriptBlock  = $readDescriptor
            ArgumentList = @($Sections)
        }
        Invoke-WithWindowsPrivilege @privilegeParameters
    } else {
        & $readDescriptor $Sections
    }
}
