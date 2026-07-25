function Get-WindowsNamedSecurityDescriptor {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [string]$NativePath,

        [Parameter(Mandatory)]
        [int]$NativeObjectType,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections
    )

    Initialize-WindowsAccessControlNativeType
    $readDescriptor = {
        param($path, $objectType, $sectionMask)

        [WindowsAccessControl.NativeMethods]::GetNamedSecurityDescriptor(
            $path,
            [uint32]$objectType,
            [uint32][int]$sectionMask
        )
    }
    $arguments = @($NativePath, $NativeObjectType, $Sections)
    if (($Sections -band [WindowsSecurityDescriptorSection]::Audit) -ne 0) {
        $privilegeParameters = @{
            Name         = 'SeSecurityPrivilege'
            ScriptBlock  = $readDescriptor
            ArgumentList = $arguments
        }
        Invoke-WithWindowsPrivilege @privilegeParameters
    } else {
        & $readDescriptor @arguments
    }
}
