function Get-NTFSSecurityDescriptorForItem {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.FileSystemSecurity])]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileSystemInfo]$Item,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.AccessControlSections]$Sections
    )

    $getAclParameters = @{
        LiteralPath = $Item.FullName
        ErrorAction = 'Stop'
    }
    if (($Sections -band [System.Security.AccessControl.AccessControlSections]::Audit) -ne 0) {
        $getAclParameters.Audit = $true
    }
    $readDescriptor = {
        param($parameters)

        Get-Acl @parameters
    }
    $readArguments = ,$getAclParameters
    if (($Sections -band [System.Security.AccessControl.AccessControlSections]::Audit) -ne 0) {
        $privilegeParameters = @{
            Name         = 'SeSecurityPrivilege'
            ScriptBlock  = $readDescriptor
            ArgumentList = $readArguments
        }
        Invoke-WithWindowsPrivilege @privilegeParameters
    } else {
        & $readDescriptor @readArguments
    }
}
