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
    Get-Acl @getAclParameters
}