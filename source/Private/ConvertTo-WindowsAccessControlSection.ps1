function ConvertTo-WindowsAccessControlSection {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.AccessControlSections])]
    param(
        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections
    )

    $result = [System.Security.AccessControl.AccessControlSections]::None
    if (($Sections -band [WindowsSecurityDescriptorSection]::Owner) -ne 0) {
        $result = $result -bor [System.Security.AccessControl.AccessControlSections]::Owner
    }
    if (($Sections -band [WindowsSecurityDescriptorSection]::Group) -ne 0) {
        $result = $result -bor [System.Security.AccessControl.AccessControlSections]::Group
    }
    if (($Sections -band [WindowsSecurityDescriptorSection]::Access) -ne 0) {
        $result = $result -bor [System.Security.AccessControl.AccessControlSections]::Access
    }
    if (($Sections -band [WindowsSecurityDescriptorSection]::Audit) -ne 0) {
        $result = $result -bor [System.Security.AccessControl.AccessControlSections]::Audit
    }
    $result
}
