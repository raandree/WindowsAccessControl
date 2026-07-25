function Get-WindowsPrivilege {
    <#
    .SYNOPSIS
        Gets privileges held by the current process token.

    .DESCRIPTION
        Returns structured information for every Windows privilege present in
        the current PowerShell process token. This command does not enable,
        disable, add, or remove privileges.

    .EXAMPLE
        Get-WindowsPrivilege | Where-Object Enabled

        Lists privileges that are currently enabled in this process.

    .INPUTS
        None

    .OUTPUTS
        WindowsAccessControl.Privilege
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    Initialize-NTFSNativeType
    foreach ($privilege in [WindowsAccessControl.NativeMethods]::GetTokenPrivileges() | Sort-Object Name) {
        $result = [pscustomobject]@{
            Name             = $privilege.Name
            Enabled          = $privilege.Enabled
            EnabledByDefault = $privilege.EnabledByDefault
            UsedForAccess    = $privilege.UsedForAccess
            Attributes       = $privilege.Attributes
        }
        $result.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.Privilege')
        $result
    }
}
