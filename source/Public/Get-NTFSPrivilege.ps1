function Get-NTFSPrivilege {
    <#
    .SYNOPSIS
        Gets privileges held by the current process token.

    .DESCRIPTION
        Returns structured information for every Windows privilege present in
        the current PowerShell process token. This command does not enable,
        disable, add, or remove privileges.

    .EXAMPLE
        Get-NTFSPrivilege | Where-Object Enabled

        Lists privileges that are currently enabled in this process.

    .INPUTS
        None

    .OUTPUTS
        NTFSPermission.Privilege
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    Initialize-NTFSNativeType
    foreach ($privilege in [NTFSPermission.NativeMethods]::GetTokenPrivileges() | Sort-Object Name) {
        $result = [pscustomobject]@{
            Name             = $privilege.Name
            Enabled          = $privilege.Enabled
            EnabledByDefault = $privilege.EnabledByDefault
            UsedForAccess    = $privilege.UsedForAccess
            Attributes       = $privilege.Attributes
        }
        $result.PSObject.TypeNames.Insert(0, 'NTFSPermission.Privilege')
        $result
    }
}
