function Test-WindowsPrivilege {
    <#
    .SYNOPSIS
        Tests whether a process token privilege is enabled.

    .DESCRIPTION
        Checks the current PowerShell process token and returns true when the
        named Windows privilege is present and enabled.

    .PARAMETER Name
        The Windows privilege constant name, such as SeSecurityPrivilege or
        SeTakeOwnershipPrivilege. Tab completion offers the well-known Windows
        privilege constants.

    .EXAMPLE
        Test-WindowsPrivilege -Name SeSecurityPrivilege

        Tests whether the current process can read and modify SACL information.

    .INPUTS
        System.String

    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidatePattern('^Se[A-Za-z0-9]+Privilege$')]
        [ArgumentCompleter([WindowsPrivilegeNameCompleter])]
        [string[]]$Name
    )

    begin {
        Initialize-WindowsAccessControlNativeType
    }

    process {
        foreach ($privilegeName in $Name) {
            [WindowsAccessControl.NativeMethods]::IsPrivilegeEnabled($privilegeName)
        }
    }
}
