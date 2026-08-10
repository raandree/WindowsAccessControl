function Enable-WindowsPrivilege {
    <#
    .SYNOPSIS
        Enables a privilege in the current process token.

    .DESCRIPTION
        Enables a Windows privilege already assigned to the current process
        token. The command cannot add privileges that the token does not hold.

    .PARAMETER Name
        The Windows privilege constant name to enable in the current process.
        Tab completion offers the well-known Windows privilege constants.

    .PARAMETER PassThru
        Returns the enabled state after the token is changed.

    .EXAMPLE
        Enable-WindowsPrivilege -Name SeSecurityPrivilege

        Enables SACL access for later audit-rule commands when the token holds it.

    .INPUTS
        System.String

    .OUTPUTS
        None
        System.Boolean
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidatePattern('^Se[A-Za-z0-9]+Privilege$')]
        [ArgumentCompleter([WindowsPrivilegeNameCompleter])]
        [string[]]$Name,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        Initialize-WindowsAccessControlNativeType
    }

    process {
        foreach ($privilegeName in $Name) {
            if ($PSCmdlet.ShouldProcess('Current process token', "Enable $privilegeName")) {
                [WindowsAccessControl.NativeMethods]::SetPrivilege($privilegeName, $true)
                if ($PassThru) {
                    [WindowsAccessControl.NativeMethods]::IsPrivilegeEnabled($privilegeName)
                }
            }
        }
    }
}
