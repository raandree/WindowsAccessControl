function Enable-NTFSPrivilege {
    <#
    .SYNOPSIS
        Enables a privilege in the current process token.

    .DESCRIPTION
        Enables a Windows privilege already assigned to the current process
        token. The command cannot add privileges that the token does not hold.

    .PARAMETER Name
        The Windows privilege constant name to enable in the current process.

    .PARAMETER PassThru
        Returns the enabled state after the token is changed.

    .EXAMPLE
        Enable-NTFSPrivilege -Name SeSecurityPrivilege

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
        [string[]]$Name,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        Initialize-NTFSNativeType
    }

    process {
        foreach ($privilegeName in $Name) {
            if ($PSCmdlet.ShouldProcess('Current process token', "Enable $privilegeName")) {
                [NTFSPermission.NativeMethods]::SetPrivilege($privilegeName, $true)
                if ($PassThru) {
                    [NTFSPermission.NativeMethods]::IsPrivilegeEnabled($privilegeName)
                }
            }
        }
    }
}