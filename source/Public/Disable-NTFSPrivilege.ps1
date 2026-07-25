function Disable-NTFSPrivilege {
    <#
    .SYNOPSIS
        Disables a privilege in the current process token.

    .DESCRIPTION
        Disables a Windows privilege already assigned to the current process
        token. This does not remove the privilege from the token permanently.

    .PARAMETER Name
        The Windows privilege constant name to disable in the current process.

    .PARAMETER PassThru
        Returns the enabled state after the token is changed.

    .EXAMPLE
        Disable-NTFSPrivilege -Name SeSecurityPrivilege

        Disables SACL access in the current PowerShell process token.

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
            if ($PSCmdlet.ShouldProcess('Current process token', "Disable $privilegeName")) {
                [NTFSPermission.NativeMethods]::SetPrivilege($privilegeName, $false)
                if ($PassThru) {
                    [NTFSPermission.NativeMethods]::IsPrivilegeEnabled($privilegeName)
                }
            }
        }
    }
}