function Invoke-WindowsAccessControl {
    <#
    .SYNOPSIS
        Runs Windows access-control operations as an explicit local identity.

    .DESCRIPTION
        Logs on the supplied Windows identity for a local interactive session,
        executes the script block under that identity, and restores the caller
        identity before returning. The credential does not enable remote target
        syntax and its password is never written to module output or logs.

    .PARAMETER Credential
        Supplies the Windows identity used only for this local impersonation
        scope. Domain-qualified, local, and user principal names are accepted.

    .PARAMETER ScriptBlock
        Specifies one or more local WindowsAccessControl operations to execute
        while the supplied Windows identity is impersonated.

    .PARAMETER ArgumentList
        Supplies positional values passed to the impersonated script block.
        Use an empty array when the script block does not declare parameters.

    .EXAMPLE
        Invoke-WindowsAccessControl -Credential $credential -ScriptBlock {
            Get-NTFSAccessRule -LiteralPath 'C:\Data'
        }

        Reads the local path while impersonating the supplied Windows identity.

    .INPUTS
        None

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscredential]$Credential,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$ArgumentList = @()
    )

    Invoke-WithWindowsImpersonation @PSBoundParameters
}
