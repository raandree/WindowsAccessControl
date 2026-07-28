function Remove-SmbShareAccessRule {
    <#
    .SYNOPSIS
        Removes one exact access rule from a local SMB share.
    .DESCRIPTION
        Accepts a path-bound share rule, validates its local target, removes one
        exact native ACE, and preserves every unrelated share descriptor entry.
    .PARAMETER InputObject
        A path-bound rule returned by Get-SmbShareAccessRule.
    .PARAMETER PassThru
        Returns the removed rule after successful persistence.
    .EXAMPLE
        Get-SmbShareAccessRule -Name 'Data$' -Account Everyone | Remove-SmbShareAccessRule -WhatIf

        Previews exact removal of the selected local share rule.
    .INPUTS
        WindowsAccessControl.SmbShareAccessRule
    .OUTPUTS
        None
        WindowsAccessControl.SmbShareAccessRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [psobject]$InputObject,

        [Parameter()]
        [switch]$PassThru
    )

    process {
        if ($InputObject.PSObject.TypeNames -notcontains 'WindowsAccessControl.SmbShareAccessRule' -or
            -not $InputObject.NativeAce -or -not $InputObject.ShareName) {
            throw 'InputObject must be a path-bound rule from Get-SmbShareAccessRule.'
        }
        $target = Resolve-WindowsSmbShareTarget -Name $InputObject.ShareName
        if ($target.CanonicalTarget -cne $InputObject.CanonicalTarget) {
            throw 'The SMB share rule target no longer matches its canonical identity.'
        }
        if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Remove exact SMB share access rule for $($InputObject.SID)")) {
            $null = Invoke-WindowsSmbShareAclRuleMutation `
                -Target $target `
                -Operation Remove `
                -NativeAce $InputObject.NativeAce
            if ($PassThru) { $InputObject }
        }
    }
}
