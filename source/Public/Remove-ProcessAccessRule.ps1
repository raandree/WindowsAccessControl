function Remove-ProcessAccessRule {
    <#
    .SYNOPSIS
        Removes an exact access rule from a pinned live process.
    .DESCRIPTION
        Accepts a path-bound process access rule, revalidates its process
        instance, removes the matching explicit ACE only, and preserves others.
    .PARAMETER InputObject
        A path-bound rule returned by Get-ProcessAccessRule.
    .PARAMETER PassThru
        Returns the removed rule after successful persistence.
    .EXAMPLE
        Get-ProcessAccessRule -ProcessId $PID -Account Everyone | Remove-ProcessAccessRule -WhatIf

        Previews exact removal of the selected current-process rule.
    .INPUTS
        WindowsAccessControl.ProcessAccessRule
    .OUTPUTS
        None
        WindowsAccessControl.ProcessAccessRule
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
        if ($InputObject.PSObject.TypeNames -notcontains 'WindowsAccessControl.ProcessAccessRule' -or
            -not $InputObject.NativeAce) {
            throw 'InputObject must be a path-bound rule from Get-ProcessAccessRule.'
        }
        $target = Resolve-WindowsProcessTarget -InputObject $InputObject
        if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Remove exact process access rule for $($InputObject.SID)")) {
            $parameters = @{
                Target    = $target
                RuleType  = 'Access'
                Operation = 'Remove'
                NativeAce = $InputObject.NativeAce
            }
            Invoke-WindowsProcessAclRuleMutation @parameters
            if ($PassThru) { $InputObject }
        }
    }
}
