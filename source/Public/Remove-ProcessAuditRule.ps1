function Remove-ProcessAuditRule {
    <#
    .SYNOPSIS
        Removes an exact audit rule from a pinned live process.
    .DESCRIPTION
        Accepts a path-bound process audit rule, revalidates its instance,
        removes the matching explicit SACL ACE only, and preserves unrelated entries.
    .PARAMETER InputObject
        A path-bound rule returned by Get-ProcessAuditRule.
    .PARAMETER PassThru
        Returns the removed audit rule after successful persistence.
    .EXAMPLE
        Get-ProcessAuditRule -ProcessId $PID -Account Everyone | Remove-ProcessAuditRule -WhatIf

        Previews exact removal of the selected current-process audit rule.
    .INPUTS
        WindowsAccessControl.ProcessAuditRule
    .OUTPUTS
        None
        WindowsAccessControl.ProcessAuditRule
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
        if ($InputObject.PSObject.TypeNames -notcontains 'WindowsAccessControl.ProcessAuditRule' -or
            -not $InputObject.NativeAce) {
            throw 'InputObject must be a path-bound rule from Get-ProcessAuditRule.'
        }
        $target = Resolve-WindowsProcessTarget -InputObject $InputObject
        if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Remove exact process audit rule for $($InputObject.SID)")) {
            $parameters = @{
                Target    = $target
                RuleType  = 'Audit'
                Operation = 'Remove'
                NativeAce = $InputObject.NativeAce
            }
            Invoke-WindowsProcessAclRuleMutation @parameters
            if ($PassThru) { $InputObject }
        }
    }
}
