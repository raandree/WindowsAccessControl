function Remove-ScheduledTaskAccessRule {
    <#
    .SYNOPSIS
        Removes one exact access rule from a contained local registered task.
    .DESCRIPTION
        Accepts a task-bound rule, revalidates its canonical local target and
        containment boundary, removes one exact native ACE, and preserves every
        unrelated task descriptor entry. Removal is idempotent: an ACE that is
        already absent leaves the descriptor unchanged and succeeds.
    .PARAMETER InputObject
        A task-bound rule returned by Get-ScheduledTaskAccessRule.
    .PARAMETER AllowedRootPath
        The explicit non-system folder boundary containing the write target.
    .PARAMETER PassThru
        Returns the removed rule after successful persistence.
    .EXAMPLE
        Get-ScheduledTaskAccessRule -TaskPath '\Operations' -TaskName 'Cleanup' -ExcludeInherited |
            Remove-ScheduledTaskAccessRule -AllowedRootPath '\Operations' -WhatIf

        Previews exact removal of the selected local registered-task rule.
    .INPUTS
        WindowsAccessControl.ScheduledTaskAccessRule
    .OUTPUTS
        None
        WindowsAccessControl.ScheduledTaskAccessRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [psobject]$InputObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AllowedRootPath,

        [Parameter()]
        [switch]$PassThru
    )

    process {
        if ($InputObject.PSObject.TypeNames -notcontains 'WindowsAccessControl.ScheduledTaskAccessRule' -or
            -not $InputObject.NativeAce -or -not $InputObject.TaskPath -or
            -not $InputObject.TaskName) {
            throw 'InputObject must be a task-bound rule from Get-ScheduledTaskAccessRule.'
        }
        if ($InputObject.IsInherited) {
            throw 'An inherited registered-task rule must be removed on the folder that defines it.'
        }
        $target = Resolve-WindowsTaskSchedulerTarget `
            -Path $InputObject.TaskPath `
            -TaskName $InputObject.TaskName `
            -ForWrite `
            -AllowedRootPath $AllowedRootPath
        if ($target.CanonicalTarget -cne $InputObject.CanonicalTarget) {
            throw 'The registered-task rule target no longer matches its canonical identity.'
        }
        if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Remove exact registered-task access rule for $($InputObject.SID)")) {
            $null = Invoke-WindowsTaskSchedulerAclRuleMutation `
                -Target $target `
                -Operation Remove `
                -NativeAce $InputObject.NativeAce
            if ($PassThru) { $InputObject }
        }
    }
}
