function Remove-TaskFolderAccessRule {
    <#
    .SYNOPSIS
        Removes one exact access rule from a contained local task folder.
    .DESCRIPTION
        Accepts a folder-bound rule, revalidates its canonical local target and
        containment boundary, removes one exact native ACE, and preserves every
        unrelated folder descriptor entry. Removal is idempotent: an ACE that is
        already absent leaves the descriptor unchanged and succeeds.
    .PARAMETER InputObject
        A folder-bound rule returned by Get-TaskFolderAccessRule.
    .PARAMETER AllowedRootPath
        The explicit non-system folder boundary containing the write target.
    .PARAMETER PassThru
        Returns the removed rule after successful persistence.
    .EXAMPLE
        Get-TaskFolderAccessRule -Path '\Operations' -Account 'CONTOSO\Operators' |
            Remove-TaskFolderAccessRule -AllowedRootPath '\Operations' -WhatIf

        Previews exact removal of the selected local task-folder rule.
    .INPUTS
        WindowsAccessControl.TaskFolderAccessRule
    .OUTPUTS
        None
        WindowsAccessControl.TaskFolderAccessRule
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
        if ($InputObject.PSObject.TypeNames -notcontains 'WindowsAccessControl.TaskFolderAccessRule' -or
            -not $InputObject.NativeAce -or -not $InputObject.TaskPath) {
            throw 'InputObject must be a folder-bound rule from Get-TaskFolderAccessRule.'
        }
        if ($InputObject.IsInherited) {
            throw 'An inherited task-folder rule must be removed on the folder that defines it.'
        }
        $target = Resolve-WindowsTaskSchedulerTarget `
            -Path $InputObject.TaskPath `
            -ForWrite `
            -AllowedRootPath $AllowedRootPath
        if ($target.CanonicalTarget -cne $InputObject.CanonicalTarget) {
            throw 'The task-folder rule target no longer matches its canonical identity.'
        }
        if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Remove exact Task Scheduler folder access rule for $($InputObject.SID)")) {
            $null = Invoke-WindowsTaskSchedulerAclRuleMutation `
                -Target $target `
                -Operation Remove `
                -NativeAce $InputObject.NativeAce
            if ($PassThru) { $InputObject }
        }
    }
}
