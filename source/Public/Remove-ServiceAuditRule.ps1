function Remove-ServiceAuditRule {
    <#
    .SYNOPSIS
        Removes an exact audit rule from a local service or the SCM.
    .DESCRIPTION
        Accepts a path-bound service or SCM audit rule, removes the matching
        explicit SACL ACE only, and preserves every unrelated descriptor entry.
    .PARAMETER InputObject
        A path-bound rule returned by Get-ServiceAuditRule.
    .PARAMETER PassThru
        Returns the removed audit rule after successful persistence.
    .EXAMPLE
        Get-ServiceAuditRule -Name BITS -Account Everyone | Remove-ServiceAuditRule -WhatIf

        Previews exact removal of the selected BITS audit rule.
    .INPUTS
        WindowsAccessControl.ServiceAuditRule
        WindowsAccessControl.ServiceControlManagerAuditRule
    .OUTPUTS
        None
        WindowsAccessControl.ServiceAuditRule
        WindowsAccessControl.ServiceControlManagerAuditRule
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
        $validTypes = @(
            'WindowsAccessControl.ServiceAuditRule'
            'WindowsAccessControl.ServiceControlManagerAuditRule'
        )
        if (-not @($InputObject.PSObject.TypeNames | Where-Object { $_ -in $validTypes }) -or
            -not $InputObject.NativeAce) {
            throw 'InputObject must be a path-bound rule from Get-ServiceAuditRule.'
        }
        $target = if ($InputObject.ObjectType -eq 'ServiceControlManager') {
            Resolve-WindowsServiceTarget -ServiceControlManager
        } else {
            Resolve-WindowsServiceTarget -Name $InputObject.ServiceName
        }
        if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Remove exact audit rule for $($InputObject.SID)")) {
            $mutationParameters = @{
                Target    = $target
                RuleType  = 'Audit'
                Operation = 'Remove'
                NativeAce = $InputObject.NativeAce
            }
            $null = Invoke-WindowsServiceAclRuleMutation @mutationParameters
            if ($PassThru) { $InputObject }
        }
    }
}
