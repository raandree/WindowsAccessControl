function Remove-ServiceAccessRule {
    <#
    .SYNOPSIS
        Removes an exact access rule from a local service or the SCM.
    .DESCRIPTION
        Accepts a path-bound service or SCM access rule, removes the matching
        explicit ACE only, and preserves every unrelated descriptor entry.
    .PARAMETER InputObject
        A path-bound rule returned by Get-ServiceAccessRule.
    .PARAMETER PassThru
        Returns the removed rule after successful persistence.
    .EXAMPLE
        Get-ServiceAccessRule -Name BITS -Account Everyone | Remove-ServiceAccessRule -WhatIf

        Previews exact removal of the selected BITS access rule.
    .INPUTS
        WindowsAccessControl.ServiceAccessRule
        WindowsAccessControl.ServiceControlManagerAccessRule
    .OUTPUTS
        None
        WindowsAccessControl.ServiceAccessRule
        WindowsAccessControl.ServiceControlManagerAccessRule
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
            'WindowsAccessControl.ServiceAccessRule'
            'WindowsAccessControl.ServiceControlManagerAccessRule'
        )
        if (-not @($InputObject.PSObject.TypeNames | Where-Object { $_ -in $validTypes }) -or
            -not $InputObject.NativeAce) {
            throw 'InputObject must be a path-bound rule from Get-ServiceAccessRule.'
        }
        $target = if ($InputObject.ObjectType -eq 'ServiceControlManager') {
            Resolve-WindowsServiceTarget -ServiceControlManager
        } else {
            Resolve-WindowsServiceTarget -Name $InputObject.ServiceName
        }
        if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Remove exact access rule for $($InputObject.SID)")) {
            $mutationParameters = @{
                Target    = $target
                RuleType  = 'Access'
                Operation = 'Remove'
                NativeAce = $InputObject.NativeAce
            }
            $null = Invoke-WindowsServiceAclRuleMutation @mutationParameters
            if ($PassThru) { $InputObject }
        }
    }
}
