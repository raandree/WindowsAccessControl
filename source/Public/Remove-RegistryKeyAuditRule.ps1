function Remove-RegistryKeyAuditRule {
    <#
    .SYNOPSIS
        Removes an exact audit rule from a local registry key.
    .DESCRIPTION
        Accepts a path-bound registry audit rule from the pipeline, removes the
        matching explicit SACL ACE only, and preserves every unrelated ACE.
    .PARAMETER InputObject
        A path-bound rule returned by Get-RegistryKeyAuditRule.
    .PARAMETER PassThru
        Returns the removed rule after successful persistence.
    .EXAMPLE
        Get-RegistryKeyAuditRule HKCU:\Software -ExcludeInherited | Remove-RegistryKeyAuditRule -WhatIf

        Previews exact removal of each explicit pipeline audit rule.
    .INPUTS
        WindowsAccessControl.RegistryKeyAuditRule
    .OUTPUTS
        None
        WindowsAccessControl.RegistryKeyAuditRule
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
        if ($InputObject.PSObject.TypeNames -notcontains 'WindowsAccessControl.RegistryKeyAuditRule' -or
            -not $InputObject.NativeAce -or -not $InputObject.Path) {
            throw 'InputObject must be a path-bound rule from Get-RegistryKeyAuditRule.'
        }
        $view = [WindowsRegistryView]$InputObject.RegistryView
        $target = Resolve-RegistryKeyTarget -Path $InputObject.Path -RegistryView $view
        if ($PSCmdlet.ShouldProcess($target.Path, "Remove exact registry audit rule for $($InputObject.SID)")) {
            $getDescriptorParameters = @{
                NativePath       = $target.NativePath
                NativeObjectType = $target.NativeObjectType
                Sections         = [WindowsSecurityDescriptorSection]::Audit
            }
            $currentDescriptor = Get-WindowsNamedSecurityDescriptor @getDescriptorParameters
            $descriptor = $currentDescriptor
            $mutationParameters = @{
                SecurityDescriptor = $descriptor
                RuleType          = 'Audit'
                Operation         = 'Remove'
                NativeAce         = $InputObject.NativeAce
            }
            $descriptor = Invoke-WindowsAclRuleMutation @mutationParameters
            $setDescriptorParameters = @{
                NativePath         = $target.NativePath
                NativeObjectType   = $target.NativeObjectType
                Sections           = [WindowsSecurityDescriptorSection]::Audit
                SecurityDescriptor = $descriptor
                CurrentSecurityDescriptor = $currentDescriptor
            }
            Set-WindowsNamedSecurityDescriptor @setDescriptorParameters
            if ($PassThru) { $InputObject }
        }
    }
}
