function Remove-RegistryKeyAccessRule {
    <#
    .SYNOPSIS
        Removes an exact access rule from a local registry key.
    .DESCRIPTION
        Accepts a path-bound registry access rule from the pipeline, removes
        the matching explicit ACE only, and preserves every unrelated ACE.
    .PARAMETER InputObject
        A path-bound rule returned by Get-RegistryKeyAccessRule.
    .PARAMETER PassThru
        Returns the removed rule after successful persistence.
    .EXAMPLE
        Get-RegistryKeyAccessRule HKCU:\Software -ExcludeInherited | Remove-RegistryKeyAccessRule -WhatIf

        Previews exact removal of each explicit pipeline rule.
    .INPUTS
        WindowsAccessControl.RegistryKeyAccessRule
    .OUTPUTS
        None
        WindowsAccessControl.RegistryKeyAccessRule
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
        if ($InputObject.PSObject.TypeNames -notcontains 'WindowsAccessControl.RegistryKeyAccessRule' -or
            -not $InputObject.NativeAce -or -not $InputObject.Path) {
            throw 'InputObject must be a path-bound rule from Get-RegistryKeyAccessRule.'
        }
        $view = [WindowsRegistryView]$InputObject.RegistryView
        $target = Resolve-RegistryKeyTarget -Path $InputObject.Path -RegistryView $view
        if ($PSCmdlet.ShouldProcess($target.Path, "Remove exact registry access rule for $($InputObject.SID)")) {
            $getDescriptorParameters = @{
                NativePath       = $target.NativePath
                NativeObjectType = $target.NativeObjectType
                Sections         = [WindowsSecurityDescriptorSection]::Access
            }
            $currentDescriptor = Get-WindowsNamedSecurityDescriptor @getDescriptorParameters
            $descriptor = $currentDescriptor
            $mutationParameters = @{
                SecurityDescriptor = $descriptor
                RuleType          = 'Access'
                Operation         = 'Remove'
                NativeAce         = $InputObject.NativeAce
            }
            $descriptor = Invoke-WindowsAclRuleMutation @mutationParameters
            $setDescriptorParameters = @{
                NativePath         = $target.NativePath
                NativeObjectType   = $target.NativeObjectType
                Sections           = [WindowsSecurityDescriptorSection]::Access
                SecurityDescriptor = $descriptor
                CurrentSecurityDescriptor = $currentDescriptor
            }
            Set-WindowsNamedSecurityDescriptor @setDescriptorParameters
            if ($PassThru) { $InputObject }
        }
    }
}
