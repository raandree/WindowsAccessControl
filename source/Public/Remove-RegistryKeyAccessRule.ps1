function Remove-RegistryKeyAccessRule {
    <#
    .SYNOPSIS
        Removes an exact access rule from a local registry key.
    .DESCRIPTION
        Accepts a path-bound registry access rule from the pipeline, removes
        the matching explicit ACE only, and preserves every unrelated ACE.
    .PARAMETER InputObject
        A path-bound rule returned by Get-RegistryKeyAccessRule.
    .PARAMETER SecurityDescriptor
        A WindowsAccessControl.RegistryKeySecurityDescriptor object returned by
        Get-RegistryKeySecurityDescriptor. When supplied, the removal is staged
        on the descriptor in memory and the descriptor is returned; nothing is
        written until Set-RegistryKeySecurityDescriptor persists it.
    .PARAMETER Rule
        The rule returned by Get-RegistryKeyAccessRule whose exact ACE is
        removed from the supplied descriptor.
    .PARAMETER PassThru
        Returns the removed rule after successful persistence.
    .EXAMPLE
        Get-RegistryKeyAccessRule HKCU:\Software -ExcludeInherited | Remove-RegistryKeyAccessRule -WhatIf

        Previews exact removal of each explicit pipeline rule.
    .INPUTS
        WindowsAccessControl.RegistryKeyAccessRule
        WindowsAccessControl.RegistryKeySecurityDescriptor
    .OUTPUTS
        None
        WindowsAccessControl.RegistryKeyAccessRule
        WindowsAccessControl.RegistryKeySecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Rule')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Rule')]
        [ValidateNotNull()]
        [psobject]$InputObject,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'SecurityDescriptor')]
        [PSTypeName('WindowsAccessControl.RegistryKeySecurityDescriptor')]
        [pscustomobject]$SecurityDescriptor,
        [Parameter(Mandatory, ParameterSetName = 'SecurityDescriptor')]
        [ValidateNotNull()]
        [psobject]$Rule,
        [Parameter()]
        [switch]$PassThru
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'SecurityDescriptor') {
            if ($Rule.PSObject.TypeNames -notcontains 'WindowsAccessControl.RegistryKeyAccessRule' -or
                -not $Rule.NativeAce) {
                throw 'Rule must be a rule returned by Get-RegistryKeyAccessRule.'
            }
            $bytes = Assert-WindowsDescriptorSection `
                -SecurityDescriptor $SecurityDescriptor `
                -RequiredSections Access `
                -TypeName 'WindowsAccessControl.RegistryKeySecurityDescriptor'
            $bytes = Invoke-WindowsAclRuleMutation `
                -SecurityDescriptor $bytes `
                -RuleType 'Access' `
                -Operation 'Remove' `
                -NativeAce $Rule.NativeAce
            Update-WindowsSecurityDescriptorObject `
                -Descriptor $SecurityDescriptor `
                -SecurityDescriptor $bytes
            $SecurityDescriptor
            return
        }

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
