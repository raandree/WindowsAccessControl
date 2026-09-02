function Enable-RegistryKeyInheritance {
    <#
    .SYNOPSIS
        Enables access or audit inheritance on local registry keys.
    .DESCRIPTION
        Removes protection from selected registry ACLs and can remove explicit
        ACEs before parent inheritance is restored through section-scoped persistence.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey pipeline objects.
    .PARAMETER SecurityDescriptor
        A WindowsAccessControl.RegistryKeySecurityDescriptor object returned by
        Get-RegistryKeySecurityDescriptor with the selected sections loaded.
        When supplied, inheritance is enabled on the descriptor in memory and
        the descriptor is returned; nothing is written until
        Set-RegistryKeySecurityDescriptor persists it.
    .PARAMETER Section
        Selects access inheritance, audit inheritance, or both ACLs.
    .PARAMETER RemoveExplicitRules
        Removes explicit rules from selected ACLs before enabling inheritance.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical targets. One requests
        deterministic sequential execution.
    .PARAMETER PassThru
        Returns the updated registry inheritance state after persistence.
    .EXAMPLE
        Enable-RegistryKeyInheritance -Path HKCU:\Software -Section Access -WhatIf

        Previews enabling DACL inheritance on the Software key.
    .INPUTS
        System.String
        Microsoft.Win32.RegistryKey
        WindowsAccessControl.RegistryKeySecurityDescriptor
    .OUTPUTS
        None
        WindowsAccessControl.RegistryKeyInheritance
        WindowsAccessControl.RegistryKeySecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'SecurityDescriptor')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Path')]
        [Alias('PSPath')]
        [object[]]$Path,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'SecurityDescriptor')]
        [PSTypeName('WindowsAccessControl.RegistryKeySecurityDescriptor')]
        [pscustomobject]$SecurityDescriptor,
        [Parameter()]
        [ValidateSet('Access', 'Audit', 'All')]
        [string]$Section = 'Access',
        [Parameter()]
        [switch]$RemoveExplicitRules,
        [Parameter()]
        [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount)),
        [Parameter()]
        [switch]$PassThru
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'SecurityDescriptor') {
            $bytes = Assert-WindowsDescriptorSection `
                -SecurityDescriptor $SecurityDescriptor `
                -RequiredSections (ConvertTo-WindowsInheritanceSection -Section $Section) `
                -TypeName 'WindowsAccessControl.RegistryKeySecurityDescriptor'
            $updatedBytes = Set-WindowsAclProtection `
                -SecurityDescriptor $bytes `
                -Section $Section `
                -Protected $false `
                -RemoveExplicitRules:$RemoveExplicitRules
            Update-WindowsSecurityDescriptorObject `
                -Descriptor $SecurityDescriptor `
                -SecurityDescriptor $updatedBytes
            $SecurityDescriptor
            return
        }

        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsRegistryCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -RegistryView $RegistryView `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact Medium
            return
        }
        foreach ($pathValue in $Path) {
            $target = Resolve-RegistryKeyTarget -Path $pathValue -RegistryView $RegistryView
            $sections = ConvertTo-WindowsInheritanceSection -Section $Section
            if ($PSCmdlet.ShouldProcess($target.Path, "Enable $Section registry inheritance")) {
                $getDescriptorParameters = @{
                    NativePath       = $target.NativePath
                    NativeObjectType = $target.NativeObjectType
                    Sections         = $sections
                }
                $bytes = Get-WindowsNamedSecurityDescriptor @getDescriptorParameters
                $protectionParameters = @{
                    SecurityDescriptor = $bytes
                    Section            = $Section
                    Protected          = $false
                    RemoveExplicitRules = $RemoveExplicitRules
                }
                $updated = Set-WindowsAclProtection @protectionParameters
                $setDescriptorParameters = @{
                    NativePath         = $target.NativePath
                    NativeObjectType   = $target.NativeObjectType
                    Sections           = $sections
                    SecurityDescriptor = $updated
                    CurrentSecurityDescriptor = $bytes
                }
                Set-WindowsNamedSecurityDescriptor @setDescriptorParameters
                if ($PassThru) {
                    $getInheritanceParameters = @{
                        Path         = $target.Path
                        Section      = $Section
                        RegistryView = $RegistryView
                    }
                    Get-RegistryKeyInheritance @getInheritanceParameters
                }
            }
        }
    }
}
