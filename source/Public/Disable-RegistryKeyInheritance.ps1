function Disable-RegistryKeyInheritance {
    <#
    .SYNOPSIS
        Disables access or audit inheritance on local registry keys.
    .DESCRIPTION
        Protects selected registry ACLs from parent changes and preserves
        inherited ACEs as explicit entries by default before section-scoped persistence.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey pipeline objects.
    .PARAMETER SecurityDescriptor
        A WindowsAccessControl.RegistryKeySecurityDescriptor object returned by
        Get-RegistryKeySecurityDescriptor with the selected sections loaded.
        When supplied, inheritance is disabled on the descriptor in memory and
        the descriptor is returned; nothing is written until
        Set-RegistryKeySecurityDescriptor persists it.
    .PARAMETER Section
        Selects access inheritance, audit inheritance, or both ACLs.
    .PARAMETER PreserveInherited
        Converts inherited ACEs to explicit entries when true or discards them when false.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical targets. One requests
        deterministic sequential execution.
    .PARAMETER PassThru
        Returns the updated registry inheritance state after persistence.
    .EXAMPLE
        Disable-RegistryKeyInheritance -Path HKCU:\Software -Section Access -WhatIf

        Previews protecting the Software key DACL.
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
        [bool]$PreserveInherited = $true,
        [Parameter()]
        [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(
            1,
            [Math]::Min(8, [Environment]::ProcessorCount)
        ),
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
                -Protected $true `
                -PreserveInherited $PreserveInherited
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
            if ($PSCmdlet.ShouldProcess($target.Path, "Disable $Section registry inheritance")) {
                $getDescriptorParameters = @{
                    NativePath       = $target.NativePath
                    NativeObjectType = $target.NativeObjectType
                    Sections         = $sections
                }
                $bytes = Get-WindowsNamedSecurityDescriptor @getDescriptorParameters
                $protectionParameters = @{
                    SecurityDescriptor = $bytes
                    Section            = $Section
                    Protected          = $true
                    PreserveInherited  = $PreserveInherited
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
