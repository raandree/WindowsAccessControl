function Get-RegistryKeySecurityDescriptor {
    <#
    .SYNOPSIS
        Gets selected security descriptor sections from local registry keys.
    .DESCRIPTION
        Resolves local registry provider or native key paths, reads only the
        selected owner, group, DACL, or SACL sections, and emits portable SDDL
        with the original binary descriptor.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey objects supplied
        directly or through the pipeline.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .PARAMETER Sections
        Selects owner, group, access, audit, or any combination to retrieve.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical targets. One requests
        deterministic sequential execution.
    .EXAMPLE
        Get-Item HKCU:\Software | Get-RegistryKeySecurityDescriptor

        Gets all security descriptor sections for the Software key.
    .INPUTS
        System.String
        Microsoft.Win32.RegistryKey
    .OUTPUTS
        WindowsAccessControl.RegistryKeySecurityDescriptor
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('PSPath')]
        [object[]]$Path,

        [Parameter()]
        [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,

        [Parameter()]
        [WindowsSecurityDescriptorSection]$Sections =
            [WindowsSecurityDescriptorSection]::All,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(
            1,
            [Math]::Min(8, [Environment]::ProcessorCount)
        )
    )

    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsRegistryCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -RegistryView $RegistryView `
                -ThrottleLimit $ThrottleLimit
            return
        }
        foreach ($pathValue in $Path) {
            $target = Resolve-RegistryKeyTarget -Path $pathValue -RegistryView $RegistryView
            $descriptorParameters = @{
                NativePath       = $target.NativePath
                NativeObjectType = $target.NativeObjectType
                Sections         = $Sections
            }
            $descriptor = Get-WindowsNamedSecurityDescriptor @descriptorParameters
            $conversionParameters = @{
                Target             = $target
                Sections           = $Sections
                SecurityDescriptor = $descriptor
                TypeName           = 'WindowsAccessControl.RegistryKeySecurityDescriptor'
            }
            ConvertTo-WindowsSecurityDescriptorObject @conversionParameters
        }
    }
}
