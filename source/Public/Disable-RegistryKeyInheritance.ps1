function Disable-RegistryKeyInheritance {
    <#
    .SYNOPSIS
        Disables access or audit inheritance on local registry keys.
    .DESCRIPTION
        Protects selected registry ACLs from parent changes and preserves
        inherited ACEs as explicit entries by default before section-scoped persistence.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey pipeline objects.
    .PARAMETER Section
        Selects access inheritance, audit inheritance, or both ACLs.
    .PARAMETER PreserveInherited
        Converts inherited ACEs to explicit entries when true or discards them when false.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .PARAMETER PassThru
        Returns the updated registry inheritance state after persistence.
    .EXAMPLE
        Disable-RegistryKeyInheritance -Path HKCU:\Software -Section Access -WhatIf

        Previews protecting the Software key DACL.
    .INPUTS
        System.String
        Microsoft.Win32.RegistryKey
    .OUTPUTS
        None
        WindowsAccessControl.RegistryKeyInheritance
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('PSPath')]
        [object[]]$Path,
        [Parameter()]
        [ValidateSet('Access', 'Audit', 'All')]
        [string]$Section = 'Access',
        [Parameter()]
        [bool]$PreserveInherited = $true,
        [Parameter()]
        [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,
        [Parameter()]
        [switch]$PassThru
    )

    process {
        foreach ($pathValue in $Path) {
            $target = Resolve-RegistryKeyTarget -Path $pathValue -RegistryView $RegistryView
            $sections = switch ($Section) {
                Access { [WindowsSecurityDescriptorSection]::Access }
                Audit { [WindowsSecurityDescriptorSection]::Audit }
                All { [WindowsSecurityDescriptorSection]::Access -bor [WindowsSecurityDescriptorSection]::Audit }
            }
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
