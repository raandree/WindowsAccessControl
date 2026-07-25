function Get-RegistryKeyInheritance {
    <#
    .SYNOPSIS
        Gets access or audit inheritance state for local registry keys.
    .DESCRIPTION
        Reads selected registry ACL control flags and reports whether access or
        audit inheritance is enabled without changing descriptor state.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey pipeline objects.
    .PARAMETER Section
        Selects access inheritance, audit inheritance, or both ACLs.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .EXAMPLE
        Get-RegistryKeyInheritance -Path HKCU:\Software -Section All

        Gets access and audit inheritance state for the Software key.
    .INPUTS
        System.String
        Microsoft.Win32.RegistryKey
    .OUTPUTS
        WindowsAccessControl.RegistryKeyInheritance
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('PSPath')]
        [object[]]$Path,
        [Parameter()]
        [ValidateSet('Access', 'Audit', 'All')]
        [string]$Section = 'Access',
        [Parameter()]
        [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default
    )

    process {
        foreach ($pathValue in $Path) {
            $target = Resolve-RegistryKeyTarget -Path $pathValue -RegistryView $RegistryView
            $sections = switch ($Section) {
                Access { [WindowsSecurityDescriptorSection]::Access }
                Audit { [WindowsSecurityDescriptorSection]::Audit }
                All {
                    [WindowsSecurityDescriptorSection]::Access -bor
                        [WindowsSecurityDescriptorSection]::Audit
                }
            }
            $getDescriptorParameters = @{
                NativePath       = $target.NativePath
                NativeObjectType = $target.NativeObjectType
                Sections         = $sections
            }
            $bytes = Get-WindowsNamedSecurityDescriptor @getDescriptorParameters
            $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($bytes, 0)
            $accessProtected = if ($Section -in @('Access', 'All')) {
                ([int]$descriptor.ControlFlags -band (
                    [int][System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
                )) -ne 0
            } else { $null }
            $auditProtected = if ($Section -in @('Audit', 'All')) {
                ([int]$descriptor.ControlFlags -band (
                    [int][System.Security.AccessControl.ControlFlags]::SystemAclProtected
                )) -ne 0
            } else { $null }
            $result = [pscustomobject]@{
                ObjectType               = 'RegistryKey'
                Path                     = $target.Path
                NativePath               = $target.NativePath
                RegistryView             = $target.RegistryView
                Section                  = $Section
                AccessInheritanceEnabled = if ($null -eq $accessProtected) { $null } else { -not $accessProtected }
                AccessRulesProtected     = $accessProtected
                AuditInheritanceEnabled  = if ($null -eq $auditProtected) { $null } else { -not $auditProtected }
                AuditRulesProtected      = $auditProtected
            }
            $result.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.RegistryKeyInheritance')
            $result
        }
    }
}
