function Enable-RegistryKeyInheritance {
    <#
    .SYNOPSIS
        Enables access or audit inheritance on local registry keys.
    .DESCRIPTION
        Removes protection from selected registry ACLs and can remove explicit
        ACEs before parent inheritance is restored through section-scoped persistence.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey pipeline objects.
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
        [switch]$RemoveExplicitRules,
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
            $sections = switch ($Section) {
                Access { [WindowsSecurityDescriptorSection]::Access }
                Audit { [WindowsSecurityDescriptorSection]::Audit }
                All { [WindowsSecurityDescriptorSection]::Access -bor [WindowsSecurityDescriptorSection]::Audit }
            }
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
