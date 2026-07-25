function Clear-RegistryKeyAccessRule {
    <#
    .SYNOPSIS
        Clears selected explicit access rules from local registry keys.
    .DESCRIPTION
        Removes explicit registry DACL entries for selected accounts, or every
        explicit access rule when Account is omitted, without changing inherited ACEs.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey pipeline objects.
    .PARAMETER Account
        Optional account names or SIDs whose explicit access rules are removed.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .PARAMETER PassThru
        Returns the rules selected for removal after successful persistence.
    .EXAMPLE
        Clear-RegistryKeyAccessRule -Path HKCU:\Software -Account Everyone -WhatIf

        Previews removing explicit Everyone access rules.
    .INPUTS
        System.String
        Microsoft.Win32.RegistryKey
    .OUTPUTS
        None
        WindowsAccessControl.RegistryKeyAccessRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('PSPath')]
        [object[]]$Path,
        [Parameter()]
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,
        [Parameter()]
        [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,
        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $seen = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $identities = @(
            foreach ($accountValue in $Account) {
                $sid = Resolve-WindowsIdentityReference -Identity $accountValue
                if ($seen.Add($sid.Value)) { $sid }
            }
        )
    }
    process {
        foreach ($pathValue in $Path) {
            $target = Resolve-RegistryKeyTarget -Path $pathValue -RegistryView $RegistryView
            if ($PSCmdlet.ShouldProcess($target.Path, 'Clear explicit registry access rules')) {
                $removed = if ($PassThru) {
                    $getRuleParameters = @{
                        Target           = $target
                        RuleType         = 'Access'
                        Account          = $identities.Value
                        ExcludeInherited = $true
                        TypeName         = 'WindowsAccessControl.RegistryKeyAccessRule'
                    }
                    @(Get-WindowsAclRule @getRuleParameters)
                }
                $getDescriptorParameters = @{
                    NativePath       = $target.NativePath
                    NativeObjectType = $target.NativeObjectType
                    Sections         = [WindowsSecurityDescriptorSection]::Access
                }
                $currentDescriptor = Get-WindowsNamedSecurityDescriptor @getDescriptorParameters
                $descriptor = $currentDescriptor
                if ($identities.Count -eq 0) {
                    $mutationParameters = @{
                        SecurityDescriptor = $descriptor
                        RuleType          = 'Access'
                        Operation         = 'Clear'
                    }
                    $descriptor = Invoke-WindowsAclRuleMutation @mutationParameters
                } else {
                    foreach ($sid in $identities) {
                        $mutationParameters = @{
                            SecurityDescriptor = $descriptor
                            RuleType          = 'Access'
                            Operation         = 'Clear'
                            SecurityIdentifier = $sid
                        }
                        $descriptor = Invoke-WindowsAclRuleMutation @mutationParameters
                    }
                }
                $setDescriptorParameters = @{
                    NativePath         = $target.NativePath
                    NativeObjectType   = $target.NativeObjectType
                    Sections           = [WindowsSecurityDescriptorSection]::Access
                    SecurityDescriptor = $descriptor
                    CurrentSecurityDescriptor = $currentDescriptor
                }
                Set-WindowsNamedSecurityDescriptor @setDescriptorParameters
                if ($PassThru) { $removed }
            }
        }
    }
}
