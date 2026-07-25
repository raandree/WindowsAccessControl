function Add-RegistryKeyAuditRule {
    <#
    .SYNOPSIS
        Adds audit rules to local registry keys.
    .DESCRIPTION
        Resolves and deduplicates accounts before adding explicit registry SACL
        entries under a scoped security privilege and persisting each target once.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey pipeline objects.
    .PARAMETER Account
        One or more account names, SID strings, identity references, or module identities.
    .PARAMETER AccessRights
        Registry rights audited by each selected account rule.
    .PARAMETER AuditFlags
        Selects successful access, failed access, or both for auditing.
    .PARAMETER AppliesTo
        Controls whether the audit ACE applies to this key, subkeys, or one level.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .PARAMETER PassThru
        Returns each stored registry audit rule after persistence.
    .EXAMPLE
        Add-RegistryKeyAuditRule -Path HKCU:\Software -Account Everyone -AccessRights SetValue -AuditFlags Failure -WhatIf

        Previews adding a failed-write audit rule.
    .INPUTS
        System.String
        Microsoft.Win32.RegistryKey
    .OUTPUTS
        None
        WindowsAccessControl.RegistryKeyAuditRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('PSPath')]
        [object[]]$Path,
        [Parameter(Mandatory)]
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,
        [Parameter(Mandatory)]
        [System.Security.AccessControl.RegistryRights]$AccessRights,
        [Parameter()]
        [ValidateScript({ $_ -ne [System.Security.AccessControl.AuditFlags]::None })]
        [System.Security.AccessControl.AuditFlags]$AuditFlags =
            [System.Security.AccessControl.AuditFlags]::Success,
        [Parameter()]
        [ValidateSet('ThisKeyOnly', 'ThisKeyAndSubkeys', 'SubkeysOnly', 'ThisKeyAndSubkeysOneLevel', 'SubkeysOnlyOneLevel')]
        [string]$AppliesTo = 'ThisKeyOnly',
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
        $aceFlagParameters = @{
            AppliesTo  = $AppliesTo
            AuditFlags = $AuditFlags
        }
        $aceFlags = ConvertTo-WindowsRegistryAceFlag @aceFlagParameters
    }
    process {
        foreach ($pathValue in $Path) {
            $target = Resolve-RegistryKeyTarget -Path $pathValue -RegistryView $RegistryView
            if ($PSCmdlet.ShouldProcess($target.Path, "Add $AuditFlags registry audit rules")) {
                $getDescriptorParameters = @{
                    NativePath       = $target.NativePath
                    NativeObjectType = $target.NativeObjectType
                    Sections         = [WindowsSecurityDescriptorSection]::Audit
                }
                $currentDescriptor = Get-WindowsNamedSecurityDescriptor @getDescriptorParameters
                $descriptor = $currentDescriptor
                foreach ($sid in $identities) {
                    $parameters = @{
                        SecurityDescriptor = $descriptor
                        RuleType = 'Audit'
                        Operation = 'Add'
                        SecurityIdentifier = $sid
                        AccessMask = [int]$AccessRights
                        AceFlags = $aceFlags
                    }
                    $descriptor = Invoke-WindowsAclRuleMutation @parameters
                }
                $setDescriptorParameters = @{
                    NativePath         = $target.NativePath
                    NativeObjectType   = $target.NativeObjectType
                    Sections           = [WindowsSecurityDescriptorSection]::Audit
                    SecurityDescriptor = $descriptor
                    CurrentSecurityDescriptor = $currentDescriptor
                }
                Set-WindowsNamedSecurityDescriptor @setDescriptorParameters
                if ($PassThru) {
                    $getRuleParameters = @{
                        Path             = $target.Path
                        RegistryView     = $RegistryView
                        Account          = $identities.Value
                        ExcludeInherited = $true
                    }
                    Get-RegistryKeyAuditRule @getRuleParameters
                }
            }
        }
    }
}
