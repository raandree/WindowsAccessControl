function Set-RegistryKeyAuditRule {
    <#
    .SYNOPSIS
        Replaces matching audit rules on local registry keys.
    .DESCRIPTION
        Removes explicit registry audit rules for each selected SID and audit
        flag combination, adds the replacement, and persists each SACL once.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey pipeline objects.
    .PARAMETER Account
        One or more account names, SID strings, identity references, or module identities.
    .PARAMETER AccessRights
        Registry rights stored in each replacement audit rule.
    .PARAMETER AuditFlags
        Selects successful access, failed access, or both for auditing.
    .PARAMETER AppliesTo
        Controls whether the audit ACE applies to this key, subkeys, or one level.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical targets. One requests
        deterministic sequential execution.
    .PARAMETER PassThru
        Returns each stored replacement rule after persistence.
    .EXAMPLE
        Set-RegistryKeyAuditRule -Path HKCU:\Software -Account Everyone -AccessRights SetValue -AuditFlags Failure -Confirm:$false

        Replaces the matching Everyone audit rule.
    .INPUTS
        System.String
        Microsoft.Win32.RegistryKey
    .OUTPUTS
        None
        WindowsAccessControl.RegistryKeyAuditRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
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
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(
            1,
            [Math]::Min(8, [Environment]::ProcessorCount)
        ),
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
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsRegistryCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -RegistryView $RegistryView `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact High
            return
        }
        foreach ($pathValue in $Path) {
            $target = Resolve-RegistryKeyTarget -Path $pathValue -RegistryView $RegistryView
            if ($PSCmdlet.ShouldProcess($target.Path, "Replace $AuditFlags registry audit rules")) {
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
                        Operation = 'Set'
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
