function Set-RegistryKeyAccessRule {
    <#
    .SYNOPSIS
        Replaces matching access rules on local registry keys.
    .DESCRIPTION
        Removes explicit registry access rules for each selected SID and allow
        or deny qualifier, adds the replacement rule, and writes each DACL once.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey pipeline objects.
    .PARAMETER SecurityDescriptor
        A WindowsAccessControl.RegistryKeySecurityDescriptor object returned by
        Get-RegistryKeySecurityDescriptor. When supplied, matching rules are
        replaced on the descriptor in memory and the descriptor is returned;
        nothing is written until Set-RegistryKeySecurityDescriptor persists it.
    .PARAMETER Account
        One or more account names, SID strings, identity references, or module identities.
    .PARAMETER AccessRights
        Registry rights stored in each replacement rule.
    .PARAMETER AccessControlType
        Replaces Allow rules by default or explicit Deny rules.
    .PARAMETER AppliesTo
        Controls whether the ACE applies to this key, subkeys, or one level.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical targets. One requests
        deterministic sequential execution.
    .PARAMETER PassThru
        Returns each stored replacement rule after persistence.
    .EXAMPLE
        Set-RegistryKeyAccessRule -Path HKCU:\Software -Account Everyone -AccessRights ReadKey -Confirm:$false

        Replaces the Everyone allow rule on the Software key.
    .INPUTS
        System.String
        Microsoft.Win32.RegistryKey
        WindowsAccessControl.RegistryKeySecurityDescriptor
    .OUTPUTS
        None
        WindowsAccessControl.RegistryKeyAccessRule
        WindowsAccessControl.RegistryKeySecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'SecurityDescriptor')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Path')]
        [Alias('PSPath')]
        [object[]]$Path,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'SecurityDescriptor')]
        [PSTypeName('WindowsAccessControl.RegistryKeySecurityDescriptor')]
        [pscustomobject]$SecurityDescriptor,
        [Parameter(Mandatory)]
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,
        [Parameter(Mandatory)]
        [System.Security.AccessControl.RegistryRights]$AccessRights,
        [Parameter()]
        [System.Security.AccessControl.AccessControlType]$AccessControlType =
            [System.Security.AccessControl.AccessControlType]::Allow,
        [Parameter()]
        [ValidateSet('ThisKeyOnly', 'ThisKeyAndSubkeys', 'SubkeysOnly', 'ThisKeyAndSubkeysOneLevel', 'SubkeysOnlyOneLevel')]
        [string]$AppliesTo = 'ThisKeyOnly',
        [Parameter()]
        [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount)),
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
        $aceFlags = ConvertTo-WindowsRegistryAceFlag -AppliesTo $AppliesTo
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'SecurityDescriptor') {
            $bytes = Assert-WindowsDescriptorSection `
                -SecurityDescriptor $SecurityDescriptor `
                -RequiredSections Access `
                -TypeName 'WindowsAccessControl.RegistryKeySecurityDescriptor'
            foreach ($sid in $identities) {
                $bytes = Invoke-WindowsAclRuleMutation `
                    -SecurityDescriptor $bytes `
                    -RuleType 'Access' `
                    -Operation 'Set' `
                    -SecurityIdentifier $sid `
                    -AccessMask ([int]$AccessRights) `
                    -AccessControlType $AccessControlType `
                    -AceFlags $aceFlags
            }
            Update-WindowsSecurityDescriptorObject `
                -Descriptor $SecurityDescriptor `
                -SecurityDescriptor $bytes
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
                -ConfirmationImpact High
            return
        }
        foreach ($pathValue in $Path) {
            $target = Resolve-RegistryKeyTarget -Path $pathValue -RegistryView $RegistryView
            if ($PSCmdlet.ShouldProcess($target.Path, "Replace $AccessControlType registry access rules")) {
                $getDescriptorParameters = @{
                    NativePath       = $target.NativePath
                    NativeObjectType = $target.NativeObjectType
                    Sections         = [WindowsSecurityDescriptorSection]::Access
                }
                $currentDescriptor = Get-WindowsNamedSecurityDescriptor @getDescriptorParameters
                $descriptor = $currentDescriptor
                foreach ($sid in $identities) {
                    $parameters = @{
                        SecurityDescriptor = $descriptor
                        RuleType = 'Access'
                        Operation = 'Set'
                        SecurityIdentifier = $sid
                        AccessMask = [int]$AccessRights
                        AccessControlType = $AccessControlType
                        AceFlags = $aceFlags
                    }
                    $descriptor = Invoke-WindowsAclRuleMutation @parameters
                }
                $setDescriptorParameters = @{
                    NativePath         = $target.NativePath
                    NativeObjectType   = $target.NativeObjectType
                    Sections           = [WindowsSecurityDescriptorSection]::Access
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
                    Get-RegistryKeyAccessRule @getRuleParameters
                }
            }
        }
    }
}
