function Clear-RegistryKeyAuditRule {
    <#
    .SYNOPSIS
        Clears selected explicit audit rules from local registry keys.
    .DESCRIPTION
        Removes explicit registry SACL entries for selected accounts, or every
        explicit audit rule when Account is omitted, without changing inherited ACEs.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey pipeline objects.
    .PARAMETER SecurityDescriptor
        A WindowsAccessControl.RegistryKeySecurityDescriptor object returned by
        Get-RegistryKeySecurityDescriptor with the Audit section loaded. When
        supplied, the selected explicit rules are cleared on the descriptor in
        memory and the descriptor is returned; nothing is written until
        Set-RegistryKeySecurityDescriptor persists it.
    .PARAMETER Account
        Optional account names or SIDs whose explicit audit rules are removed.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical targets. One requests
        deterministic sequential execution.
    .PARAMETER PassThru
        Returns the rules selected for removal after successful persistence.
    .EXAMPLE
        Clear-RegistryKeyAuditRule -Path HKCU:\Software -Account Everyone -WhatIf

        Previews removing explicit Everyone audit rules.
    .INPUTS
        System.String
        Microsoft.Win32.RegistryKey
        WindowsAccessControl.RegistryKeySecurityDescriptor
    .OUTPUTS
        None
        WindowsAccessControl.RegistryKeyAuditRule
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
        [Parameter()]
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,
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
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'SecurityDescriptor') {
            $bytes = Assert-WindowsDescriptorSection `
                -SecurityDescriptor $SecurityDescriptor `
                -RequiredSections Audit `
                -TypeName 'WindowsAccessControl.RegistryKeySecurityDescriptor'
            if ($identities.Count -eq 0) {
                $bytes = Invoke-WindowsAclRuleMutation `
                    -SecurityDescriptor $bytes `
                    -RuleType 'Audit' `
                    -Operation 'Clear'
            } else {
                foreach ($sid in $identities) {
                    $bytes = Invoke-WindowsAclRuleMutation `
                        -SecurityDescriptor $bytes `
                        -RuleType 'Audit' `
                        -Operation 'Clear' `
                        -SecurityIdentifier $sid
                }
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
            if ($PSCmdlet.ShouldProcess($target.Path, 'Clear explicit registry audit rules')) {
                $removed = if ($PassThru) {
                    $getRuleParameters = @{
                        Target           = $target
                        RuleType         = 'Audit'
                        Account          = $identities.Value
                        ExcludeInherited = $true
                        TypeName         = 'WindowsAccessControl.RegistryKeyAuditRule'
                    }
                    @(Get-WindowsAclRule @getRuleParameters)
                }
                $getDescriptorParameters = @{
                    NativePath       = $target.NativePath
                    NativeObjectType = $target.NativeObjectType
                    Sections         = [WindowsSecurityDescriptorSection]::Audit
                }
                $currentDescriptor = Get-WindowsNamedSecurityDescriptor @getDescriptorParameters
                $descriptor = $currentDescriptor
                if ($identities.Count -eq 0) {
                    $mutationParameters = @{
                        SecurityDescriptor = $descriptor
                        RuleType          = 'Audit'
                        Operation         = 'Clear'
                    }
                    $descriptor = Invoke-WindowsAclRuleMutation @mutationParameters
                } else {
                    foreach ($sid in $identities) {
                        $mutationParameters = @{
                            SecurityDescriptor = $descriptor
                            RuleType          = 'Audit'
                            Operation         = 'Clear'
                            SecurityIdentifier = $sid
                        }
                        $descriptor = Invoke-WindowsAclRuleMutation @mutationParameters
                    }
                }
                $setDescriptorParameters = @{
                    NativePath         = $target.NativePath
                    NativeObjectType   = $target.NativeObjectType
                    Sections           = [WindowsSecurityDescriptorSection]::Audit
                    SecurityDescriptor = $descriptor
                    CurrentSecurityDescriptor = $currentDescriptor
                }
                Set-WindowsNamedSecurityDescriptor @setDescriptorParameters
                if ($PassThru) { $removed }
            }
        }
    }
}
