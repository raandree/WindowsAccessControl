function Remove-ADObjectAccessRule {
    <#
    .SYNOPSIS
        Removes explicit Active Directory access rules.
    .DESCRIPTION
        Removes one exact piped rule by default. Target-based calls can remove
        an exact rule, subtract a rights mask, or purge every explicit rule for
        an account. Every mode revalidates server, allowed OU, distinguished
        name, and object GUID, and preserves unrelated object ACEs.
    .PARAMETER InputObject
        A path-bound rule returned by Get-ADObjectAccessRule.
    .PARAMETER Server
        The explicit DNS name of the final writable domain controller. When it
        is omitted, one writable domain controller is located in the current
        computer's domain and pinned for the whole command.
    .PARAMETER DistinguishedName
        One or more distinguished names to modify.
    .PARAMETER AllowedBaseDistinguishedName
        The organizational unit that bounds the permitted mutation.
    .PARAMETER Credential
        An optional credential used only for the direct LDAP bind to the rule server.
    .PARAMETER Account
        One or more account names, SIDs, identity references, or module identities.
    .PARAMETER AccessRights
        The rights used for Exact or Rights removal modes.
    .PARAMETER AccessControlType
        Selects whether an allow or deny rule is removed.
    .PARAMETER InheritanceType
        Selects the directory inheritance matched by Exact mode.
    .PARAMETER ObjectType
        Selects the object, property, or extended-right GUID scope to match, or
        the schema class, attribute, property set, validated write, or extended
        right name that identifies it.
    .PARAMETER InheritedObjectType
        Selects the inherited object-class GUID scope to match, or the schema
        class name that identifies it.
    .PARAMETER RemovalMode
        Exact removes only an identical ACE, Rights subtracts matching rights
        from explicit ACEs with the same object scope, and All purges every
        explicit ACE for the selected account, including deny rules.
    .PARAMETER TimeoutSeconds
        Sets the LDAP request timeout from 1 through 300 seconds.
    .PARAMETER ThrottleLimit
        Limits concurrently processed immutable object targets from 1 through 64.
    .PARAMETER PassThru
        Returns the removed rules after successful persistence.
    .EXAMPLE
        Get-ADObjectAccessRule -Server dc01.example.test -DistinguishedName $dn -Account $sid | Remove-ADObjectAccessRule -AllowedBaseDistinguishedName $ou -WhatIf

        Previews exact removal of the selected directory ACE.
    .EXAMPLE
        Remove-ADObjectAccessRule -DistinguishedName $dn -AllowedBaseDistinguishedName $ou -Account $sid -RemovalMode All

        Purges every explicit directory ACE for one account inside the allowed OU.
    .INPUTS
        WindowsAccessControl.ADObjectAccessRule
        System.String
    .OUTPUTS
        None
        WindowsAccessControl.ADObjectAccessRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Rule')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Rule')]
        [ValidateNotNull()]
        [psobject]$InputObject,
        [Parameter(ParameterSetName = 'Target')]
        [string]$Server,
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Target')]
        [Alias('Path')]
        [object[]]$DistinguishedName,
        [Parameter(Mandatory)]
        [string]$AllowedBaseDistinguishedName,
        [Parameter()]
        [pscredential]$Credential,
        [Parameter(Mandatory, ParameterSetName = 'Target')]
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,
        [Parameter(ParameterSetName = 'Target')]
        [WindowsAccessRightsTransformAttribute([WindowsActiveDirectoryRights])]
        $AccessRights,
        [Parameter(ParameterSetName = 'Target')]
        [System.Security.AccessControl.AccessControlType]$AccessControlType =
            [System.Security.AccessControl.AccessControlType]::Allow,
        [Parameter(ParameterSetName = 'Target')]
        [WindowsActiveDirectoryInheritance]$InheritanceType =
            [WindowsActiveDirectoryInheritance]::None,
        [Parameter(ParameterSetName = 'Target')]
        [AllowEmptyString()]
        [string]$ObjectType,
        [Parameter(ParameterSetName = 'Target')]
        [AllowEmptyString()]
        [string]$InheritedObjectType,
        [Parameter(ParameterSetName = 'Target')]
        [ValidateSet('Exact', 'Rights', 'All')]
        [string]$RemovalMode = 'Exact',
        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10,
        [Parameter(ParameterSetName = 'Target')]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount)),
        [Parameter()]
        [switch]$PassThru
    )

    begin {
        if ($PSCmdlet.ParameterSetName -eq 'Target') {
            if ($RemovalMode -ne 'All' -and
                -not $PSBoundParameters.ContainsKey('AccessRights')) {
                throw 'AccessRights is required when RemovalMode is Exact or Rights.'
            }
            # Reject a parameter the selected mode would silently discard, so a
            # caller is never told an ignored constraint was applied.
            $ignoredParameters = switch ($RemovalMode) {
                'All' {
                    @('AccessRights', 'AccessControlType', 'InheritanceType',
                        'ObjectType', 'InheritedObjectType')
                }
                'Rights' { @('InheritanceType') }
                default { @() }
            }
            $bound = @(
                $ignoredParameters | Where-Object { $PSBoundParameters.ContainsKey($_) }
            )
            if ($bound.Count -gt 0) {
                throw (
                    "RemovalMode $RemovalMode ignores $($bound -join ', '). " +
                    'Remove the parameter or choose another mode.'
                )
            }
            Assert-WindowsADDistinguishedNameInput -DistinguishedName $DistinguishedName
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
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Rule') {
            if ($InputObject.PSObject.TypeNames -notcontains 'WindowsAccessControl.ADObjectAccessRule' -or
                -not $InputObject.NativeAce -or
                -not $InputObject.Server -or
                -not $InputObject.DistinguishedName -or
                -not $InputObject.ObjectGuid) {
                throw 'InputObject must be a path-bound rule from Get-ADObjectAccessRule.'
            }
            $target = Resolve-WindowsADObjectTarget `
                -Server $InputObject.Server `
                -DistinguishedName $InputObject.DistinguishedName `
                -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds `
                -ForWrite `
                -ExpectedObjectGuid ([guid]$InputObject.ObjectGuid)
            if ($target.CanonicalTarget -cne $InputObject.CanonicalTarget) {
                throw 'The Active Directory access rule no longer matches its immutable target.'
            }
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Remove exact Active Directory access rule for $($InputObject.SID)")) {
                $descriptor = Invoke-WindowsADAccessRuleMutation `
                    -SecurityDescriptor $target.BinarySecurityDescriptor `
                    -Operation Remove `
                    -NativeAce $InputObject.NativeAce
                Set-WindowsADObjectSecurityDescriptor `
                    -Target $target `
                    -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                    -Credential $Credential `
                    -TimeoutSeconds $TimeoutSeconds `
                    -SecurityDescriptor $descriptor `
                    -ExpectedSecurityDescriptor $target.BinarySecurityDescriptor `
                    -RequireManageableDacl
                if ($PassThru) { $InputObject }
            }
            return
        }

        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            if (-not $pinnedServer) {
                $pinnedServer = Resolve-WindowsADServer -Server $Server
            }
            $PSBoundParameters['Server'] = $pinnedServer
            if (-not $objectTypes) {
                $objectTypes = Resolve-WindowsADObjectTypeGuid `
                    -ObjectType $ObjectType `
                    -InheritedObjectType $InheritedObjectType `
                    -Server $pinnedServer `
                    -Credential $Credential `
                    -TimeoutSeconds $TimeoutSeconds
            }
            foreach ($typeParameter in 'ObjectType', 'InheritedObjectType') {
                if ($PSBoundParameters.ContainsKey($typeParameter)) {
                    $PSBoundParameters[$typeParameter] =
                        $objectTypes.$typeParameter.ToString('D')
                }
            }
            Invoke-WindowsADCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Server $pinnedServer `
                -DistinguishedName $DistinguishedName `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact High
            return
        }
        if (-not $objectTypes) {
            $objectTypes = Resolve-WindowsADObjectTypeGuid `
                -ObjectType $ObjectType `
                -InheritedObjectType $InheritedObjectType
        }
        foreach ($dnValue in $DistinguishedName) {
            $target = Resolve-WindowsADObjectTarget `
                -Server $Server `
                -DistinguishedName ([string]$dnValue) `
                -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds `
                -ForWrite
            $identityLabel = $identities.Value -join ', '
            $descriptor = $target.BinarySecurityDescriptor
            foreach ($sid in $identities) {
                $mutationParameters = @{
                    SecurityDescriptor = $descriptor
                }
                if ($RemovalMode -eq 'All') {
                    $mutationParameters.Operation = 'Clear'
                    $mutationParameters.SecurityIdentifier = $sid
                }
                elseif ($RemovalMode -eq 'Rights') {
                    $mutationParameters.Operation = 'RemoveRights'
                    $mutationParameters.SecurityIdentifier = $sid
                    $mutationParameters.AccessMask = [int]$AccessRights
                    $mutationParameters.AccessControlType = $AccessControlType
                    $mutationParameters.ObjectType = $objectTypes.ObjectType
                    $mutationParameters.InheritedObjectType =
                        $objectTypes.InheritedObjectType
                }
                else {
                    $mutationParameters.Operation = 'Remove'
                    $mutationParameters.NativeAce = New-WindowsADAccessRuleAce `
                        -SecurityIdentifier $sid `
                        -AccessMask ([int]$AccessRights) `
                        -AccessControlType $AccessControlType `
                        -InheritanceType $InheritanceType `
                        -ObjectType $objectTypes.ObjectType `
                        -InheritedObjectType $objectTypes.InheritedObjectType
                }
                $descriptor = Invoke-WindowsADAccessRuleMutation @mutationParameters
            }
            # Disclose a deny removal in the description so it is visible under
            # WhatIf and before a confirmation prompt is answered.
            $denyCount = @(
                Get-WindowsADRemovedAce `
                    -OriginalSecurityDescriptor $target.BinarySecurityDescriptor `
                    -SecurityDescriptor $descriptor |
                    Where-Object {
                        ($_ -as [System.Security.AccessControl.QualifiedAce]).AceQualifier -eq
                            [System.Security.AccessControl.AceQualifier]::AccessDenied
                    }
            ).Count
            $action = "$RemovalMode removal of Active Directory access rules for $identityLabel"
            if ($denyCount -gt 0) {
                $action += " including $denyCount explicit deny rule(s), which can increase effective access"
            }
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, $action)) {
                $removed = if ($PassThru) {
                    @(Get-WindowsADRemovedAccessRule `
                        -Target $target `
                        -OriginalSecurityDescriptor $target.BinarySecurityDescriptor `
                        -SecurityDescriptor $descriptor)
                }
                Set-WindowsADObjectSecurityDescriptor `
                    -Target $target `
                    -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                    -Credential $Credential `
                    -TimeoutSeconds $TimeoutSeconds `
                    -SecurityDescriptor $descriptor `
                    -ExpectedSecurityDescriptor $target.BinarySecurityDescriptor `
                    -RequireManageableDacl
                if ($denyCount -gt 0) {
                    Write-Warning (
                        "$RemovalMode removal on $($target.CanonicalTarget) removed " +
                        "$denyCount explicit deny rule(s), which can increase " +
                        'effective access.'
                    )
                }
                if ($PassThru) {
                    foreach ($rule in $removed) { $rule }
                }
            }
        }
    }
}
