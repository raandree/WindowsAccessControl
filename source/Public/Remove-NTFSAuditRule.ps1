function Remove-NTFSAuditRule {
    <#
    .SYNOPSIS
        Removes NTFS audit rules from files or directories.

    .DESCRIPTION
        Removes an exact piped audit rule by default. Path-based calls can
        remove an exact rule, subtract rights, or purge an account from a SACL.

    .PARAMETER InputObject
        An audit-rule object returned by Get-NTFSAuditRule with a target path.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem provider.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied.

    .PARAMETER SecurityDescriptor
        A WindowsAccessControl.SecurityDescriptor object returned by
        Get-NTFSItemSecurityDescriptor with the Audit section loaded. When
        supplied, the removal is staged on the descriptor in memory and the
        descriptor is returned; nothing is written until
        Set-NTFSItemSecurityDescriptor persists it.

    .PARAMETER Account
        The account name or SID whose audit rule is removed.

    .PARAMETER AccessRights
        The rights used for Exact or Rights removal modes. A raw access mask is
        also accepted as a decimal number or a hexadecimal string, which is how
        an entry carrying generic rights is removed.

    .PARAMETER AuditFlags
        Selects the success or failure audit rule to remove.

    .PARAMETER AppliesTo
        Selects inheritance and propagation flags matched by Exact mode.

    .PARAMETER RemovalMode
        Exact removes an identical ACE, Rights subtracts rights, and All purges the account.

    .PARAMETER PassThru
        Returns the audit rule object representing the requested removal.

    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical paths for path-based calls.
        One requests deterministic sequential execution. Piped rule objects
        remain scalar.

    .EXAMPLE
        Get-NTFSAuditRule -LiteralPath C:\Data -ExcludeInherited | Remove-NTFSAuditRule

        Removes each explicit audit rule returned for C:\Data.

    .INPUTS
        WindowsAccessControl.AuditRule
        WindowsAccessControl.SecurityDescriptor

    .OUTPUTS
        None
        WindowsAccessControl.AuditRule
        WindowsAccessControl.SecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Rule')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Rule')]
        [ValidateNotNull()]
        [psobject]$InputObject,

        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')]
        [SupportsWildcards()]
        [string[]]$Path,

        [Parameter(Mandatory, ParameterSetName = 'LiteralPath')]
        [string[]]$LiteralPath,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'SecurityDescriptor')]
        [PSTypeName('WindowsAccessControl.SecurityDescriptor')]
        [pscustomobject]$SecurityDescriptor,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [Parameter(Mandatory, ParameterSetName = 'LiteralPath')]
        [Parameter(Mandatory, ParameterSetName = 'SecurityDescriptor')]
        [ValidateNotNullOrEmpty()]
        [string]$Account,

        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [Parameter(ParameterSetName = 'SecurityDescriptor')]
        [WindowsAccessRightsTransformAttribute([System.Security.AccessControl.FileSystemRights])]
        $AccessRights,

        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [Parameter(ParameterSetName = 'SecurityDescriptor')]
        [System.Security.AccessControl.AuditFlags]$AuditFlags = 'Success',

        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [Parameter(ParameterSetName = 'SecurityDescriptor')]
        [ValidateSet(
            'ThisFolderOnly', 'ThisFolderSubfoldersAndFiles', 'ThisFolderAndSubfolders',
            'ThisFolderAndFiles', 'SubfoldersAndFilesOnly', 'SubfoldersOnly', 'FilesOnly',
            'ThisFolderSubfoldersAndFilesOneLevel', 'ThisFolderAndSubfoldersOneLevel',
            'ThisFolderAndFilesOneLevel', 'SubfoldersAndFilesOnlyOneLevel',
            'SubfoldersOnlyOneLevel', 'FilesOnlyOneLevel'
        )]
        [string]$AppliesTo,

        [Parameter()]
        [ValidateSet('Exact', 'Rights', 'All')]
        [string]$RemovalMode = 'Exact',

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount)),

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        if ($PSCmdlet.ParameterSetName -ne 'Rule' -and
            $RemovalMode -ne 'All' -and
            -not $PSBoundParameters.ContainsKey('AccessRights')) {
            throw 'AccessRights is required when RemovalMode is Exact or Rights.'
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'SecurityDescriptor') {
            $security = Assert-NTFSDescriptorSection `
                -SecurityDescriptor $SecurityDescriptor `
                -RequiredSections Audit
            $securityIdentifier = Resolve-WindowsIdentityReference -Identity $Account
            if ($RemovalMode -eq 'All') {
                $security.PurgeAuditRules($securityIdentifier)
            } else {
                $effectiveAppliesTo = Get-NTFSDescriptorAppliesTo `
                    -SecurityDescriptor $SecurityDescriptor `
                    -AppliesTo $AppliesTo
                $scope = ConvertFrom-NTFSAppliesTo -AppliesTo $effectiveAppliesTo
                $rule = New-NTFSFileSystemRule `
                    -SecurityIdentifier $securityIdentifier `
                    -AccessRights $AccessRights `
                    -InheritanceFlags $scope.InheritanceFlags `
                    -PropagationFlags $scope.PropagationFlags `
                    -AuditFlags $AuditFlags
                if ($RemovalMode -eq 'Exact') {
                    Remove-NTFSFileSystemRuleSpecific -Security $security -Rule $rule
                } else {
                    $null = $security.RemoveAuditRule($rule)
                }
            }
            Update-NTFSSecurityDescriptorObject -Descriptor $SecurityDescriptor
            $SecurityDescriptor
            return
        }

        if (-not $script:WindowsAccessControlBatchWorker.Value -and
            $PSCmdlet.ParameterSetName -ne 'Rule') {
            Invoke-WindowsNtfsCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -LiteralPath $LiteralPath `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact High
            return
        }
        if ($PSCmdlet.ParameterSetName -eq 'Rule') {
            if ($InputObject.PSObject.TypeNames -notcontains 'WindowsAccessControl.AuditRule' -or
                -not $InputObject.NativeRule -or
                [string]::IsNullOrWhiteSpace($InputObject.Path)) {
                throw 'InputObject must be a path-bound rule returned by Get-NTFSAuditRule.'
            }
            $items = @(Resolve-NTFSPath -LiteralPath $InputObject.Path)
            $rule = $InputObject.NativeRule
            $identityLabel = $InputObject.SID
        } else {
            $resolveParameters = @{}
            if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
                $resolveParameters.LiteralPath = $LiteralPath
            } else {
                $resolveParameters.Path = $Path
            }
            $items = @(Resolve-NTFSPath @resolveParameters)
            $securityIdentifier = Resolve-WindowsIdentityReference -Identity $Account
            $identityLabel = $securityIdentifier.Value
        }

        foreach ($item in $items) {
            if ($PSCmdlet.ParameterSetName -ne 'Rule' -and $RemovalMode -ne 'All') {
                $effectiveAppliesTo = $AppliesTo
                if (-not $PSBoundParameters.ContainsKey('AppliesTo')) {
                    $effectiveAppliesTo = if ($item.PSIsContainer) {
                        'ThisFolderSubfoldersAndFiles'
                    } else {
                        'ThisFolderOnly'
                    }
                }
                $scope = ConvertFrom-NTFSAppliesTo -AppliesTo $effectiveAppliesTo
                $rule = New-NTFSFileSystemRule `
                    -SecurityIdentifier $securityIdentifier `
                    -AccessRights $AccessRights `
                    -InheritanceFlags $scope.InheritanceFlags `
                    -PropagationFlags $scope.PropagationFlags `
                    -AuditFlags $AuditFlags
            }

            if ($PSCmdlet.ShouldProcess($item.FullName, "$RemovalMode removal of audit rules for $identityLabel")) {
                $security = Get-NTFSSecurityDescriptorForItem -Item $item -Sections Audit
                $removedRules = @()
                switch ($RemovalMode) {
                    'Exact' { Remove-NTFSFileSystemRuleSpecific -Security $security -Rule $rule }
                    'Rights' { $null = $security.RemoveAuditRule($rule) }
                    'All' {
                        $identityReference = if ($PSCmdlet.ParameterSetName -eq 'Rule') {
                            $rule.IdentityReference
                        } else {
                            $securityIdentifier
                        }
                        if ($PassThru) {
                            $removedRules = @($security.GetAuditRules(
                                $true,
                                $false,
                                [System.Security.Principal.SecurityIdentifier]
                            ) | Where-Object {
                                $_.IdentityReference.Value -eq $identityReference.Value
                            })
                        }
                        $security.PurgeAuditRules($identityReference)
                    }
                }
                $persistenceParameters = @{
                    Item     = $item
                    Security = $security
                    Sections = 'Audit'
                }
                Invoke-NTFSSecurityDescriptorPersistence @persistenceParameters
                if ($PassThru) {
                    if ($RemovalMode -eq 'All') {
                        foreach ($removedRule in $removedRules) {
                            ConvertTo-NTFSAuditRuleObject -Rule $removedRule -Path $item.FullName
                        }
                    } else {
                        ConvertTo-NTFSAuditRuleObject -Rule $rule -Path $item.FullName
                    }
                }
            }
        }
    }
}
