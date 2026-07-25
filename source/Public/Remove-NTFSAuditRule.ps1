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

    .PARAMETER Account
        The account name or SID whose audit rule is removed.

    .PARAMETER AccessRights
        The rights used for Exact or Rights removal modes.

    .PARAMETER AuditFlags
        Selects the success or failure audit rule to remove.

    .PARAMETER AppliesTo
        Selects inheritance and propagation flags matched by Exact mode.

    .PARAMETER RemovalMode
        Exact removes an identical ACE, Rights subtracts rights, and All purges the account.

    .PARAMETER PassThru
        Returns the audit rule object representing the requested removal.

    .EXAMPLE
        Get-NTFSAuditRule -LiteralPath C:\Data -ExcludeInherited | Remove-NTFSAuditRule

        Removes each explicit audit rule returned for C:\Data.

    .INPUTS
        NTFSPermission.AuditRule

    .OUTPUTS
        None
        NTFSPermission.AuditRule
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

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [Parameter(Mandatory, ParameterSetName = 'LiteralPath')]
        [ValidateNotNullOrEmpty()]
        [string]$Account,

        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [System.Security.AccessControl.FileSystemRights]$AccessRights,

        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [System.Security.AccessControl.AuditFlags]$AuditFlags = 'Success',

        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [ValidateSet(
            'ThisFolderOnly', 'ThisFolderSubfoldersAndFiles', 'ThisFolderAndSubfolders',
            'ThisFolderAndFiles', 'SubfoldersAndFilesOnly', 'SubfoldersOnly', 'FilesOnly',
            'ThisFolderSubfoldersAndFilesOneLevel', 'ThisFolderAndSubfoldersOneLevel',
            'ThisFolderAndFilesOneLevel'
        )]
        [string]$AppliesTo,

        [Parameter()]
        [ValidateSet('Exact', 'Rights', 'All')]
        [string]$RemovalMode = 'Exact',

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
        if ($PSCmdlet.ParameterSetName -eq 'Rule') {
            if ($InputObject.PSObject.TypeNames -notcontains 'NTFSPermission.AuditRule' -or
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
            $securityIdentifier = Resolve-NTFSIdentityReference -Identity $Account
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
                $rule = [System.Security.AccessControl.FileSystemAuditRule]::new(
                    $securityIdentifier,
                    $AccessRights,
                    $scope.InheritanceFlags,
                    $scope.PropagationFlags,
                    $AuditFlags
                )
            }

            if ($PSCmdlet.ShouldProcess($item.FullName, "$RemovalMode removal of audit rules for $identityLabel")) {
                $security = Get-Acl -LiteralPath $item.FullName -Audit -ErrorAction Stop
                $removedRules = @()
                switch ($RemovalMode) {
                    'Exact' { $security.RemoveAuditRuleSpecific($rule) }
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
                Invoke-NTFSSecurityDescriptorPersistence -Item $item -Security $security
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