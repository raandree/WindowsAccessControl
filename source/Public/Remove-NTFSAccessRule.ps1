function Remove-NTFSAccessRule {
    <#
    .SYNOPSIS
        Removes NTFS access rules from files or directories.

    .DESCRIPTION
        Removes an exact piped rule by default. Path-based calls can remove an
        exact rule, subtract a rights mask, or purge every access rule for an
        account. Inherited rules cannot be removed from a child item.

    .PARAMETER InputObject
        An access-rule object returned by Get-NTFSAccessRule or
        New-NTFSAccessRule. Rules returned by Get include their target path.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied.

    .PARAMETER Account
        The account name or SID whose access rule is removed.

    .PARAMETER AccessRights
        The rights used for Exact or Rights removal modes.

    .PARAMETER AccessControlType
        Selects whether an allow or deny rule is removed.

    .PARAMETER AppliesTo
        Selects the inheritance and propagation flags matched by Exact mode.

    .PARAMETER RemovalMode
        Exact removes only an identical ACE, Rights subtracts matching rights,
        and All purges every ACE for the selected account.

    .PARAMETER PassThru
        Returns the rule object representing the requested removal.

    .EXAMPLE
        Get-NTFSAccessRule -LiteralPath C:\Data -ExcludeInherited | Remove-NTFSAccessRule

        Removes each explicit rule returned for C:\Data.

    .INPUTS
        WindowsAccessControl.AccessRule

    .OUTPUTS
        None
        WindowsAccessControl.AccessRule
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
        [System.Security.AccessControl.AccessControlType]$AccessControlType = 'Allow',

        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [ValidateSet(
            'ThisFolderOnly',
            'ThisFolderSubfoldersAndFiles',
            'ThisFolderAndSubfolders',
            'ThisFolderAndFiles',
            'SubfoldersAndFilesOnly',
            'SubfoldersOnly',
            'FilesOnly',
            'ThisFolderSubfoldersAndFilesOneLevel',
            'ThisFolderAndSubfoldersOneLevel',
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
            if ($InputObject.PSObject.TypeNames -notcontains 'WindowsAccessControl.AccessRule' -or
                -not $InputObject.NativeRule -or
                [string]::IsNullOrWhiteSpace($InputObject.Path)) {
                throw 'InputObject must be a path-bound rule returned by Get-NTFSAccessRule.'
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
                $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $securityIdentifier,
                    $AccessRights,
                    $scope.InheritanceFlags,
                    $scope.PropagationFlags,
                    $AccessControlType
                )
            }

            if ($PSCmdlet.ShouldProcess($item.FullName, "$RemovalMode removal of access rules for $identityLabel")) {
                $security = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
                $removedRules = @()
                switch ($RemovalMode) {
                    'Exact' { $security.RemoveAccessRuleSpecific($rule) }
                    'Rights' { $null = $security.RemoveAccessRule($rule) }
                    'All' {
                        $identityReference = if ($PSCmdlet.ParameterSetName -eq 'Rule') {
                            $rule.IdentityReference
                        } else {
                            $securityIdentifier
                        }
                        if ($PassThru) {
                            $removedRules = @($security.GetAccessRules(
                                $true,
                                $false,
                                [System.Security.Principal.SecurityIdentifier]
                            ) | Where-Object {
                                $_.IdentityReference.Value -eq $identityReference.Value
                            })
                        }
                        $security.PurgeAccessRules($identityReference)
                    }
                }
                Invoke-NTFSSecurityDescriptorPersistence -Item $item -Security $security

                if ($PassThru) {
                    if ($RemovalMode -eq 'All') {
                        foreach ($removedRule in $removedRules) {
                            ConvertTo-NTFSAccessRuleObject -Rule $removedRule -Path $item.FullName
                        }
                    } else {
                        ConvertTo-NTFSAccessRuleObject -Rule $rule -Path $item.FullName
                    }
                }
            }
        }
    }
}