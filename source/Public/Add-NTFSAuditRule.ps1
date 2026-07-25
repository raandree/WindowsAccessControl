function Add-NTFSAuditRule {
    <#
    .SYNOPSIS
        Adds an NTFS audit rule to files or directories.

    .DESCRIPTION
        Adds a success or failure audit rule without replacing unrelated SACL
        entries. Reading and writing SACLs requires SeSecurityPrivilege.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER Account
        One or more account names or SIDs to which the audit rule applies.

    .PARAMETER AccessRights
        The filesystem rights whose access attempts are audited.

    .PARAMETER AuditFlags
        Specifies whether successful access, failed access, or both are audited.

    .PARAMETER AppliesTo
        Specifies how a directory rule applies to the directory and its child
        files or directories. Files default to ThisFolderOnly.

    .PARAMETER PassThru
        Returns the audit rule after the descriptor is persisted.

    .EXAMPLE
        Add-NTFSAuditRule -LiteralPath C:\Data -Account Everyone -AccessRights Write -AuditFlags Failure

        Audits failed write attempts by Everyone on C:\Data and its children.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        None
        NTFSPermission.AuditRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Path')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Path')]
        [Alias('FullName')]
        [SupportsWildcards()]
        [string[]]$Path,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'LiteralPath')]
        [Alias('PSPath')]
        [string[]]$LiteralPath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'ID')]
        [string[]]$Account,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemRights]$AccessRights,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.AuditFlags]$AuditFlags,

        [Parameter()]
        [ValidateSet(
            'ThisFolderOnly', 'ThisFolderSubfoldersAndFiles', 'ThisFolderAndSubfolders',
            'ThisFolderAndFiles', 'SubfoldersAndFilesOnly', 'SubfoldersOnly', 'FilesOnly',
            'ThisFolderSubfoldersAndFilesOneLevel', 'ThisFolderAndSubfoldersOneLevel',
            'ThisFolderAndFilesOneLevel'
        )]
        [string]$AppliesTo,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $seenIdentifiers = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $securityIdentifiers = @(
            foreach ($accountName in $Account) {
                $securityIdentifier = Resolve-NTFSIdentityReference -Identity $accountName
                if ($seenIdentifiers.Add($securityIdentifier.Value)) {
                    $securityIdentifier
                }
            }
        )
    }

    process {
        $resolveParameters = @{}
        if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $resolveParameters.LiteralPath = $LiteralPath
        } else {
            $resolveParameters.Path = $Path
        }

        foreach ($item in Resolve-NTFSPath @resolveParameters) {
            $effectiveAppliesTo = $AppliesTo
            if (-not $PSBoundParameters.ContainsKey('AppliesTo')) {
                $effectiveAppliesTo = if ($item.PSIsContainer) {
                    'ThisFolderSubfoldersAndFiles'
                } else {
                    'ThisFolderOnly'
                }
            }
            $scope = ConvertFrom-NTFSAppliesTo -AppliesTo $effectiveAppliesTo
            $rules = foreach ($securityIdentifier in $securityIdentifiers) {
                [System.Security.AccessControl.FileSystemAuditRule]::new(
                    $securityIdentifier,
                    $AccessRights,
                    $scope.InheritanceFlags,
                    $scope.PropagationFlags,
                    $AuditFlags
                )
            }

            $identityLabel = $securityIdentifiers.Value -join ', '
            $ruleNoun = if ($securityIdentifiers.Count -eq 1) { 'rule' } else { 'rules' }
            $action = "Add $AuditFlags audit $ruleNoun for $identityLabel"
            if ($PSCmdlet.ShouldProcess($item.FullName, $action)) {
                $security = Get-Acl -LiteralPath $item.FullName -Audit -ErrorAction Stop
                foreach ($rule in $rules) {
                    $security.AddAuditRule($rule)
                }
                Invoke-NTFSSecurityDescriptorPersistence -Item $item -Security $security
                if ($PassThru) {
                    foreach ($rule in $rules) {
                        ConvertTo-NTFSAuditRuleObject -Rule $rule -Path $item.FullName
                    }
                }
            }
        }
    }
}
