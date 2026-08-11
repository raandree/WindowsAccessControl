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

    .PARAMETER SecurityDescriptor
        A WindowsAccessControl.SecurityDescriptor object returned by
        Get-NTFSItemSecurityDescriptor with the Audit section loaded. When
        supplied, the audit rule is staged on the descriptor in memory and the
        descriptor is returned; nothing is written until
        Set-NTFSItemSecurityDescriptor persists it.

    .PARAMETER Account
        One or more account names or SIDs to which the audit rule applies.

    .PARAMETER AccessRights
        The filesystem rights whose access attempts are audited. A raw access
        mask is also accepted as a decimal number or a hexadecimal string, so
        bits the FileSystemRights enumeration cannot name, such as the generic
        rights, can be used.

    .PARAMETER AuditFlags
        Specifies whether successful access, failed access, or both are audited.

    .PARAMETER AppliesTo
        Specifies how a directory rule applies to the directory and its child
        files or directories. Files default to ThisFolderOnly.

    .PARAMETER PassThru
        Returns the audit rule after the descriptor is persisted.

    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical paths. One requests
        deterministic sequential execution.

    .EXAMPLE
        Add-NTFSAuditRule -LiteralPath C:\Data -Account Everyone -AccessRights Write -AuditFlags Failure

        Audits failed write attempts by Everyone on C:\Data and its children.

    .INPUTS
        System.String
        System.IO.FileSystemInfo
        WindowsAccessControl.SecurityDescriptor

    .OUTPUTS
        None
        WindowsAccessControl.AuditRule
        WindowsAccessControl.SecurityDescriptor
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

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'SecurityDescriptor')]
        [PSTypeName('WindowsAccessControl.SecurityDescriptor')]
        [pscustomobject]$SecurityDescriptor,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'ID')]
        [string[]]$Account,

        [Parameter(Mandatory)]
        [WindowsAccessRightsTransformAttribute([System.Security.AccessControl.FileSystemRights])]
        [System.Security.AccessControl.FileSystemRights]$AccessRights,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.AuditFlags]$AuditFlags,

        [Parameter()]
        [ValidateSet(
            'ThisFolderOnly', 'ThisFolderSubfoldersAndFiles', 'ThisFolderAndSubfolders',
            'ThisFolderAndFiles', 'SubfoldersAndFilesOnly', 'SubfoldersOnly', 'FilesOnly',
            'ThisFolderSubfoldersAndFilesOneLevel', 'ThisFolderAndSubfoldersOneLevel',
            'ThisFolderAndFilesOneLevel', 'SubfoldersAndFilesOnlyOneLevel',
            'SubfoldersOnlyOneLevel', 'FilesOnlyOneLevel'
        )]
        [string]$AppliesTo,

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
        $seenIdentifiers = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $securityIdentifiers = @(
            foreach ($accountName in $Account) {
                $securityIdentifier = Resolve-WindowsIdentityReference -Identity $accountName
                if ($seenIdentifiers.Add($securityIdentifier.Value)) {
                    $securityIdentifier
                }
            }
        )
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'SecurityDescriptor') {
            $security = Assert-NTFSDescriptorSection `
                -SecurityDescriptor $SecurityDescriptor `
                -RequiredSections Audit
            $effectiveAppliesTo = Get-NTFSDescriptorAppliesTo `
                -SecurityDescriptor $SecurityDescriptor `
                -AppliesTo $AppliesTo
            $scope = ConvertFrom-NTFSAppliesTo -AppliesTo $effectiveAppliesTo
            foreach ($securityIdentifier in $securityIdentifiers) {
                $security.AddAuditRule(
                    (New-NTFSFileSystemRule `
                        -SecurityIdentifier $securityIdentifier `
                        -AccessRights $AccessRights `
                        -InheritanceFlags $scope.InheritanceFlags `
                        -PropagationFlags $scope.PropagationFlags `
                        -AuditFlags $AuditFlags)
                )
            }
            Update-NTFSSecurityDescriptorObject -Descriptor $SecurityDescriptor
            $SecurityDescriptor
            return
        }

        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsNtfsCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -LiteralPath $LiteralPath `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact Medium
            return
        }
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
                New-NTFSFileSystemRule `
                    -SecurityIdentifier $securityIdentifier `
                    -AccessRights $AccessRights `
                    -InheritanceFlags $scope.InheritanceFlags `
                    -PropagationFlags $scope.PropagationFlags `
                    -AuditFlags $AuditFlags
            }

            $identityLabel = $securityIdentifiers.Value -join ', '
            $ruleNoun = if ($securityIdentifiers.Count -eq 1) { 'rule' } else { 'rules' }
            $action = "Add $AuditFlags audit $ruleNoun for $identityLabel"
            if ($PSCmdlet.ShouldProcess($item.FullName, $action)) {
                $security = Get-NTFSSecurityDescriptorForItem -Item $item -Sections Audit
                foreach ($rule in $rules) {
                    $security.AddAuditRule($rule)
                }
                $persistenceParameters = @{
                    Item     = $item
                    Security = $security
                    Sections = 'Audit'
                }
                Invoke-NTFSSecurityDescriptorPersistence @persistenceParameters
                if ($PassThru) {
                    foreach ($rule in $rules) {
                        ConvertTo-NTFSAuditRuleObject -Rule $rule -Path $item.FullName
                    }
                }
            }
        }
    }
}
