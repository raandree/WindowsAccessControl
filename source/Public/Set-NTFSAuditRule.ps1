function Set-NTFSAuditRule {
    <#
    .SYNOPSIS
        Replaces matching NTFS audit rules.

    .DESCRIPTION
        Removes audit rules with the same account and audit qualifier, then
        adds the specified rule. Unrelated SACL entries remain unchanged.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem provider.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied.

    .PARAMETER SecurityDescriptor
        A WindowsAccessControl.SecurityDescriptor object returned by
        Get-NTFSItemSecurityDescriptor with the Audit section loaded. When
        supplied, matching rules are replaced on the descriptor in memory and
        the descriptor is returned; nothing is written until
        Set-NTFSItemSecurityDescriptor persists it.

    .PARAMETER Account
        The account name or SID whose matching audit rules are replaced.

    .PARAMETER AccessRights
        The filesystem rights for the replacement audit rule. A raw access mask
        is also accepted as a decimal number or a hexadecimal string, so bits
        the FileSystemRights enumeration cannot name, such as the generic
        rights, can be used.

    .PARAMETER AuditFlags
        Selects the success or failure audit qualifier that is replaced.

    .PARAMETER AppliesTo
        Specifies how a directory rule applies to the directory and its children.

    .PARAMETER PassThru
        Returns the replacement audit rule after it is persisted.

    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical paths. One requests
        deterministic sequential execution.

    .EXAMPLE
        Set-NTFSAuditRule -LiteralPath C:\Data -Account Everyone -AccessRights Write -AuditFlags Failure

        Replaces failure audit rules for Everyone with a write audit rule.

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
        [string]$Account,

        [Parameter(Mandatory)]
        [WindowsAccessRightsTransformAttribute([System.Security.AccessControl.FileSystemRights])]
        $AccessRights,

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
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount)),

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $securityIdentifier = Resolve-WindowsIdentityReference -Identity $Account
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
            $security.SetAuditRule(
                (New-NTFSFileSystemRule `
                    -SecurityIdentifier $securityIdentifier `
                    -AccessRights $AccessRights `
                    -InheritanceFlags $scope.InheritanceFlags `
                    -PropagationFlags $scope.PropagationFlags `
                    -AuditFlags $AuditFlags)
            )
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
            $rule = New-NTFSFileSystemRule `
                -SecurityIdentifier $securityIdentifier `
                -AccessRights $AccessRights `
                -InheritanceFlags $scope.InheritanceFlags `
                -PropagationFlags $scope.PropagationFlags `
                -AuditFlags $AuditFlags
            if ($PSCmdlet.ShouldProcess($item.FullName, "Replace $AuditFlags audit rules for $Account")) {
                $security = Get-NTFSSecurityDescriptorForItem -Item $item -Sections Audit
                $security.SetAuditRule($rule)
                $persistenceParameters = @{
                    Item     = $item
                    Security = $security
                    Sections = 'Audit'
                }
                Invoke-NTFSSecurityDescriptorPersistence @persistenceParameters
                if ($PassThru) {
                    ConvertTo-NTFSAuditRuleObject -Rule $rule -Path $item.FullName
                }
            }
        }
    }
}
