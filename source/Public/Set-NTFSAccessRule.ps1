function Set-NTFSAccessRule {
    <#
    .SYNOPSIS
        Replaces matching NTFS access rules.

    .DESCRIPTION
        Removes access rules with the same account and allow or deny qualifier,
        then adds the specified rule. Rules with the opposite qualifier and
        rules for other accounts are preserved.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER SecurityDescriptor
        A WindowsAccessControl.SecurityDescriptor object returned by
        Get-NTFSItemSecurityDescriptor. When supplied, matching rules are
        replaced on the descriptor in memory and the descriptor is returned;
        nothing is written until Set-NTFSItemSecurityDescriptor persists it.

    .PARAMETER Account
        The account name or SID whose matching access rules are replaced.

    .PARAMETER AccessRights
        The filesystem rights for the replacement access rule.

    .PARAMETER AccessControlType
        Selects the allow or deny qualifier that is replaced.

    .PARAMETER AppliesTo
        Specifies how a directory rule applies to the directory and its child
        files or directories. Files default to ThisFolderOnly.

    .PARAMETER PassThru
        Returns the replacement access rule after it is persisted.

    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical paths. One requests
        deterministic sequential execution.

    .EXAMPLE
        Set-NTFSAccessRule -LiteralPath C:\Data -Account 'CONTOSO\Analysts' -AccessRights Modify

        Replaces allow rules for the Analysts group with a Modify rule.

    .EXAMPLE
        Get-NTFSItemSecurityDescriptor -LiteralPath C:\Data -Sections Access |
            Set-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Modify |
            Set-NTFSItemSecurityDescriptor

        Stages the replacement in memory and persists it with one write.

    .INPUTS
        System.String
        System.IO.FileSystemInfo
        WindowsAccessControl.SecurityDescriptor

    .OUTPUTS
        None
        WindowsAccessControl.AccessRule
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
        [System.Security.AccessControl.FileSystemRights]$AccessRights,

        [Parameter()]
        [System.Security.AccessControl.AccessControlType]$AccessControlType = 'Allow',

        [Parameter()]
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
            'ThisFolderAndFilesOneLevel',
            'SubfoldersAndFilesOnlyOneLevel',
            'SubfoldersOnlyOneLevel',
            'FilesOnlyOneLevel'
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
        $securityIdentifier = Resolve-WindowsIdentityReference -Identity $Account
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'SecurityDescriptor') {
            $security = Assert-NTFSDescriptorSection `
                -SecurityDescriptor $SecurityDescriptor `
                -RequiredSections Access
            $effectiveAppliesTo = Get-NTFSDescriptorAppliesTo `
                -SecurityDescriptor $SecurityDescriptor `
                -AppliesTo $AppliesTo
            $scope = ConvertFrom-NTFSAppliesTo -AppliesTo $effectiveAppliesTo
            $security.SetAccessRule(
                [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $securityIdentifier,
                    $AccessRights,
                    $scope.InheritanceFlags,
                    $scope.PropagationFlags,
                    $AccessControlType
                )
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
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $securityIdentifier,
                $AccessRights,
                $scope.InheritanceFlags,
                $scope.PropagationFlags,
                $AccessControlType
            )

            if ($PSCmdlet.ShouldProcess($item.FullName, "Replace $AccessControlType access rules for $Account")) {
                $security = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
                $security.SetAccessRule($rule)
                Invoke-NTFSSecurityDescriptorPersistence -Item $item -Security $security

                if ($PassThru) {
                    ConvertTo-NTFSAccessRuleObject -Rule $rule -Path $item.FullName
                }
            }
        }
    }
}
