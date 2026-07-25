function Add-NTFSAccessRule {
    <#
    .SYNOPSIS
        Adds an NTFS access rule to files or directories.

    .DESCRIPTION
        Adds an allow or deny access rule without replacing unrelated rules.
        Directory rules use Explorer-style AppliesTo values, while file rules
        apply only to the file unless AppliesTo is explicitly supplied.

    .PARAMETER Path
        One or more filesystem paths. Wildcards are expanded by the FileSystem
        provider, and path strings can be supplied through the pipeline.

    .PARAMETER LiteralPath
        One or more filesystem paths used exactly as supplied. FileSystem
        objects bind to this parameter through their PSPath property.

    .PARAMETER Account
        The account name or SID to which the access rule applies.

    .PARAMETER AccessRights
        The filesystem rights to add to the access control list.

    .PARAMETER AccessControlType
        Specifies whether the rule allows or denies the selected rights.

    .PARAMETER AppliesTo
        Specifies how a directory rule applies to the directory and its child
        files or directories. Files default to ThisFolderOnly.

    .PARAMETER PassThru
        Returns the access rule that was persisted. By default, the command
        does not emit output.

    .EXAMPLE
        Get-Item -LiteralPath C:\Data | Add-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Read

        Adds read access for the Analysts group to C:\Data and its children.

    .INPUTS
        System.String
        System.IO.FileSystemInfo

    .OUTPUTS
        None
        NTFSPermission.AccessRule
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
            'ThisFolderAndFilesOneLevel'
        )]
        [string]$AppliesTo,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $securityIdentifier = Resolve-NTFSIdentityReference -Identity $Account
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
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $securityIdentifier,
                $AccessRights,
                $scope.InheritanceFlags,
                $scope.PropagationFlags,
                $AccessControlType
            )

            if ($PSCmdlet.ShouldProcess($item.FullName, "Add $AccessControlType access rule for $Account")) {
                $security = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
                $security.AddAccessRule($rule)
                Invoke-NTFSSecurityDescriptorPersistence -Item $item -Security $security

                if ($PassThru) {
                    ConvertTo-NTFSAccessRuleObject -Rule $rule -Path $item.FullName
                }
            }
        }
    }
}