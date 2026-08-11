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

    .PARAMETER SecurityDescriptor
        A WindowsAccessControl.SecurityDescriptor object returned by
        Get-NTFSItemSecurityDescriptor. When supplied, the access rule is
        staged on the descriptor in memory and the descriptor is returned;
        nothing is written until Set-NTFSItemSecurityDescriptor persists it.

    .PARAMETER Account
        One or more account names or SIDs to which the access rule applies.

    .PARAMETER AccessRights
        The filesystem rights to add to the access control list. A raw access
        mask is also accepted as a decimal number or a hexadecimal string, so
        bits the FileSystemRights enumeration cannot name, such as the generic
        rights, can be used.

    .PARAMETER AccessControlType
        Specifies whether the rule allows or denies the selected rights.

    .PARAMETER AppliesTo
        Specifies how a directory rule applies to the directory and its child
        files or directories. Files default to ThisFolderOnly.

    .PARAMETER PassThru
        Returns the access rule that was persisted. By default, the command
        does not emit output.

    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical paths. One requests
        deterministic sequential execution.

    .EXAMPLE
        Get-Item -LiteralPath C:\Data | Add-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Read

        Adds read access for the Analysts group to C:\Data and its children.

    .EXAMPLE
        Get-NTFSItemSecurityDescriptor -LiteralPath C:\Data -Sections Access |
            Add-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Read |
            Set-NTFSItemSecurityDescriptor

        Stages a read access rule in memory and persists it with one write.

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
        [Alias('IdentityReference', 'ID')]
        [string[]]$Account,

        [Parameter(Mandatory)]
        [WindowsAccessRightsTransformAttribute([System.Security.AccessControl.FileSystemRights])]
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
                -RequiredSections Access
            $effectiveAppliesTo = Get-NTFSDescriptorAppliesTo `
                -SecurityDescriptor $SecurityDescriptor `
                -AppliesTo $AppliesTo
            $scope = ConvertFrom-NTFSAppliesTo -AppliesTo $effectiveAppliesTo
            foreach ($securityIdentifier in $securityIdentifiers) {
                $security.AddAccessRule(
                    (New-NTFSFileSystemRule `
                        -SecurityIdentifier $securityIdentifier `
                        -AccessRights $AccessRights `
                        -InheritanceFlags $scope.InheritanceFlags `
                        -PropagationFlags $scope.PropagationFlags `
                        -AccessControlType $AccessControlType)
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
                    -AccessControlType $AccessControlType
            }

            $identityLabel = $securityIdentifiers.Value -join ', '
            $ruleNoun = if ($securityIdentifiers.Count -eq 1) { 'rule' } else { 'rules' }
            $action = "Add $AccessControlType access $ruleNoun for $identityLabel"
            if ($PSCmdlet.ShouldProcess($item.FullName, $action)) {
                $security = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
                foreach ($rule in $rules) {
                    $security.AddAccessRule($rule)
                }
                Invoke-NTFSSecurityDescriptorPersistence -Item $item -Security $security

                if ($PassThru) {
                    foreach ($rule in $rules) {
                        ConvertTo-NTFSAccessRuleObject -Rule $rule -Path $item.FullName
                    }
                }
            }
        }
    }
}
