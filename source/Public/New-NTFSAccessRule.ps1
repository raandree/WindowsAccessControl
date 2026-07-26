function New-NTFSAccessRule {
    <#
    .SYNOPSIS
        Creates a reusable NTFS access rule.

    .DESCRIPTION
        Creates an in-memory access rule with an account, rights, allow or deny
        qualifier, and an Explorer-style inheritance scope. The returned rule
        can be inspected, exported, or passed to another module command.

    .PARAMETER Account
        The account name or SID to which the new access rule applies.

    .PARAMETER AccessRights
        The filesystem rights represented by the new access rule.

    .PARAMETER AccessControlType
        Specifies whether the rule allows or denies the selected rights.

    .PARAMETER AppliesTo
        Specifies how the rule applies to a directory and its child files or
        directories using names that correspond to Windows Explorer.

    .EXAMPLE
        New-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Read -AppliesTo FilesOnly

        Creates a read rule that is inherited by files below a directory.

    .INPUTS
        System.String

    .OUTPUTS
        WindowsAccessControl.AccessRule
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Creates an in-memory rule and does not change system state.'
    )]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Account,

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
        [string]$AppliesTo = 'ThisFolderSubfoldersAndFiles'
    )

    process {
        $scope = ConvertFrom-NTFSAppliesTo -AppliesTo $AppliesTo
        foreach ($accountName in $Account) {
            $securityIdentifier = Resolve-WindowsIdentityReference -Identity $accountName
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $securityIdentifier,
                $AccessRights,
                $scope.InheritanceFlags,
                $scope.PropagationFlags,
                $AccessControlType
            )
            ConvertTo-NTFSAccessRuleObject -Rule $rule -Path ''
        }
    }
}