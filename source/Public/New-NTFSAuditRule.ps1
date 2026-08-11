function New-NTFSAuditRule {
    <#
    .SYNOPSIS
        Creates a reusable NTFS audit rule.

    .DESCRIPTION
        Creates an in-memory audit rule with an account, rights, success or
        failure flags, and an Explorer-style inheritance scope.

    .PARAMETER Account
        The account name or SID to which the new audit rule applies.

    .PARAMETER AccessRights
        The filesystem rights represented by the new audit rule. A raw access
        mask is also accepted as a decimal number or a hexadecimal string, so
        bits the FileSystemRights enumeration cannot name, such as the generic
        rights, can be used.

    .PARAMETER AuditFlags
        Specifies whether successful access, failed access, or both are audited.

    .PARAMETER AppliesTo
        Specifies how the rule applies to a directory and its child files or
        directories using names that correspond to Windows Explorer.

    .EXAMPLE
        New-NTFSAuditRule -Account 'CONTOSO\Analysts' -AccessRights Write -AuditFlags Failure

        Creates a rule that audits failed write attempts by the Analysts group.

    .INPUTS
        System.String

    .OUTPUTS
        WindowsAccessControl.AuditRule
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
        [WindowsAccessRightsTransformAttribute([System.Security.AccessControl.FileSystemRights])]
        [System.Security.AccessControl.FileSystemRights]$AccessRights,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.AuditFlags]$AuditFlags,

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
            $rule = New-NTFSFileSystemRule `
                -SecurityIdentifier $securityIdentifier `
                -AccessRights $AccessRights `
                -InheritanceFlags $scope.InheritanceFlags `
                -PropagationFlags $scope.PropagationFlags `
                -AuditFlags $AuditFlags
            ConvertTo-NTFSAuditRuleObject -Rule $rule -Path ''
        }
    }
}