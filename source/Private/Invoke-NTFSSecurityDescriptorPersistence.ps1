function Invoke-NTFSSecurityDescriptorPersistence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileSystemInfo]$Item,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemSecurity]$Security,

        [Parameter()]
        [System.Security.AccessControl.AccessControlSections]$Sections =
            [System.Security.AccessControl.AccessControlSections]::Access,

        [Parameter()]
        [ValidateSet('Access', 'Audit', 'All')]
        [string]$ProtectionSection
    )

    $persistDescriptor = {
        param($targetItem, $targetSecurity, $targetProtectionSection)

        if ($PSVersionTable.PSEdition -eq 'Core') {
            if ($targetItem.PSIsContainer) {
                [System.IO.FileSystemAclExtensions]::SetAccessControl(
                    [System.IO.DirectoryInfo]$targetItem,
                    [System.Security.AccessControl.DirectorySecurity]$targetSecurity
                )
            } else {
                [System.IO.FileSystemAclExtensions]::SetAccessControl(
                    [System.IO.FileInfo]$targetItem,
                    [System.Security.AccessControl.FileSecurity]$targetSecurity
                )
            }
        } elseif ($targetItem.PSIsContainer) {
            [System.IO.Directory]::SetAccessControl(
                $targetItem.FullName,
                [System.Security.AccessControl.DirectorySecurity]$targetSecurity
            )
        } else {
            [System.IO.File]::SetAccessControl(
                $targetItem.FullName,
                [System.Security.AccessControl.FileSecurity]$targetSecurity
            )
        }

        if ($targetProtectionSection) {
            Initialize-WindowsAccessControlNativeType
            [WindowsAccessControl.NativeMethods]::SetFileSystemAclProtection(
                $targetItem.FullName,
                $targetSecurity.GetSecurityDescriptorBinaryForm(),
                $targetProtectionSection -in @('Access', 'All'),
                $targetSecurity.AreAccessRulesProtected,
                $targetProtectionSection -in @('Audit', 'All'),
                $targetSecurity.AreAuditRulesProtected
            )
        }
    }
    $persistenceArguments = @($Item, $Security, $ProtectionSection)

    $requiredPrivileges = [System.Collections.Generic.List[string]]::new()
    if (($Sections -band [System.Security.AccessControl.AccessControlSections]::Audit) -ne 0 -or
        $ProtectionSection -in @('Audit', 'All')) {
        $requiredPrivileges.Add('SeSecurityPrivilege')
    }
    $ownerOrGroup =
        [System.Security.AccessControl.AccessControlSections]::Owner -bor
        [System.Security.AccessControl.AccessControlSections]::Group
    if (($Sections -band $ownerOrGroup) -ne 0) {
        Initialize-WindowsAccessControlNativeType
        $tokenPrivilegeNames = @(
            [WindowsAccessControl.NativeMethods]::GetTokenPrivileges()
        ).Name
        if ('SeRestorePrivilege' -in $tokenPrivilegeNames) {
            $requiredPrivileges.Add('SeRestorePrivilege')
        }
    }

    if ($requiredPrivileges.Count -gt 0) {
        $privilegeParameters = @{
            Name        = $requiredPrivileges.ToArray()
            ScriptBlock = $persistDescriptor
            ArgumentList = $persistenceArguments
        }
        Invoke-WithWindowsPrivilege @privilegeParameters
    } else {
        & $persistDescriptor @persistenceArguments
    }
}
