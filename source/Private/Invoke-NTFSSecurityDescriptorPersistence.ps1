function Invoke-NTFSSecurityDescriptorPersistence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileSystemInfo]$Item,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemSecurity]$Security,

        [Parameter()]
        [ValidateSet('Access', 'Audit', 'All')]
        [string]$ProtectionSection
    )

    if ($PSVersionTable.PSEdition -eq 'Core') {
        if ($Item.PSIsContainer) {
            [System.IO.FileSystemAclExtensions]::SetAccessControl(
                [System.IO.DirectoryInfo]$Item,
                [System.Security.AccessControl.DirectorySecurity]$Security
            )
        } else {
            [System.IO.FileSystemAclExtensions]::SetAccessControl(
                [System.IO.FileInfo]$Item,
                [System.Security.AccessControl.FileSecurity]$Security
            )
        }
    } elseif ($Item.PSIsContainer) {
        [System.IO.Directory]::SetAccessControl(
            $Item.FullName,
            [System.Security.AccessControl.DirectorySecurity]$Security
        )
    } else {
        [System.IO.File]::SetAccessControl(
            $Item.FullName,
            [System.Security.AccessControl.FileSecurity]$Security
        )
    }

    if ($ProtectionSection) {
        Initialize-NTFSNativeType
        [NTFSPermission.NativeMethods]::SetFileSystemAclProtection(
            $Item.FullName,
            $Security.GetSecurityDescriptorBinaryForm(),
            $ProtectionSection -in @('Access', 'All'),
            $Security.AreAccessRulesProtected,
            $ProtectionSection -in @('Audit', 'All'),
            $Security.AreAuditRulesProtected
        )
    }
}