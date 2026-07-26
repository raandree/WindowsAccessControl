function Write-WindowsSecurityDescriptorBackupFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Content,

        [Parameter(Mandatory)]
        [bool]$DestinationExists
    )

    $parentPath = [System.IO.Path]::GetDirectoryName($Path)
    $temporaryName = '.{0}.{1}.tmp' -f (
        [System.IO.Path]::GetFileName($Path),
        [guid]::NewGuid().ToString('N')
    )
    $temporaryPath = [System.IO.Path]::Combine($parentPath, $temporaryName)
    $replacementBackupPath = '{0}.bak' -f $temporaryPath
    $encoding = [System.Text.UTF8Encoding]::new($false)
    try {
        [System.IO.File]::WriteAllText($temporaryPath, $Content, $encoding)
        if ($DestinationExists) {
            [System.IO.File]::Replace(
                $temporaryPath,
                $Path,
                $replacementBackupPath
            )
        } else {
            [System.IO.File]::Move($temporaryPath, $Path)
        }
    } finally {
        if ([System.IO.File]::Exists($temporaryPath)) {
            try {
                [System.IO.File]::Delete($temporaryPath)
            } catch {
                Write-Warning `
                    "Could not remove backup temporary file '$temporaryPath': $($_.Exception.Message)" `
                    -WarningAction Continue
            }
        }
        if ([System.IO.File]::Exists($replacementBackupPath)) {
            try {
                [System.IO.File]::Delete($replacementBackupPath)
            } catch {
                Write-Warning `
                    "Could not remove backup rollback file '$replacementBackupPath': $($_.Exception.Message)" `
                    -WarningAction Continue
            }
        }
    }
}
