function Backup-WindowsSecurityDescriptor {
    <#
    .SYNOPSIS
        Backs up Windows security descriptor objects to one JSON envelope.
    .DESCRIPTION
        Accepts security descriptors emitted by WindowsAccessControl, normalizes
        their object-family metadata and section masks, and writes versioned,
        non-executable JSON records protected by SHA-256 digests. Local object
        families use record version 1; SMB share and Active Directory records
        use record version 2 and additionally bind explicit server authority
        plus immutable target identity. The envelope schema version is the
        highest record version it contains. The completed envelope atomically
        replaces its destination.
    .PARAMETER InputObject
        One or more security descriptor objects emitted by WindowsAccessControl.
    .PARAMETER DestinationPath
        The literal JSON file path written after all input is validated.
    .PARAMETER Force
        Allows an existing backup file to be overwritten.
    .PARAMETER SigningCertificate
        An RSA X.509 certificate with a private key used to sign each record
        after ShouldProcess approves the destination write.
    .PARAMETER PassThru
        Returns each normalized backup record after the file is written.
    .EXAMPLE
        Get-NTFSItemSecurityDescriptor C:\Data -Sections Access |
            Backup-WindowsSecurityDescriptor -DestinationPath C:\Backup\acl.json

        Backs up the selected filesystem DACL in the unified envelope.
    .INPUTS
        WindowsAccessControl.SecurityDescriptor
    .OUTPUTS
        None
        WindowsAccessControl.SecurityDescriptorBackupRecord
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [psobject[]]$InputObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DestinationPath,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $records = [System.Collections.Generic.List[object]]::new()
        $recordIdentities = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
    }

    process {
        foreach ($descriptor in $InputObject) {
            $record = ConvertTo-WindowsSecurityDescriptorBackupRecord `
                -InputObject $descriptor
            $identity = Get-WindowsSecurityDescriptorRecordIdentity -Record $record
            if (-not $recordIdentities.Add($identity)) {
                throw "The backup contains duplicate records for '$identity'."
            }
            $records.Add($record)
        }
    }

    end {
        if ($records.Count -eq 0) {
            throw [System.ArgumentException]::new(
                'At least one security descriptor is required.'
            )
        }

        $resolvedDestination = [System.IO.Path]::GetFullPath($DestinationPath)
        $parentPath = [System.IO.Path]::GetDirectoryName($resolvedDestination)
        if (-not [System.IO.Directory]::Exists($parentPath)) {
            throw "Backup destination directory does not exist: $parentPath"
        }
        if ([System.IO.Directory]::Exists($resolvedDestination)) {
            throw "Backup destination is a directory: $resolvedDestination"
        }
        $destinationExists = [System.IO.File]::Exists($resolvedDestination)
        if ($destinationExists -and -not $Force) {
            throw "Backup destination already exists: $resolvedDestination. Use Force to overwrite it."
        }
        $action = if ($destinationExists) {
            "Overwrite with $($records.Count) security descriptor records"
        } else {
            "Write $($records.Count) security descriptor records"
        }
        if ($PSCmdlet.ShouldProcess($resolvedDestination, $action)) {
            if ($SigningCertificate) {
                for ($index = 0; $index -lt $records.Count; $index++) {
                    $records[$index] = Protect-WindowsSecurityDescriptorBackupRecord `
                        -Record $records[$index] `
                        -Certificate $SigningCertificate
                }
            }
            $schemaVersion = 1
            foreach ($record in $records) {
                if ([int]$record.RecordVersion -gt $schemaVersion) {
                    $schemaVersion = [int]$record.RecordVersion
                }
            }
            $backup = [ordered]@{
                SchemaVersion = $schemaVersion
                Format        = 'WindowsAccessControl.SecurityDescriptorBackup'
                CreatedUtc    = [DateTime]::UtcNow.ToString('o')
                Records       = $records.ToArray()
            }
            $json = $backup | ConvertTo-Json -Depth 8
            Write-WindowsSecurityDescriptorBackupFile `
                -Path $resolvedDestination `
                -Content $json `
                -DestinationExists $destinationExists
            if ($PassThru) {
                foreach ($record in $records) {
                    $record
                }
            }
        }
    }
}
