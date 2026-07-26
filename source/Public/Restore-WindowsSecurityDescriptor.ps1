function Restore-WindowsSecurityDescriptor {
    <#
    .SYNOPSIS
        Restores Windows security descriptors from a unified JSON backup.
    .DESCRIPTION
        Parses a versioned backup as data, validates every record and SHA-256
        digest, resolves every target, and only then restores the selected
        descriptor sections. Invalid later records fail before the first write.
    .PARAMETER BackupPath
        The literal path to a unified backup created by
        Backup-WindowsSecurityDescriptor.
    .PARAMETER PassThru
        Returns each restored security descriptor after persistence.
    .PARAMETER VerificationCertificate
        The RSA X.509 certificate required to verify every signed record.
    .EXAMPLE
        Restore-WindowsSecurityDescriptor `
            -BackupPath C:\Backup\acl.json `
            -Confirm:$false

        Verifies and restores every record in the unified backup.
    .INPUTS
        None
    .OUTPUTS
        None
        WindowsAccessControl.SecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$BackupPath,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$VerificationCertificate,

        [Parameter()]
        [switch]$PassThru
    )

    $backup = Get-Content -LiteralPath $BackupPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ($backup.SchemaVersion -ne 1 -or
        [string]$backup.Format -cne
            'WindowsAccessControl.SecurityDescriptorBackup' -or
        $null -eq $backup.Records) {
        throw 'The backup document is not a supported WindowsAccessControl schema.'
    }

    $validatedRecords = [System.Collections.Generic.List[object]]::new()
    $validatedTargets = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($record in @($backup.Records)) {
        $validationParameters = @{ Record = $record }
        if ($VerificationCertificate) {
            $validationParameters.VerificationCertificate = $VerificationCertificate
        }
        $validatedRecord = ConvertFrom-WindowsSecurityDescriptorBackupRecord `
            @validationParameters
        if (-not $validatedTargets.Add($validatedRecord.CanonicalTarget)) {
            throw "The backup contains duplicate records for '$($validatedRecord.CanonicalTarget)'."
        }
        $validatedRecords.Add($validatedRecord)
    }
    if ($validatedRecords.Count -eq 0) {
        throw 'The backup document does not contain any descriptor records.'
    }

    $preparedRecords = [System.Collections.Generic.List[object]]::new()
    foreach ($record in $validatedRecords) {
        $preparedRecord = switch ($record.ObjectFamily) {
            'FileSystem' {
                $items = @(Resolve-NTFSPath -LiteralPath $record.Target)
                if ($items.Count -ne 1) {
                    throw "Backup target '$($record.Target)' does not resolve to one item."
                }
                $item = $items[0]
                $actualType = if ($item.PSIsContainer) { 'Directory' } else { 'File' }
                if ($actualType -ne $record.ItemType) {
                    throw "Backup item type for '$($record.Target)' does not match the filesystem item."
                }
                $managedSections = ConvertTo-WindowsAccessControlSection `
                    -Sections $record.Sections
                $security = Get-NTFSSecurityDescriptorForItem `
                    -Item $item `
                    -Sections $managedSections
                $security.SetSecurityDescriptorSddlForm($record.Sddl, $managedSections)
                [pscustomobject]@{
                    Record          = $record
                    Item            = $item
                    ManagedSections = $managedSections
                    Security        = $security
                    Descriptor      = $null
                }
            }
            'RegistryKey' {
                $descriptor = Get-RegistryKeySecurityDescriptor `
                    -Path $record.Target `
                    -RegistryView ([WindowsRegistryView]$record.RegistryView) `
                    -Sections $record.Sections
                [pscustomobject]@{
                    Record          = $record
                    Item            = $null
                    ManagedSections = $null
                    Security        = $null
                    Descriptor      = $descriptor
                }
            }
            'Service' {
                $descriptor = Get-ServiceSecurityDescriptor `
                    -Name $record.Target `
                    -Sections $record.Sections
                [pscustomobject]@{
                    Record          = $record
                    Item            = $null
                    ManagedSections = $null
                    Security        = $null
                    Descriptor      = $descriptor
                }
            }
            'ServiceControlManager' {
                $descriptor = Get-ServiceSecurityDescriptor `
                    -ServiceControlManager `
                    -Sections $record.Sections
                [pscustomobject]@{
                    Record          = $record
                    Item            = $null
                    ManagedSections = $null
                    Security        = $null
                    Descriptor      = $descriptor
                }
            }
            'Process' {
                $processIdentity = [pscustomobject]@{
                    ObjectType           = 'Process'
                    ProcessId            = $record.ProcessId
                    ProcessName          = $null
                    CreationTime         = $null
                    CreationTimeFileTime = $record.CreationTimeFileTime
                }
                $descriptor = Get-ProcessSecurityDescriptor `
                    -InputObject $processIdentity `
                    -Sections $record.Sections
                [pscustomobject]@{
                    Record          = $record
                    Item            = $null
                    ManagedSections = $null
                    Security        = $null
                    Descriptor      = $descriptor
                }
            }
            default {
                throw [System.IO.InvalidDataException]::new(
                    "Unsupported object family '$($record.ObjectFamily)'."
                )
            }
        }

        if ($preparedRecord.Descriptor -and -not [string]::Equals(
            [string]$preparedRecord.Descriptor.CanonicalTarget,
            $record.CanonicalTarget,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Backup target '$($record.Target)' does not match its canonical identity."
        }
        $preparedRecords.Add($preparedRecord)
    }

    foreach ($preparedRecord in $preparedRecords) {
        if ($PSCmdlet.ShouldProcess(
            $preparedRecord.Record.CanonicalTarget,
            "Restore $($preparedRecord.Record.Sections) security descriptor sections"
        )) {
            switch ($preparedRecord.Record.ObjectFamily) {
                'FileSystem' {
                    $persistenceParameters = @{
                        Item     = $preparedRecord.Item
                        Security = $preparedRecord.Security
                        Sections = $preparedRecord.ManagedSections
                    }
                    Invoke-NTFSSecurityDescriptorPersistence @persistenceParameters
                    if ($PassThru) {
                        $updated = Get-NTFSSecurityDescriptorForItem `
                            -Item $preparedRecord.Item `
                            -Sections $preparedRecord.ManagedSections
                        ConvertTo-NTFSSecurityDescriptorObject `
                            -Item $preparedRecord.Item `
                            -Security $updated `
                            -Sections $preparedRecord.ManagedSections
                    }
                    break
                }
                'RegistryKey' {
                    $setParameters = @{
                        Path         = $preparedRecord.Record.Target
                        RegistryView = [WindowsRegistryView]$preparedRecord.Record.RegistryView
                        Sddl         = $preparedRecord.Record.Sddl
                        Sections     = $preparedRecord.Record.Sections
                        Confirm      = $false
                        PassThru     = $PassThru
                    }
                    Set-RegistryKeySecurityDescriptor @setParameters
                    break
                }
                'Service' {
                    $setParameters = @{
                        Name     = $preparedRecord.Record.Target
                        Sddl     = $preparedRecord.Record.Sddl
                        Sections = $preparedRecord.Record.Sections
                        Confirm  = $false
                        PassThru = $PassThru
                    }
                    Set-ServiceSecurityDescriptor @setParameters
                    break
                }
                'ServiceControlManager' {
                    $setParameters = @{
                        ServiceControlManager = $true
                        Sddl                  = $preparedRecord.Record.Sddl
                        Sections              = $preparedRecord.Record.Sections
                        Confirm               = $false
                        PassThru              = $PassThru
                    }
                    Set-ServiceSecurityDescriptor @setParameters
                    break
                }
                'Process' {
                    $setParameters = @{
                        InputObject = $preparedRecord.Descriptor
                        Sddl        = $preparedRecord.Record.Sddl
                        Sections    = $preparedRecord.Record.Sections
                        Confirm     = $false
                        PassThru    = $PassThru
                    }
                    Set-ProcessSecurityDescriptor @setParameters
                    break
                }
                default {
                    throw [System.IO.InvalidDataException]::new(
                        "Unsupported object family '$($preparedRecord.Record.ObjectFamily)'."
                    )
                }
            }
        }
    }
}
