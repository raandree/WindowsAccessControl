function Restore-WindowsSecurityDescriptor {
    <#
    .SYNOPSIS
        Restores Windows security descriptors from a unified JSON backup.
    .DESCRIPTION
        Parses a versioned backup as data, validates every record and SHA-256
        digest, resolves every target, and only then restores the selected
        descriptor sections. Invalid later records fail before the first write.
        Schema version 2 additionally restores SMB share records on their
        originating computer and Active Directory records through one pinned
        writable domain controller inside an explicit allowed organizational
        unit, matched by immutable object GUID and domain partition. Task
        Scheduler records restore on their originating computer inside an
        explicit allowed root path.
    .PARAMETER BackupPath
        The literal path to a unified backup created by
        Backup-WindowsSecurityDescriptor.
    .PARAMETER PassThru
        Returns each restored security descriptor after persistence.
    .PARAMETER VerificationCertificate
        The RSA X.509 certificate required to verify every signed record.
    .PARAMETER Server
        The explicit DNS name of the writable domain controller used for every
        Active Directory record. When it is omitted, one writable domain
        controller is located in the current computer's domain and pinned.
    .PARAMETER AllowedBaseDistinguishedName
        The organizational unit that bounds every Active Directory restore. It
        is required when the backup contains Active Directory records.
    .PARAMETER AllowedRootPath
        The non-system task folder that bounds every Task Scheduler restore. It
        is required when the backup contains Task Scheduler records.
    .PARAMETER Credential
        An optional credential used only for the direct LDAP bind to Server.
    .PARAMETER TimeoutSeconds
        Sets the LDAP request timeout from 1 through 300 seconds.
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
        [string]$Server,

        [Parameter()]
        [string]$AllowedBaseDistinguishedName,

        [Parameter()]
        [string]$AllowedRootPath,

        [Parameter()]
        [pscredential]$Credential,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10,

        [Parameter()]
        [switch]$PassThru
    )

    $backup = Get-Content -LiteralPath $BackupPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $schemaVersion = 0
    if (-not [int]::TryParse([string]$backup.SchemaVersion, [ref]$schemaVersion) -or
        $schemaVersion -notin @(1, 2) -or
        [string]$backup.Format -cne
            'WindowsAccessControl.SecurityDescriptorBackup' -or
        $null -eq $backup.Records) {
        throw 'The backup document is not a supported WindowsAccessControl schema.'
    }

    $validatedRecords = [System.Collections.Generic.List[object]]::new()
    $validatedIdentities = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($record in @($backup.Records)) {
        $validationParameters = @{ Record = $record }
        if ($VerificationCertificate) {
            $validationParameters.VerificationCertificate = $VerificationCertificate
        }
        $validatedRecord = ConvertFrom-WindowsSecurityDescriptorBackupRecord `
            @validationParameters
        if ($validatedRecord.RecordVersion -gt $schemaVersion) {
            throw "The backup document declares schema version $schemaVersion but contains a version $($validatedRecord.RecordVersion) record for '$($validatedRecord.CanonicalTarget)'."
        }
        $identity = Get-WindowsSecurityDescriptorRecordIdentity -Record $validatedRecord
        if (-not $validatedIdentities.Add($identity)) {
            throw "The backup contains duplicate records for '$identity'."
        }
        $validatedRecords.Add($validatedRecord)
    }
    if ($validatedRecords.Count -eq 0) {
        throw 'The backup document does not contain any descriptor records.'
    }
    if (-not $VerificationCertificate -and @(
            $validatedRecords | Where-Object RecordVersion -GE 2
        ).Count -gt 0) {
        Write-Warning (
            'Restoring enterprise records without a verification certificate. ' +
            'The SHA-256 digest is unkeyed, so it detects accidental damage ' +
            'but not deliberate modification.'
        )
    }

    $directoryServer = $null
    if (@($validatedRecords | Where-Object ObjectFamily -EQ 'ADObject').Count -gt 0) {
        if ([string]::IsNullOrWhiteSpace($AllowedBaseDistinguishedName)) {
            throw 'AllowedBaseDistinguishedName is required to restore Active Directory records.'
        }
        $directoryServer = Resolve-WindowsADServer -Server $Server
    }
    if (@($validatedRecords | Where-Object {
            $_.ObjectFamily -in @('TaskFolder', 'ScheduledTask')
        }).Count -gt 0 -and [string]::IsNullOrWhiteSpace($AllowedRootPath)) {
        throw 'AllowedRootPath is required to restore Task Scheduler records.'
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
            'SmbShare' {
                if (-not [string]::Equals(
                        [string]$record.Server,
                        [System.Environment]::MachineName,
                        [System.StringComparison]::OrdinalIgnoreCase
                    )) {
                    throw "SMB share backup record '$($record.CanonicalTarget)' was captured on another server. Run the restore on that computer."
                }
                $descriptor = Get-SmbShareSecurityDescriptor `
                    -Name $record.ShareName `
                    -ThrottleLimit 1
                [pscustomobject]@{
                    Record          = $record
                    Item            = $null
                    ManagedSections = $null
                    Security        = $null
                    Descriptor      = $descriptor
                }
            }
            'ADObject' {
                # Resolve for write so the allowed base, base object class,
                # protected targets, excluded partitions, and immutable object
                # GUID are all rejected before any earlier record is written.
                $target = Resolve-WindowsADObjectTarget `
                    -Server $directoryServer `
                    -DistinguishedName $record.DistinguishedName `
                    -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                    -Credential $Credential `
                    -TimeoutSeconds $TimeoutSeconds `
                    -ForWrite `
                    -ExpectedObjectGuid $record.ObjectGuid
                if (-not [string]::Equals(
                        [string]$target.DefaultNamingContext,
                        $record.DomainNamingContext,
                        [System.StringComparison]::OrdinalIgnoreCase
                    )) {
                    throw "Active Directory backup target '$($record.DistinguishedName)' is served from another domain partition."
                }
                [pscustomobject]@{
                    Record          = $record
                    Item            = $null
                    ManagedSections = $null
                    Security        = $null
                    Descriptor      = $null
                }
            }
            { $_ -in @('TaskFolder', 'ScheduledTask') } {
                if (-not [string]::Equals(
                        [string]$record.Server,
                        [System.Environment]::MachineName,
                        [System.StringComparison]::OrdinalIgnoreCase
                    )) {
                    throw "Task Scheduler backup record '$($record.CanonicalTarget)' was captured on another computer. Run the restore on that computer."
                }
                # Resolve for write so the root, Microsoft system tree, and
                # allowed root path all reject a bad record before any earlier
                # record is written.
                $resolveParameters = @{
                    Path            = $record.TaskPath
                    ForWrite        = $true
                    AllowedRootPath = $AllowedRootPath
                }
                if ($record.ObjectFamily -eq 'ScheduledTask') {
                    $resolveParameters.TaskName = $record.TaskName
                }
                $target = Resolve-WindowsTaskSchedulerTarget @resolveParameters
                if ($target.CanonicalTarget -cne $record.CanonicalTarget) {
                    throw "Task Scheduler backup target '$($record.Target)' does not match its canonical identity."
                }
                $descriptor = if ($record.ObjectFamily -eq 'ScheduledTask') {
                    Get-ScheduledTaskSecurityDescriptor `
                        -TaskPath $record.TaskPath `
                        -TaskName $record.TaskName `
                        -ThrottleLimit 1
                } else {
                    Get-TaskFolderSecurityDescriptor `
                        -Path $record.TaskPath `
                        -ThrottleLimit 1
                }
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

        # A directory record carries no descriptor here: its canonical target
        # names the domain controller that produced the backup, and a restore
        # may legitimately bind a different writable one. The prepare branch
        # verified it by immutable object GUID and domain partition instead.
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
                'SmbShare' {
                    $setParameters = @{
                        Name          = $preparedRecord.Record.ShareName
                        Sddl          = $preparedRecord.Record.Sddl
                        ThrottleLimit = 1
                        Confirm       = $false
                        PassThru      = $PassThru
                    }
                    Set-SmbShareSecurityDescriptor @setParameters
                    break
                }
                'ADObject' {
                    $setParameters = @{
                        Server                       = $directoryServer
                        DistinguishedName            = $preparedRecord.Record.DistinguishedName
                        AllowedBaseDistinguishedName = $AllowedBaseDistinguishedName
                        Sddl                         = $preparedRecord.Record.Sddl
                        Credential                   = $Credential
                        TimeoutSeconds               = $TimeoutSeconds
                        ThrottleLimit                = 1
                        Confirm                      = $false
                        PassThru                     = $PassThru
                    }
                    Set-ADObjectSecurityDescriptor @setParameters
                    break
                }
                'TaskFolder' {
                    $setParameters = @{
                        Path            = $preparedRecord.Record.TaskPath
                        AllowedRootPath = $AllowedRootPath
                        Sddl            = $preparedRecord.Record.Sddl
                        ThrottleLimit   = 1
                        Confirm         = $false
                        PassThru        = $PassThru
                    }
                    Set-TaskFolderSecurityDescriptor @setParameters
                    break
                }
                'ScheduledTask' {
                    $setParameters = @{
                        TaskPath        = $preparedRecord.Record.TaskPath
                        TaskName        = $preparedRecord.Record.TaskName
                        AllowedRootPath = $AllowedRootPath
                        Sddl            = $preparedRecord.Record.Sddl
                        ThrottleLimit   = 1
                        Confirm         = $false
                        PassThru        = $PassThru
                    }
                    Set-ScheduledTaskSecurityDescriptor @setParameters
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
