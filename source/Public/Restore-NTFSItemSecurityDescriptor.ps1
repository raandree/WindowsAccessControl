function Restore-NTFSItemSecurityDescriptor {
    <#
    .SYNOPSIS
        Restores NTFS security descriptors from JSON backup.

    .DESCRIPTION
        Validates a schema-versioned backup and restores only the descriptor
        sections recorded for each original path. Backup content is parsed as
        data and never evaluated as PowerShell code.

    .PARAMETER BackupPath
        The literal path to a JSON backup created by Backup-NTFSItemSecurityDescriptor.

    .PARAMETER PassThru
        Returns each restored security descriptor after persistence.

    .EXAMPLE
        Restore-NTFSItemSecurityDescriptor -BackupPath C:\Backup\permissions.json -Confirm:$false

        Restores all valid records in the selected backup file.

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
        [switch]$PassThru
    )

    $backup = Get-Content -LiteralPath $BackupPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($backup.SchemaVersion -ne 1 -or $null -eq $backup.Records) {
        throw 'The backup document is not a supported WindowsAccessControl schema.'
    }
    if ([string]$backup.Format -ceq
        'WindowsAccessControl.SecurityDescriptorBackup') {
        foreach ($record in @($backup.Records)) {
            if ([string]$record.ObjectFamily -ne 'FileSystem') {
                throw 'Restore-NTFSItemSecurityDescriptor accepts only filesystem backup records.'
            }
        }
        $restoreParameters = @{
            BackupPath = $BackupPath
            PassThru   = $PassThru
            WhatIf     = $WhatIfPreference
        }
        Restore-WindowsSecurityDescriptor @restoreParameters
        return
    }

    $validatedRecords = [System.Collections.Generic.List[object]]::new()
    $validatedPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($record in @($backup.Records)) {
        if ([string]::IsNullOrWhiteSpace([string]$record.Path) -or
            [string]::IsNullOrWhiteSpace([string]$record.Sddl) -or
            [string]$record.ItemType -notin @('File', 'Directory')) {
            throw 'The backup contains an invalid security descriptor record.'
        }
        $sectionValue = 0
        if (-not [int]::TryParse([string]$record.Sections, [ref]$sectionValue) -or
            $sectionValue -lt 1 -or $sectionValue -gt 15) {
            throw "The backup record for '$($record.Path)' has invalid sections."
        }
        $sections = [System.Security.AccessControl.AccessControlSections]$sectionValue
        $items = @(Resolve-NTFSPath -LiteralPath ([string]$record.Path))
        if ($items.Count -ne 1) {
            throw "Backup path '$($record.Path)' does not resolve to one item."
        }
        $item = $items[0]
        $actualType = if ($item.PSIsContainer) { 'Directory' } else { 'File' }
        if ($actualType -ne [string]$record.ItemType) {
            throw "Backup item type for '$($record.Path)' does not match the filesystem item."
        }
        if (-not $validatedPaths.Add($item.FullName)) {
            throw "The backup contains duplicate records for '$($item.FullName)'."
        }

        $security = Get-NTFSSecurityDescriptorForItem -Item $item -Sections $sections
        $security.SetSecurityDescriptorSddlForm([string]$record.Sddl, $sections)
        $validatedRecords.Add([pscustomobject]@{
            Item     = $item
            Sections = $sections
            Security = $security
        })
    }

    foreach ($validatedRecord in $validatedRecords) {
        if ($PSCmdlet.ShouldProcess(
            $validatedRecord.Item.FullName,
            "Restore $($validatedRecord.Sections) security descriptor sections"
        )) {
            $persistenceParameters = @{
                Item     = $validatedRecord.Item
                Security = $validatedRecord.Security
                Sections = $validatedRecord.Sections
            }
            Invoke-NTFSSecurityDescriptorPersistence @persistenceParameters
            if ($PassThru) {
                $updated = Get-NTFSSecurityDescriptorForItem `
                    -Item $validatedRecord.Item `
                    -Sections $validatedRecord.Sections
                ConvertTo-NTFSSecurityDescriptorObject `
                    -Item $validatedRecord.Item `
                    -Security $updated `
                    -Sections $validatedRecord.Sections
            }
        }
    }
}
