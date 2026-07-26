function ConvertTo-WindowsSecurityDescriptorBackupRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [psobject]$InputObject
    )

    process {
        if ($InputObject.PSObject.TypeNames -notcontains
            'WindowsAccessControl.SecurityDescriptor') {
            throw [System.ArgumentException]::new(
                'InputObject must be a security descriptor emitted by WindowsAccessControl.'
            )
        }
        $sddlProperty = $InputObject.PSObject.Properties['Sddl']
        if (-not $sddlProperty -or $null -eq $sddlProperty.Value) {
            throw [System.ArgumentException]::new(
                'The security descriptor does not contain SDDL.'
            )
        }
        $rawDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            [string]$sddlProperty.Value
        )

        $recordValues = [ordered]@{
            RecordVersion         = 1
            ObjectFamily         = $null
            Target               = $null
            Path                 = $null
            CanonicalTarget      = $null
            ItemType             = $null
            RegistryView         = $null
            ProcessId            = $null
            CreationTimeFileTime = $null
            Sections             = 0
            Sddl                 = [string]$InputObject.Sddl
            Integrity            = $null
        }

        if ($InputObject.PSObject.Properties['ItemType'] -and
            $InputObject.PSObject.Properties['Path'] -and
            -not $InputObject.PSObject.Properties['ObjectType']) {
            if ([string]$InputObject.ItemType -notin @('File', 'Directory')) {
                throw [System.ArgumentException]::new(
                    'A filesystem security descriptor requires File or Directory item type.'
                )
            }
            $recordValues.ObjectFamily = 'FileSystem'
            $recordValues.Target = [System.IO.Path]::GetFullPath(
                [string]$InputObject.Path
            )
            $recordValues.Path = $recordValues.Target
            $recordValues.CanonicalTarget = $recordValues.Target
            $recordValues.ItemType = [string]$InputObject.ItemType

            $managedSections = [int]$InputObject.Sections
            if (($managedSections -band
                [int][System.Security.AccessControl.AccessControlSections]::Owner) -ne 0) {
                $recordValues.Sections = $recordValues.Sections -bor 1
            }
            if (($managedSections -band
                [int][System.Security.AccessControl.AccessControlSections]::Group) -ne 0) {
                $recordValues.Sections = $recordValues.Sections -bor 2
            }
            if (($managedSections -band
                [int][System.Security.AccessControl.AccessControlSections]::Access) -ne 0) {
                $recordValues.Sections = $recordValues.Sections -bor 4
            }
            if (($managedSections -band
                [int][System.Security.AccessControl.AccessControlSections]::Audit) -ne 0) {
                $recordValues.Sections = $recordValues.Sections -bor 8
            }
        } elseif ($InputObject.PSObject.Properties['ObjectType']) {
            $recordValues.Sections = [int]$InputObject.Sections
            switch ([string]$InputObject.ObjectType) {
                'RegistryKey' {
                    $recordValues.ObjectFamily = 'RegistryKey'
                    $recordValues.Target = [string]$InputObject.Path
                    $recordValues.CanonicalTarget = [string]$InputObject.CanonicalTarget
                    $recordValues.RegistryView = [string]$InputObject.RegistryView
                    break
                }
                'Service' {
                    $recordValues.ObjectFamily = 'Service'
                    $recordValues.Target = [string]$InputObject.ServiceName
                    $recordValues.CanonicalTarget = [string]$InputObject.CanonicalTarget
                    break
                }
                'ServiceControlManager' {
                    $recordValues.ObjectFamily = 'ServiceControlManager'
                    $recordValues.Target = [string]$InputObject.Path
                    $recordValues.CanonicalTarget = [string]$InputObject.CanonicalTarget
                    break
                }
                'Process' {
                    $processId = [int]$InputObject.ProcessId
                    $creationTimeFileTime = [long]$InputObject.CreationTimeFileTime
                    if ($processId -le 0 -or $creationTimeFileTime -le 0) {
                        throw [System.ArgumentException]::new(
                            'A process backup requires a positive PID and creation identity.'
                        )
                    }
                    $recordValues.ObjectFamily = 'Process'
                    $recordValues.Target = 'PID:{0}' -f $processId
                    $recordValues.CanonicalTarget = [string]$InputObject.CanonicalTarget
                    $recordValues.ProcessId = $processId
                    $recordValues.CreationTimeFileTime = $creationTimeFileTime
                    break
                }
                default {
                    throw [System.ArgumentException]::new(
                        "Security descriptor object family '$($InputObject.ObjectType)' is not supported for backup."
                    )
                }
            }
            if ([string]::IsNullOrWhiteSpace($recordValues.Target) -or
                [string]::IsNullOrWhiteSpace($recordValues.CanonicalTarget)) {
                throw [System.ArgumentException]::new(
                    'The security descriptor does not contain a canonical target identity.'
                )
            }
        } else {
            throw [System.ArgumentException]::new(
                'The security descriptor object family is not supported for backup.'
            )
        }

        if ($recordValues.Sections -lt 1 -or $recordValues.Sections -gt 15) {
            throw [System.ArgumentException]::new(
                'The security descriptor does not select a supported section.'
            )
        }

        $selectedSections = [WindowsSecurityDescriptorSection]$recordValues.Sections
        if (($selectedSections -band [WindowsSecurityDescriptorSection]::Owner) -ne 0 -and
            -not $rawDescriptor.Owner) {
            throw [System.ArgumentException]::new(
                'The security descriptor does not contain an owner.'
            )
        }
        if (($selectedSections -band [WindowsSecurityDescriptorSection]::Group) -ne 0 -and
            -not $rawDescriptor.Group) {
            throw [System.ArgumentException]::new(
                'The security descriptor does not contain a primary group.'
            )
        }
        if (($selectedSections -band [WindowsSecurityDescriptorSection]::Access) -ne 0 -and
            -not $rawDescriptor.DiscretionaryAcl) {
            throw [System.ArgumentException]::new(
                'The security descriptor does not contain a non-null DACL.'
            )
        }
        $managedSections = ConvertTo-WindowsAccessControlSection `
            -Sections $selectedSections
        $recordValues.Sddl = $rawDescriptor.GetSddlForm($managedSections)
        $systemAclPresent = ([int]$rawDescriptor.ControlFlags -band
            [int][System.Security.AccessControl.ControlFlags]::SystemAclPresent) -ne 0
        if (($selectedSections -band [WindowsSecurityDescriptorSection]::Audit) -ne 0 -and
            -not $systemAclPresent) {
            throw [System.ArgumentException]::new(
                'The security descriptor does not explicitly represent the selected SACL.'
            )
        }

        $record = [pscustomobject]$recordValues
        $hash = Get-WindowsSecurityDescriptorRecordHash -Record $record
        $digest = -join @($hash | ForEach-Object {
            $_.ToString('X2', [System.Globalization.CultureInfo]::InvariantCulture)
        })
        $record.Integrity = [pscustomobject][ordered]@{
            Algorithm = 'SHA256'
            Digest    = $digest
        }
        $record.PSObject.TypeNames.Insert(
            0,
            'WindowsAccessControl.SecurityDescriptorBackupRecord'
        )
        $record
    }
}
