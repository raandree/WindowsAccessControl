function Set-WindowsAccessControlDscSecurityDescriptor {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'The DSC engine invokes this private adapter only from resource Set().'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('FileSystem', 'RegistryKey', 'Service', 'ServiceControlManager', 'Process', 'SmbShare', 'ADObject', 'TaskFolder', 'ScheduledTask')]
        [string]$ObjectFamily,

        [Parameter()]
        [string]$Target,

        [Parameter()]
        [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,

        [Parameter()]
        [uint32]$ProcessId,

        [Parameter()]
        [int64]$CreationTimeFileTime,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$TaskName,

        [Parameter()]
        [string]$AllowedRootPath,

        [Parameter()]
        [string]$AllowedBaseDistinguishedName,

        [Parameter()]
        [string]$ObjectGuid,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Sddl
    )

    if ([int]$Sections -le 0 -or [int]$Sections -gt 15) {
        throw [System.ArgumentOutOfRangeException]::new('Sections')
    }
    if ($ObjectFamily -in @('SmbShare', 'ADObject', 'TaskFolder', 'ScheduledTask') -and
        $Sections -ne [WindowsSecurityDescriptorSection]::Access) {
        throw [System.ArgumentException]::new(
            "Object family $ObjectFamily manages only the access section."
        )
    }
    if ($ObjectFamily -in @('TaskFolder', 'ScheduledTask') -and
        [string]::IsNullOrWhiteSpace($AllowedRootPath)) {
        throw [System.ArgumentException]::new(
            'AllowedRootPath is required for Task Scheduler writes.'
        )
    }

    switch ($ObjectFamily) {
        'FileSystem' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw [System.ArgumentException]::new(
                    'A filesystem target path is required.'
                )
            }
            Set-WindowsNtfsDscSecurityDescriptor `
                -Path $Target `
                -Sections $Sections `
                -Sddl $Sddl `
                -ErrorAction Stop
            break
        }
        'RegistryKey' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw [System.ArgumentException]::new(
                    'A registry key target path is required.'
                )
            }
            Set-RegistryKeySecurityDescriptor `
                -Path $Target `
                -RegistryView $RegistryView `
                -Sections $Sections `
                -Sddl $Sddl `
                -ThrottleLimit 1 `
                -Confirm:$false `
                -ErrorAction Stop
            break
        }
        'Service' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw [System.ArgumentException]::new(
                    'A service name is required.'
                )
            }
            Set-ServiceSecurityDescriptor `
                -Name $Target `
                -Sections $Sections `
                -Sddl $Sddl `
                -ThrottleLimit 1 `
                -Confirm:$false `
                -ErrorAction Stop
            break
        }
        'ServiceControlManager' {
            Set-ServiceSecurityDescriptor `
                -ServiceControlManager `
                -Sections $Sections `
                -Sddl $Sddl `
                -ThrottleLimit 1 `
                -Confirm:$false `
                -ErrorAction Stop
            break
        }
        'Process' {
            if ($ProcessId -eq 0 -or $CreationTimeFileTime -le 0) {
                throw [System.ArgumentException]::new(
                    'A positive process ID and creation FILETIME are required.'
                )
            }
            $processIdentity = [pscustomobject]@{
                ObjectType           = 'Process'
                ProcessId            = [int]$ProcessId
                ProcessName          = $null
                CreationTime         = $null
                CreationTimeFileTime = $CreationTimeFileTime
            }
            Set-ProcessSecurityDescriptor `
                -InputObject $processIdentity `
                -Sections $Sections `
                -Sddl $Sddl `
                -ThrottleLimit 1 `
                -Confirm:$false `
                -ErrorAction Stop
            break
        }
        'SmbShare' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw [System.ArgumentException]::new(
                    'An SMB share name is required.'
                )
            }
            Set-SmbShareSecurityDescriptor `
                -Name $Target `
                -Sddl $Sddl `
                -ThrottleLimit 1 `
                -Confirm:$false `
                -ErrorAction Stop
            break
        }
        'ADObject' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw [System.ArgumentException]::new(
                    'An Active Directory distinguished name is required.'
                )
            }
            if ([string]::IsNullOrWhiteSpace($AllowedBaseDistinguishedName)) {
                throw [System.ArgumentException]::new(
                    'AllowedBaseDistinguishedName is required for Active Directory writes.'
                )
            }
            # Pin one domain controller so the identity check and the write
            # cannot land on two controllers that disagree.
            $pinnedServer = Resolve-WindowsADServer -Server $Server
            if (-not [string]::IsNullOrWhiteSpace($ObjectGuid)) {
                $expectedObjectGuid = [guid]::Empty
                if (-not [guid]::TryParse($ObjectGuid, [ref]$expectedObjectGuid)) {
                    throw [System.ArgumentException]::new(
                        'ObjectGuid must be empty or a GUID.'
                    )
                }
                $null = Resolve-WindowsADObjectTarget `
                    -Server $pinnedServer `
                    -DistinguishedName $Target `
                    -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                    -TimeoutSeconds $TimeoutSeconds `
                    -ForWrite `
                    -ExpectedObjectGuid $expectedObjectGuid
            }
            Set-ADObjectSecurityDescriptor `
                -Server $pinnedServer `
                -DistinguishedName $Target `
                -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                -Sddl $Sddl `
                -TimeoutSeconds $TimeoutSeconds `
                -ThrottleLimit 1 `
                -Confirm:$false `
                -ErrorAction Stop
            break
        }
        'TaskFolder' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw [System.ArgumentException]::new(
                    'A Task Scheduler folder path is required.'
                )
            }
            Set-TaskFolderSecurityDescriptor `
                -Path $Target `
                -AllowedRootPath $AllowedRootPath `
                -Sddl $Sddl `
                -ThrottleLimit 1 `
                -Confirm:$false `
                -ErrorAction Stop
            break
        }
        'ScheduledTask' {
            if ([string]::IsNullOrWhiteSpace($Target) -or
                [string]::IsNullOrWhiteSpace($TaskName)) {
                throw [System.ArgumentException]::new(
                    'A Task Scheduler folder path and task name are required.'
                )
            }
            Set-ScheduledTaskSecurityDescriptor `
                -TaskPath $Target `
                -TaskName $TaskName `
                -AllowedRootPath $AllowedRootPath `
                -Sddl $Sddl `
                -ThrottleLimit 1 `
                -Confirm:$false `
                -ErrorAction Stop
            break
        }
    }
}
