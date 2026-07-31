function Get-WindowsAccessControlDscSecurityDescriptor {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
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
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections
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

    switch ($ObjectFamily) {
        'FileSystem' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw [System.ArgumentException]::new(
                    'A filesystem target path is required.'
                )
            }
            $managedSections = ConvertTo-WindowsAccessControlSection `
                -Sections $Sections
            Get-NTFSItemSecurityDescriptor `
                -LiteralPath $Target `
                -Sections $managedSections `
                -ThrottleLimit 1 `
                -ErrorAction Stop
            break
        }
        'RegistryKey' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw [System.ArgumentException]::new(
                    'A registry key target path is required.'
                )
            }
            Get-RegistryKeySecurityDescriptor `
                -Path $Target `
                -RegistryView $RegistryView `
                -Sections $Sections `
                -ThrottleLimit 1 `
                -ErrorAction Stop
            break
        }
        'Service' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw [System.ArgumentException]::new(
                    'A service name is required.'
                )
            }
            Get-ServiceSecurityDescriptor `
                -Name $Target `
                -Sections $Sections `
                -ThrottleLimit 1 `
                -ErrorAction Stop
            break
        }
        'ServiceControlManager' {
            Get-ServiceSecurityDescriptor `
                -ServiceControlManager `
                -Sections $Sections `
                -ThrottleLimit 1 `
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
            Get-ProcessSecurityDescriptor `
                -InputObject $processIdentity `
                -Sections $Sections `
                -ThrottleLimit 1 `
                -ErrorAction Stop
            break
        }
        'SmbShare' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw [System.ArgumentException]::new(
                    'An SMB share name is required.'
                )
            }
            Get-SmbShareSecurityDescriptor `
                -Name $Target `
                -ThrottleLimit 1 `
                -ErrorAction Stop
            break
        }
        'ADObject' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw [System.ArgumentException]::new(
                    'An Active Directory distinguished name is required.'
                )
            }
            Get-ADObjectSecurityDescriptor `
                -Server (Resolve-WindowsADServer -Server $Server) `
                -DistinguishedName $Target `
                -TimeoutSeconds $TimeoutSeconds `
                -ThrottleLimit 1 `
                -ErrorAction Stop
            break
        }
        'TaskFolder' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw [System.ArgumentException]::new(
                    'A Task Scheduler folder path is required.'
                )
            }
            Get-TaskFolderSecurityDescriptor `
                -Path $Target `
                -ThrottleLimit 1 `
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
            Get-ScheduledTaskSecurityDescriptor `
                -TaskPath $Target `
                -TaskName $TaskName `
                -ThrottleLimit 1 `
                -ErrorAction Stop
            break
        }
    }
}
