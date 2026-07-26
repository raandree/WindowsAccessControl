function Get-WindowsAccessControlDscSecurityDescriptor {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('FileSystem', 'RegistryKey', 'Service', 'ServiceControlManager', 'Process')]
        [string]$ObjectFamily,

        [Parameter()]
        [string]$Target,

        [Parameter()]
        [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,

        [Parameter()]
        [uint32]$ProcessId,

        [Parameter()]
        [int64]$CreationTimeFileTime,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections
    )

    if ([int]$Sections -le 0 -or [int]$Sections -gt 15) {
        throw [System.ArgumentOutOfRangeException]::new('Sections')
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
    }
}
