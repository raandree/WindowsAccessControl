function Set-WindowsAccessControlDscSecurityDescriptor {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'The DSC engine invokes this private adapter only from resource Set().'
    )]
    [CmdletBinding()]
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
        [WindowsSecurityDescriptorSection]$Sections,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Sddl
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
    }
}
