function Find-WindowsAccessControlDscAccessRule {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('FileSystem', 'RegistryKey', 'Service', 'ServiceControlManager', 'Process', 'SmbShare', 'ADObject', 'TaskFolder', 'ScheduledTask', 'CertificatePrivateKey')]
        [string]$ObjectFamily,
        [Parameter()] [string]$Target,
        [Parameter()] [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,
        [Parameter()] [uint32]$ProcessId,
        [Parameter()] [int64]$CreationTimeFileTime,
        [Parameter()] [string]$Server,
        [Parameter()] [string]$TaskName,
        [Parameter()] [string]$ProviderName,
        [Parameter()] [string]$KeyScope,
        [Parameter()] [ValidateRange(1, 300)] [int]$TimeoutSeconds = 10,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$Account,
        [Parameter(Mandatory)] [ValidateRange(0, [uint32]::MaxValue)] [uint64]$AccessMask,
        [Parameter(Mandatory)]
        [System.Security.AccessControl.AccessControlType]$AccessControlType,
        [Parameter()] [string]$AppliesTo,
        [Parameter()]
        [WindowsActiveDirectoryInheritance]$InheritanceType =
            [WindowsActiveDirectoryInheritance]::None,
        [Parameter()] [guid]$ObjectTypeGuid = [guid]::Empty,
        [Parameter()] [guid]$InheritedObjectTypeGuid = [guid]::Empty
    )

    $securityIdentifier = Resolve-WindowsIdentityReference -Identity $Account
    if ($ObjectFamily -eq 'FileSystem') {
        if ([string]::IsNullOrWhiteSpace($AppliesTo)) {
            throw 'An AppliesTo value is required for a filesystem rule.'
        }
        $signedMask = [System.BitConverter]::ToInt32(
            [System.BitConverter]::GetBytes([uint32]$AccessMask),
            0
        )
        $scope = ConvertFrom-NTFSAppliesTo -AppliesTo $AppliesTo
        $normalizedRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $securityIdentifier,
            [System.Enum]::ToObject(
                [System.Security.AccessControl.FileSystemRights],
                $signedMask
            ),
            $scope.InheritanceFlags,
            $scope.PropagationFlags,
            $AccessControlType
        )
        $AccessMask = [uint64](
            [int64][int]$normalizedRule.FileSystemRights -band 0xFFFFFFFFL
        )
    }
    if ($ObjectFamily -eq 'CertificatePrivateKey') {
        # The key storage provider expands and discards generic bits, so a
        # requested GenericRead can never equal the effective mask of the ACE it
        # created. Normalizing the request is what keeps a removal from matching
        # nothing and reporting the grant already absent.
        $AccessMask = [uint64](
            ConvertTo-WindowsCryptoKeyEffectiveMask -AccessMask ([long]$AccessMask)
        )
    }
    $rules = switch ($ObjectFamily) {
        'FileSystem' {
            if ([string]::IsNullOrWhiteSpace($Target) -or
                [string]::IsNullOrWhiteSpace($AppliesTo)) {
                throw 'A filesystem path and AppliesTo value are required.'
            }
            @(Get-NTFSAccessRule `
                -LiteralPath $Target `
                -Account $securityIdentifier.Value `
                -ExcludeInherited `
                -ThrottleLimit 1 `
                -ErrorAction Stop)
            break
        }
        'RegistryKey' {
            if ([string]::IsNullOrWhiteSpace($Target) -or
                [string]::IsNullOrWhiteSpace($AppliesTo)) {
                throw 'A registry key path and AppliesTo value are required.'
            }
            @(Get-RegistryKeyAccessRule `
                -Path $Target `
                -RegistryView $RegistryView `
                -Account $securityIdentifier.Value `
                -ExcludeInherited `
                -ThrottleLimit 1 `
                -ErrorAction Stop)
            break
        }
        'Service' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw 'A service name is required.'
            }
            @(Get-ServiceAccessRule `
                -Name $Target `
                -Account $securityIdentifier.Value `
                -ExcludeInherited `
                -ThrottleLimit 1 `
                -ErrorAction Stop)
            break
        }
        'ServiceControlManager' {
            @(Get-ServiceAccessRule `
                -ServiceControlManager `
                -Account $securityIdentifier.Value `
                -ExcludeInherited `
                -ThrottleLimit 1 `
                -ErrorAction Stop)
            break
        }
        'Process' {
            if ($ProcessId -eq 0 -or $CreationTimeFileTime -le 0) {
                throw 'A positive process ID and creation FILETIME are required.'
            }
            $processIdentity = [pscustomobject]@{
                ObjectType           = 'Process'
                ProcessId            = [int]$ProcessId
                ProcessName          = $null
                CreationTime         = $null
                CreationTimeFileTime = $CreationTimeFileTime
            }
            @(Get-ProcessAccessRule `
                -InputObject $processIdentity `
                -Account $securityIdentifier.Value `
                -ExcludeInherited `
                -ThrottleLimit 1 `
                -ErrorAction Stop)
            break
        }
        'SmbShare' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw 'An SMB share name is required.'
            }
            @(Get-SmbShareAccessRule `
                -Name $Target `
                -Account $securityIdentifier.Value `
                -ExcludeInherited `
                -ThrottleLimit 1 `
                -ErrorAction Stop)
            break
        }
        'ADObject' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                throw 'An Active Directory distinguished name is required.'
            }
            @(Get-ADObjectAccessRule `
                -Server (Resolve-WindowsADServer -Server $Server) `
                -DistinguishedName $Target `
                -Account $securityIdentifier.Value `
                -ExcludeInherited `
                -TimeoutSeconds $TimeoutSeconds `
                -ThrottleLimit 1 `
                -ErrorAction Stop)
            break
        }
        'TaskFolder' {
            if ([string]::IsNullOrWhiteSpace($Target) -or
                [string]::IsNullOrWhiteSpace($AppliesTo)) {
                throw 'A Task Scheduler folder path and AppliesTo value are required.'
            }
            @(Get-TaskFolderAccessRule `
                -Path $Target `
                -Account $securityIdentifier.Value `
                -ExcludeInherited `
                -ThrottleLimit 1 `
                -ErrorAction Stop)
            break
        }
        'ScheduledTask' {
            if ([string]::IsNullOrWhiteSpace($Target) -or
                [string]::IsNullOrWhiteSpace($TaskName)) {
                throw 'A Task Scheduler folder path and task name are required.'
            }
            @(Get-ScheduledTaskAccessRule `
                -TaskPath $Target `
                -TaskName $TaskName `
                -Account $securityIdentifier.Value `
                -ExcludeInherited `
                -ThrottleLimit 1 `
                -ErrorAction Stop)
            break
        }
        'CertificatePrivateKey' {
            if ([string]::IsNullOrWhiteSpace($Target) -or
                [string]::IsNullOrWhiteSpace($ProviderName) -or
                $KeyScope -notin @('Machine', 'User')) {
                throw 'A CNG provider, persisted key name, and key scope are required.'
            }
            @(Get-CertificatePrivateKeyAccessRule `
                -ProviderName $ProviderName `
                -KeyName $Target `
                -KeyScope $KeyScope `
                -Account $securityIdentifier.Value `
                -ErrorAction Stop |
                Where-Object { -not $_.IsInherited })
            break
        }
    }

    foreach ($rule in @($rules)) {
        $ruleMask = if ($ObjectFamily -eq 'FileSystem') {
            [uint64]([int64][int]$rule.AccessRights -band 0xFFFFFFFFL)
        } elseif ($ObjectFamily -eq 'CertificatePrivateKey') {
            # The provider stores a candidate ACE with the matching generic bit
            # added, so the raw stored mask never equals the requested mask.
            [uint64]$rule.EffectiveAccessMask
        } elseif ($rule.PSObject.Properties['AccessMask']) {
            [uint64]$rule.AccessMask
        } else {
            [uint64]([int64][int]$rule.AccessRights -band 0xFFFFFFFFL)
        }
        if ([string]$rule.SID -ne $securityIdentifier.Value -or
            [bool]$rule.IsInherited -or
            $ruleMask -ne $AccessMask -or
            [System.Security.AccessControl.AccessControlType]$rule.AccessControlType -ne
                $AccessControlType) {
            continue
        }
        if ($ObjectFamily -in @('FileSystem', 'RegistryKey', 'TaskFolder') -and
            [string]$rule.AppliesTo -ne $AppliesTo) {
            continue
        }
        # ACE type rather than ACE qualifier decides whether an ACE grants
        # unconditionally, so a conditional allow ACE must not report a grant as
        # present. This mirrors the private-key write boundary.
        if ($ObjectFamily -eq 'CertificatePrivateKey' -and
            $rule.NativeAce.AceType -notin @(
                [System.Security.AccessControl.AceType]::AccessAllowed
                [System.Security.AccessControl.AceType]::AccessDenied
            )) {
            continue
        }
        if ($ObjectFamily -eq 'ADObject' -and (
            [WindowsActiveDirectoryInheritance]$rule.InheritanceType -ne $InheritanceType -or
            [guid]$rule.ObjectTypeGuid -ne $ObjectTypeGuid -or
            [guid]$rule.InheritedObjectTypeGuid -ne $InheritedObjectTypeGuid)) {
            continue
        }
        $rule
    }
}
