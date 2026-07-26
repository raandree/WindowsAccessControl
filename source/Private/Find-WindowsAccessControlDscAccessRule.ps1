function Find-WindowsAccessControlDscAccessRule {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('FileSystem', 'RegistryKey', 'Service', 'ServiceControlManager', 'Process')]
        [string]$ObjectFamily,
        [Parameter()] [string]$Target,
        [Parameter()] [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,
        [Parameter()] [uint32]$ProcessId,
        [Parameter()] [int64]$CreationTimeFileTime,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$Account,
        [Parameter(Mandatory)] [ValidateRange(0, [uint32]::MaxValue)] [uint64]$AccessMask,
        [Parameter(Mandatory)]
        [System.Security.AccessControl.AccessControlType]$AccessControlType,
        [Parameter()] [string]$AppliesTo
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
    }

    foreach ($rule in @($rules)) {
        $ruleMask = if ($ObjectFamily -eq 'FileSystem') {
            [uint64]([int64][int]$rule.AccessRights -band 0xFFFFFFFFL)
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
        if ($ObjectFamily -in @('FileSystem', 'RegistryKey') -and
            [string]$rule.AppliesTo -ne $AppliesTo) {
            continue
        }
        $rule
    }
}
