function Set-WindowsAccessControlDscAccessRule {
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
        [Parameter()] [string]$Target,
        [Parameter()] [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,
        [Parameter()] [uint32]$ProcessId,
        [Parameter()] [int64]$CreationTimeFileTime,
        [Parameter()] [string]$Server,
        [Parameter()] [string]$TaskName,
        [Parameter()] [string]$AllowedRootPath,
        [Parameter()] [string]$AllowedBaseDistinguishedName,
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
        [Parameter()] [guid]$InheritedObjectTypeGuid = [guid]::Empty,
        [Parameter(Mandatory)] [WindowsAccessControlDscEnsure]$Ensure
    )

    if ($ObjectFamily -eq 'ADObject' -and
        [string]::IsNullOrWhiteSpace($AllowedBaseDistinguishedName)) {
        throw 'AllowedBaseDistinguishedName is required for Active Directory writes.'
    }
    if ($ObjectFamily -in @('TaskFolder', 'ScheduledTask') -and
        [string]::IsNullOrWhiteSpace($AllowedRootPath)) {
        throw 'AllowedRootPath is required for Task Scheduler writes.'
    }
    if ($ObjectFamily -eq 'ADObject') {
        # Pin one domain controller so the compliance read and the write cannot
        # land on two controllers that disagree.
        $Server = Resolve-WindowsADServer -Server $Server
    }
    $findParameters = @{} + $PSBoundParameters
    $null = $findParameters.Remove('Ensure')
    $null = $findParameters.Remove('AllowedBaseDistinguishedName')
    $null = $findParameters.Remove('AllowedRootPath')
    if ($ObjectFamily -eq 'ADObject') {
        $findParameters.Server = $Server
    }
    $matchingRules = @(Find-WindowsAccessControlDscAccessRule @findParameters)
    if ($Ensure -eq [WindowsAccessControlDscEnsure]::Present) {
        if ($matchingRules.Count -gt 0) {
            return
        }
        $signedMask = [System.BitConverter]::ToInt32(
            [System.BitConverter]::GetBytes([uint32]$AccessMask),
            0
        )
        switch ($ObjectFamily) {
            'FileSystem' {
                Add-NTFSAccessRule `
                    -LiteralPath $Target `
                    -Account $Account `
                    -AccessRights ([System.Enum]::ToObject(
                        [System.Security.AccessControl.FileSystemRights],
                        $signedMask
                    )) `
                    -AccessControlType $AccessControlType `
                    -AppliesTo $AppliesTo `
                    -ThrottleLimit 1 `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            'RegistryKey' {
                Add-RegistryKeyAccessRule `
                    -Path $Target `
                    -RegistryView $RegistryView `
                    -Account $Account `
                    -AccessRights ([System.Enum]::ToObject(
                        [System.Security.AccessControl.RegistryRights],
                        $signedMask
                    )) `
                    -AccessControlType $AccessControlType `
                    -AppliesTo $AppliesTo `
                    -ThrottleLimit 1 `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            'Service' {
                Add-ServiceAccessRule `
                    -Name $Target `
                    -Account $Account `
                    -ServiceRights ([System.Enum]::ToObject(
                        [WindowsServiceRights],
                        $signedMask
                    )) `
                    -AccessControlType $AccessControlType `
                    -ThrottleLimit 1 `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            'ServiceControlManager' {
                Add-ServiceAccessRule `
                    -ServiceControlManager `
                    -Account $Account `
                    -ControlManagerRights ([System.Enum]::ToObject(
                        [WindowsServiceControlManagerRights],
                        $signedMask
                    )) `
                    -AccessControlType $AccessControlType `
                    -ThrottleLimit 1 `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            'Process' {
                $processIdentity = [pscustomobject]@{
                    ObjectType           = 'Process'
                    ProcessId            = [int]$ProcessId
                    ProcessName          = $null
                    CreationTime         = $null
                    CreationTimeFileTime = $CreationTimeFileTime
                }
                Add-ProcessAccessRule `
                    -InputObject $processIdentity `
                    -Account $Account `
                    -ProcessRights ([System.Enum]::ToObject(
                        [WindowsProcessRights],
                        $signedMask
                    )) `
                    -AccessControlType $AccessControlType `
                    -ThrottleLimit 1 `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            'SmbShare' {
                Add-SmbShareAccessRule `
                    -Name $Target `
                    -Account $Account `
                    -AccessRights ([System.Enum]::ToObject(
                        [WindowsSmbShareRights],
                        $signedMask
                    )) `
                    -AccessControlType $AccessControlType `
                    -ThrottleLimit 1 `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            'ADObject' {
                Add-ADObjectAccessRule `
                    -Server $Server `
                    -DistinguishedName $Target `
                    -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                    -Account $Account `
                    -AccessRights ([System.Enum]::ToObject(
                        [WindowsActiveDirectoryRights],
                        $signedMask
                    )) `
                    -AccessControlType $AccessControlType `
                    -InheritanceType $InheritanceType `
                    -ObjectType $ObjectTypeGuid `
                    -InheritedObjectType $InheritedObjectTypeGuid `
                    -TimeoutSeconds $TimeoutSeconds `
                    -ThrottleLimit 1 `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            'TaskFolder' {
                Add-TaskFolderAccessRule `
                    -Path $Target `
                    -AllowedRootPath $AllowedRootPath `
                    -Account $Account `
                    -AccessRights ([System.Enum]::ToObject(
                        [WindowsTaskFolderRights],
                        $signedMask
                    )) `
                    -AccessControlType $AccessControlType `
                    -AppliesTo $AppliesTo `
                    -ThrottleLimit 1 `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            'ScheduledTask' {
                Add-ScheduledTaskAccessRule `
                    -TaskPath $Target `
                    -TaskName $TaskName `
                    -AllowedRootPath $AllowedRootPath `
                    -Account $Account `
                    -AccessRights ([System.Enum]::ToObject(
                        [WindowsScheduledTaskRights],
                        $signedMask
                    )) `
                    -AccessControlType $AccessControlType `
                    -ThrottleLimit 1 `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
        }
        return
    }

    foreach ($matchingRule in $matchingRules) {
        switch ($ObjectFamily) {
            'FileSystem' {
                Remove-NTFSAccessRule `
                    -InputObject $matchingRule `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            'RegistryKey' {
                Remove-RegistryKeyAccessRule `
                    -InputObject $matchingRule `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            { $_ -in @('Service', 'ServiceControlManager') } {
                Remove-ServiceAccessRule `
                    -InputObject $matchingRule `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            'Process' {
                Remove-ProcessAccessRule `
                    -InputObject $matchingRule `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            'SmbShare' {
                Remove-SmbShareAccessRule `
                    -InputObject $matchingRule `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            'ADObject' {
                Remove-ADObjectAccessRule `
                    -InputObject $matchingRule `
                    -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                    -TimeoutSeconds $TimeoutSeconds `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            'TaskFolder' {
                Remove-TaskFolderAccessRule `
                    -InputObject $matchingRule `
                    -AllowedRootPath $AllowedRootPath `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
            'ScheduledTask' {
                Remove-ScheduledTaskAccessRule `
                    -InputObject $matchingRule `
                    -AllowedRootPath $AllowedRootPath `
                    -Confirm:$false `
                    -ErrorAction Stop
                break
            }
        }
    }
}
