function Set-WindowsAccessControlDscAccessRule {
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
        [Parameter()] [string]$Target,
        [Parameter()] [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,
        [Parameter()] [uint32]$ProcessId,
        [Parameter()] [int64]$CreationTimeFileTime,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$Account,
        [Parameter(Mandatory)] [ValidateRange(0, [uint32]::MaxValue)] [uint64]$AccessMask,
        [Parameter(Mandatory)]
        [System.Security.AccessControl.AccessControlType]$AccessControlType,
        [Parameter()] [string]$AppliesTo,
        [Parameter(Mandatory)] [WindowsAccessControlDscEnsure]$Ensure
    )

    $findParameters = @{} + $PSBoundParameters
    $null = $findParameters.Remove('Ensure')
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
        }
    }
}
