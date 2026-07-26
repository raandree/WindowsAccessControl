function Get-WindowsAccessControlDscAccessRule {
    [CmdletBinding()]
    [OutputType([bool])]
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

    $parameters = @{} + $PSBoundParameters
    @(Find-WindowsAccessControlDscAccessRule @parameters).Count -gt 0
}
