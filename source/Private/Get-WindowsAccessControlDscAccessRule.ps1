function Get-WindowsAccessControlDscAccessRule {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('FileSystem', 'RegistryKey', 'Service', 'ServiceControlManager', 'Process', 'SmbShare', 'ADObject')]
        [string]$ObjectFamily,
        [Parameter()] [string]$Target,
        [Parameter()] [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,
        [Parameter()] [uint32]$ProcessId,
        [Parameter()] [int64]$CreationTimeFileTime,
        [Parameter()] [string]$Server,
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

    $parameters = @{} + $PSBoundParameters
    @(Find-WindowsAccessControlDscAccessRule @parameters).Count -gt 0
}
