if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw [System.PlatformNotSupportedException]::new(
        'WindowsAccessControl manages Windows NTFS security descriptors and is supported only on Windows.'
    )
}

# Windows PowerShell resolves parameter type attributes before a function body
# runs, so the directory assembly must be present before the first call.
Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop

$targetLockStateName = 'WindowsAccessControl.TargetLockState'
$currentAppDomain = [System.AppDomain]::CurrentDomain
[System.Threading.Monitor]::Enter($currentAppDomain)
try {
    $targetLockState = $currentAppDomain.GetData($targetLockStateName)
    if (-not $targetLockState) {
        $targetLockState = @{
            SyncRoot = [object]::new()
            Locks    = @{}
        }
        $currentAppDomain.SetData($targetLockStateName, $targetLockState)
    }
} finally {
    [System.Threading.Monitor]::Exit($currentAppDomain)
}
$script:WindowsAccessControlTargetLockSyncRoot = $targetLockState.SyncRoot
$script:WindowsAccessControlTargetLocks = $targetLockState.Locks
$script:WindowsAccessControlMetricSyncRoot = [object]::new()
$script:WindowsAccessControlMetrics = @{}
$script:WindowsADSchemaGuidNames = @{}
$script:WindowsAccessControlBatchWorker =
    [System.Threading.ThreadLocal[bool]]::new()
