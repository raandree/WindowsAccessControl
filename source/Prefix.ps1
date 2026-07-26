if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw [System.PlatformNotSupportedException]::new(
        'WindowsAccessControl manages Windows NTFS security descriptors and is supported only on Windows.'
    )
}

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
$script:WindowsAccessControlBatchWorker =
    [System.Threading.ThreadLocal[bool]]::new()
