function Unlock-WindowsAccessControlTargetLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$TargetLock
    )

    $semaphoreToDispose = $null
    [System.Threading.Monitor]::Enter(
        $script:WindowsAccessControlTargetLockSyncRoot
    )
    try {
        $TargetLock.ReferenceCount--
        if ($TargetLock.ReferenceCount -lt 0) {
            throw [System.InvalidOperationException]::new(
                "Target lock '$($TargetLock.CanonicalTarget)' has an invalid reference count."
            )
        }
        if ($TargetLock.ReferenceCount -eq 0) {
            $null = $script:WindowsAccessControlTargetLocks.Remove(
                $TargetLock.CanonicalTarget
            )
            $semaphoreToDispose = $TargetLock.Semaphore
        }
    } finally {
        [System.Threading.Monitor]::Exit(
            $script:WindowsAccessControlTargetLockSyncRoot
        )
    }
    if ($semaphoreToDispose) {
        $semaphoreToDispose.Dispose()
    }
}
