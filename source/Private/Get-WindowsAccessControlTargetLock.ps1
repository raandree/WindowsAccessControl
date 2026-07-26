function Get-WindowsAccessControlTargetLock {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CanonicalTarget
    )

    [System.Threading.Monitor]::Enter(
        $script:WindowsAccessControlTargetLockSyncRoot
    )
    try {
        if (-not $script:WindowsAccessControlTargetLocks.ContainsKey(
            $CanonicalTarget
        )) {
            $script:WindowsAccessControlTargetLocks[$CanonicalTarget] =
                [pscustomobject]@{
                    CanonicalTarget = $CanonicalTarget
                    Semaphore       = [System.Threading.SemaphoreSlim]::new(1, 1)
                    ReferenceCount  = 0
                }
        }
        $targetLock = $script:WindowsAccessControlTargetLocks[$CanonicalTarget]
        $targetLock.ReferenceCount++
        $targetLock
    } finally {
        [System.Threading.Monitor]::Exit(
            $script:WindowsAccessControlTargetLockSyncRoot
        )
    }
}
