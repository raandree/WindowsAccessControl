function Invoke-WindowsAccessControlBatch {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$ArgumentList = @(),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$CanonicalTargetProperty,

        [Parameter()]
        [switch]$SerializeByCanonicalTarget,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$CommandName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ObjectFamily,

        [Parameter()]
        [System.Management.Automation.PSModuleInfo]$OwningModule,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount))
    )

    if ($SerializeByCanonicalTarget -and
        -not $PSBoundParameters.ContainsKey('CanonicalTargetProperty')) {
        throw [System.ArgumentException]::new(
            'SerializeByCanonicalTarget requires CanonicalTargetProperty.'
        )
    }
    $metricParameterCount = @(
        $PSBoundParameters.ContainsKey('CommandName')
        $PSBoundParameters.ContainsKey('ObjectFamily')
    ) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
    if ($metricParameterCount -eq 1) {
        throw [System.ArgumentException]::new(
            'CommandName and ObjectFamily must be supplied together.'
        )
    }
    $metricsEnabled = $metricParameterCount -eq 2
    $inputValues = @(
        if ($PSBoundParameters.ContainsKey('CanonicalTargetProperty')) {
            $seenTargets = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
            foreach ($inputValue in $InputObject) {
                $targetProperty = $inputValue.PSObject.Properties[
                    $CanonicalTargetProperty
                ]
                if (-not $targetProperty -or
                    [string]::IsNullOrWhiteSpace([string]$targetProperty.Value)) {
                    throw [System.ArgumentException]::new(
                        "Every batch input requires a nonempty $CanonicalTargetProperty property."
                    )
                }
                if ($seenTargets.Add([string]$targetProperty.Value)) {
                    $inputValue
                }
            }
        } else {
            $InputObject
        }
    )
    $owningModule = if ($OwningModule) {
        $OwningModule
    } else {
        $MyInvocation.MyCommand.Module
    }
    if (-not $owningModule) {
        throw [System.InvalidOperationException]::new(
            'The batch dispatcher requires an owning module.'
        )
    }

    $successCount = [long]0
    $failureCount = [long]0
    $stopwatch = if ($metricsEnabled) {
        [System.Diagnostics.Stopwatch]::StartNew()
    } else {
        $null
    }
    if ($inputValues.Count -eq 0) {
        if ($metricsEnabled) {
            $stopwatch.Stop()
            $metricParameters = @{
                CommandName         = $CommandName
                ObjectFamily        = $ObjectFamily
                TargetCount         = 0
                SuccessCount        = 0
                FailureCount        = 0
                ElapsedMilliseconds = $stopwatch.Elapsed.TotalMilliseconds
            }
            & $owningModule {
                param($Parameters)
                Add-WindowsAccessControlMetric @Parameters
            } $metricParameters
        }
        return
    }
    $inlineWorker = {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [System.Management.Automation.PSModuleInfo]$Module,

            [Parameter(Mandatory)]
            [scriptblock]$Worker,

            [Parameter(Mandatory)]
            [object]$InputValue,

            [Parameter()]
            [object[]]$Arguments
        )

        & $Module $Worker $InputValue @Arguments
    }
    if ($ThrottleLimit -eq 1 -or $inputValues.Count -eq 1) {
        try {
            foreach ($inputValue in $inputValues) {
                $targetLock = if ($SerializeByCanonicalTarget) {
                    Get-WindowsAccessControlTargetLock -CanonicalTarget (
                        [string]$inputValue.PSObject.Properties[
                            $CanonicalTargetProperty
                        ].Value
                    )
                } else {
                    $null
                }
                $lockAcquired = $false
                $targetSucceeded = $true
                $targetError = $null
                # Buffer worker output so a downstream terminating error surfaces
                # outside this catch instead of being downgraded to a warning.
                $workerOutput = [System.Collections.Generic.List[object]]::new()
                try {
                    if ($targetLock) {
                        $targetLock.Semaphore.Wait()
                        $lockAcquired = $true
                    }
                    try {
                        $workerErrors = @()
                        & $inlineWorker `
                            -Module $owningModule `
                            -Worker $ScriptBlock `
                            -InputValue $inputValue `
                            -Arguments $ArgumentList `
                            -ErrorVariable +workerErrors |
                            ForEach-Object { $workerOutput.Add($_) }
                        if ($workerErrors.Count -gt 0) {
                            $targetSucceeded = $false
                            $failureCount++
                        }
                    } catch {
                        $targetSucceeded = $false
                        $failureCount++
                        $targetError = $_
                    }
                } finally {
                    if ($lockAcquired) {
                        $null = $targetLock.Semaphore.Release()
                    }
                    if ($targetLock) {
                        Unlock-WindowsAccessControlTargetLock -TargetLock $targetLock
                    }
                }
                if ($targetSucceeded) {
                    $successCount++
                }
                foreach ($outputItem in $workerOutput) {
                    $PSCmdlet.WriteObject($outputItem, $false)
                }
                if ($targetError) {
                    $PSCmdlet.WriteError($targetError)
                }
            }
        } finally {
            if ($metricsEnabled) {
                $stopwatch.Stop()
                if ($successCount + $failureCount -lt $inputValues.Count) {
                    $failureCount = $inputValues.Count - $successCount
                }
                $metricParameters = @{
                    CommandName         = $CommandName
                    ObjectFamily        = $ObjectFamily
                    TargetCount         = $inputValues.Count
                    SuccessCount        = $successCount
                    FailureCount        = $failureCount
                    ElapsedMilliseconds = $stopwatch.Elapsed.TotalMilliseconds
                }
                & $owningModule {
                    param($Parameters)
                    Add-WindowsAccessControlMetric @Parameters
                } $metricParameters
            }
        }
        return
    }

    $maximumWorkers = [Math]::Min($ThrottleLimit, $inputValues.Count)
    $moduleManifestPath = Join-Path `
        $owningModule.ModuleBase `
        "$($owningModule.Name).psd1"
    if (-not (Test-Path -LiteralPath $moduleManifestPath -PathType Leaf)) {
        $moduleManifestPath = $owningModule.Path
    }
    $initialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $initialSessionState.ImportPSModule(@($moduleManifestPath))
    $runspacePool = [runspacefactory]::CreateRunspacePool(
        1,
        $maximumWorkers,
        $initialSessionState,
        $Host
    )
    $activeWorkers = [System.Collections.Generic.List[object]]::new()
    $nextInputIndex = 0
    $workerWrapper = @'
param($ModuleName, $WorkerText, $InputValue, $Arguments, $TargetSemaphore)
if ($TargetSemaphore)
{
    $TargetSemaphore.Wait()
}
try
{
    $workerModule = Get-Module -Name $ModuleName
    $worker = [scriptblock]::Create($WorkerText)
    & $workerModule $worker $InputValue @Arguments
}
finally
{
    if ($TargetSemaphore)
    {
        $null = $TargetSemaphore.Release()
    }
}
'@
    try {
        $runspacePool.Open()
        while ($nextInputIndex -lt $inputValues.Count -or
            $activeWorkers.Count -gt 0) {
            while ($nextInputIndex -lt $inputValues.Count -and
                $activeWorkers.Count -lt $maximumWorkers) {
                $powerShell = [powershell]::Create()
                $powerShell.RunspacePool = $runspacePool
                $targetLock = $null
                try {
                    $targetLock = if ($SerializeByCanonicalTarget) {
                        Get-WindowsAccessControlTargetLock -CanonicalTarget (
                            [string]$inputValues[$nextInputIndex].PSObject.Properties[
                                $CanonicalTargetProperty
                            ].Value
                        )
                    } else {
                        $null
                    }
                    $targetSemaphore = if ($targetLock) {
                        $targetLock.Semaphore
                    } else {
                        $null
                    }
                    $null = $powerShell.AddScript($workerWrapper).
                        AddArgument($owningModule.Name).
                        AddArgument($ScriptBlock.ToString()).
                        AddArgument($inputValues[$nextInputIndex]).
                        AddArgument($ArgumentList).
                        AddArgument($targetSemaphore)
                    $asyncResult = $powerShell.BeginInvoke()
                    $activeWorkers.Add([pscustomobject]@{
                        PowerShell = $powerShell
                        AsyncResult = $asyncResult
                        TargetLock = $targetLock
                    })
                } catch {
                    $powerShell.Dispose()
                    if ($targetLock) {
                        Unlock-WindowsAccessControlTargetLock `
                            -TargetLock $targetLock
                    }
                    throw
                }
                $nextInputIndex++
            }

            $waitHandles = @(
                foreach ($activeWorker in $activeWorkers) {
                    $activeWorker.AsyncResult.AsyncWaitHandle
                }
            )
            $completedIndex = [System.Threading.WaitHandle]::WaitAny($waitHandles)
            $completedWorker = $activeWorkers[$completedIndex]
            $completionError = $null
            $workerOutput = $null
            try {
                $workerOutput = $completedWorker.PowerShell.EndInvoke(
                    $completedWorker.AsyncResult
                )
            } catch {
                $completionError = $_
            }
            if ($completionError -and
                $completedWorker.PowerShell.Streams.Error.Count -eq 0) {
                $innerException = $completionError.Exception.InnerException
                $workerError = if ($innerException -and
                    $innerException.PSObject.Properties['ErrorRecord'] -and
                    $innerException.ErrorRecord) {
                    $innerException.ErrorRecord
                } else {
                    $completionError
                }
                $workerErrors = @($workerError)
            } else {
                $workerErrors = @(
                    $completedWorker.PowerShell.Streams.Error
                )
            }
            if ($workerErrors.Count -gt 0) {
                $failureCount++
            } else {
                $successCount++
            }
            $completedWorker.PowerShell.Dispose()
            if ($completedWorker.TargetLock) {
                Unlock-WindowsAccessControlTargetLock `
                    -TargetLock $completedWorker.TargetLock
            }
            $activeWorkers.RemoveAt($completedIndex)
            foreach ($outputItem in $workerOutput) {
                $PSCmdlet.WriteObject($outputItem, $false)
            }
            foreach ($workerError in $workerErrors) {
                $PSCmdlet.WriteError($workerError)
            }
        }
    } finally {
        foreach ($activeWorker in $activeWorkers) {
            try {
                $activeWorker.PowerShell.Stop()
            } finally {
                $activeWorker.PowerShell.Dispose()
                if ($activeWorker.TargetLock) {
                    Unlock-WindowsAccessControlTargetLock `
                        -TargetLock $activeWorker.TargetLock
                }
            }
        }
        $runspacePool.Close()
        $runspacePool.Dispose()
        if ($metricsEnabled) {
            $stopwatch.Stop()
            if ($successCount + $failureCount -lt $inputValues.Count) {
                $failureCount = $inputValues.Count - $successCount
            }
            $metricParameters = @{
                CommandName         = $CommandName
                ObjectFamily        = $ObjectFamily
                TargetCount         = $inputValues.Count
                SuccessCount        = $successCount
                FailureCount        = $failureCount
                ElapsedMilliseconds = $stopwatch.Elapsed.TotalMilliseconds
            }
            & $owningModule {
                param($Parameters)
                Add-WindowsAccessControlMetric @Parameters
            } $metricParameters
        }
    }
}
