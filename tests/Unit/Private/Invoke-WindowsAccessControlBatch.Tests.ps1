BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module -Name 'WindowsAccessControl'
    Add-Type -TypeDefinition @'
using System.Threading;

public sealed class WindowsAccessControlBatchTestCounter
{
    private int current;
    private int maximum;

    public ManualResetEventSlim Gate { get; private set; }
    public ManualResetEventSlim FirstEntered { get; private set; }
    public ManualResetEventSlim ReleaseWorkers { get; private set; }
    public CountdownEvent InvocationReady { get; private set; }
    public ManualResetEventSlim StartInvocations { get; private set; }
    public int Current { get { return current; } }
    public int Maximum { get { return maximum; } }

    public WindowsAccessControlBatchTestCounter()
    {
        Gate = new ManualResetEventSlim(false);
        FirstEntered = new ManualResetEventSlim(false);
        ReleaseWorkers = new ManualResetEventSlim(false);
        InvocationReady = new CountdownEvent(2);
        StartInvocations = new ManualResetEventSlim(false);
    }

    public int Enter()
    {
        int value = Interlocked.Increment(ref current);
        FirstEntered.Set();
        int observed;
        do
        {
            observed = maximum;
            if (value <= observed)
            {
                break;
            }
        }
        while (Interlocked.CompareExchange(ref maximum, value, observed) != observed);

        if (value >= 2)
        {
            Gate.Set();
        }
        return value;
    }

    public void Exit()
    {
        Interlocked.Decrement(ref current);
    }
}
'@
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-WindowsAccessControlBatch' -Tag 'Unit', 'WindowsOnly' {
    It 'Should overlap work without exceeding ThrottleLimit' {
        $counter = [WindowsAccessControlBatchTestCounter]::new()
        $worker = & $script:module {
            {
                param($InputValue, $Counter)

                $null = $Counter.Enter()
                try {
                    if (-not $Counter.Gate.Wait(2000)) {
                        throw 'Parallel workers did not overlap.'
                    }
                    $InputValue
                } finally {
                    $Counter.Exit()
                }
            }
        }

        try {
            $result = & $script:module {
                param($InputValues, $Worker, $Counter)
                Invoke-WindowsAccessControlBatch `
                    -InputObject $InputValues `
                    -ScriptBlock $Worker `
                    -ArgumentList $Counter `
                    -ThrottleLimit 2
            } @(1, 2, 3, 4) $worker $counter
        } finally {
            $counter.Gate.Dispose()
        }

        $result | Sort-Object | Should -Be @(1, 2, 3, 4)
        $counter.Maximum | Should -Be 2
        $counter.Current | Should -Be 0
    }

    It 'Should preserve input order when ThrottleLimit is one' {
        $worker = & $script:module {
            { param($InputValue) $InputValue }
        }

        $result = & $script:module {
            param($InputValues, $Worker)
            Invoke-WindowsAccessControlBatch `
                -InputObject $InputValues `
                -ScriptBlock $Worker `
                -ThrottleLimit 1
        } @('third', 'first', 'second') $worker

        $result | Should -Be @('third', 'first', 'second')
    }

    It 'Should propagate a downstream terminating error from sequential dispatch' {
        $worker = & $script:module {
            { param($InputValue) $InputValue }
        }

        {
            & $script:module {
                param($InputValues, $Worker)
                Invoke-WindowsAccessControlBatch `
                    -InputObject $InputValues `
                    -ScriptBlock $Worker `
                    -ThrottleLimit 1 |
                    ForEach-Object {
                        throw [InvalidOperationException]::new(
                            'Expected downstream rejection.'
                        )
                    }
            } @(1, 2) $worker
        } | Should -Throw -ExpectedMessage '*Expected downstream rejection*'
    }

    It 'Should propagate a downstream terminating error from parallel dispatch' {
        $worker = & $script:module {
            { param($InputValue) $InputValue }
        }

        {
            & $script:module {
                param($InputValues, $Worker)
                Invoke-WindowsAccessControlBatch `
                    -InputObject $InputValues `
                    -ScriptBlock $Worker `
                    -ThrottleLimit 2 |
                    ForEach-Object {
                        throw [InvalidOperationException]::new(
                            'Expected downstream rejection.'
                        )
                    }
            } @(1, 2, 3, 4) $worker
        } | Should -Throw -ExpectedMessage '*Expected downstream rejection*'
    }

    It 'Should emit a failing target''s partial output before its error' {
        $worker = & $script:module {
            {
                param($InputValue)
                "$InputValue-partial"
                throw 'Expected target failure.'
            }
        }

        $merged = @(& $script:module {
            param($Worker)
            Invoke-WindowsAccessControlBatch `
                -InputObject @(1) `
                -ScriptBlock $Worker `
                -ThrottleLimit 1 `
                -ErrorAction Continue
        } $worker 2>&1)

        $merged | Should -HaveCount 2
        $merged[0] | Should -BeExactly '1-partial'
        $merged[1] | Should -BeOfType ([System.Management.Automation.ErrorRecord])
    }

    It 'Should clear the batch-worker flag before a downstream command runs' {
        $worker = & $script:module {
            { param($InputValue) $InputValue }
        }

        $observed = & $script:module {
            param($Worker)
            Invoke-WindowsAccessControlBatch `
                -InputObject @(1) `
                -ScriptBlock $Worker `
                -ThrottleLimit 1 |
                ForEach-Object { $script:WindowsAccessControlBatchWorker.Value }
        } $worker

        $observed | Should -BeFalse -Because 'a downstream command must dispatch its own batch and take the target lock'
    }

    It 'Should continue independent targets after one worker fails' {
        $worker = & $script:module {
            {
                param($InputValue)
                if ($InputValue -eq 2) {
                    throw 'Expected target failure.'
                }
                $InputValue
            }
        }

        $merged = @(& $script:module {
            param($InputValues, $Worker)
            Invoke-WindowsAccessControlBatch `
                -InputObject $InputValues `
                -ScriptBlock $Worker `
                -ThrottleLimit 1 `
                -ErrorAction Continue
        } @(1, 2, 3) $worker 2>&1)
        $output = @($merged | Where-Object {
            $_ -isnot [System.Management.Automation.ErrorRecord]
        })
        $targetErrors = @($merged | Where-Object {
            $_ -is [System.Management.Automation.ErrorRecord]
        })

        $output | Should -Be @(1, 3)
        $targetErrors | Should -HaveCount 1
        $targetErrors[0].Exception.Message | Should -Be 'Expected target failure.'
    }

    It 'Should classify a nonterminating inline target error as a failure' {
        $worker = & $script:module {
            {
                param($InputValue)
                Write-Error 'Expected nonterminating target error.'
                $InputValue
            }
        }

        $merged = @(& $script:module {
            param($Worker)
            Invoke-WindowsAccessControlBatch `
                -InputObject @(1) `
                -ScriptBlock $Worker `
                -ThrottleLimit 1 `
                -CommandName 'Test-InlineNonterminatingError' `
                -ObjectFamily 'FileSystem' `
                -ErrorAction Continue
        } $worker 2>&1)
        $metric = Get-WindowsAccessControlMetric `
            -CommandName 'Test-InlineNonterminatingError' `
            -ObjectFamily 'FileSystem'

        @($merged | Where-Object {
            $_ -is [System.Management.Automation.ErrorRecord]
        }) | Should -HaveCount 1
        $metric.SuccessCount | Should -Be 0
        $metric.FailureCount | Should -Be 1
    }

    It 'Should classify parallel worker errors without stopping independent targets' {
        $worker = & $script:module {
            {
                param($InputValue)
                if ($InputValue -eq 2) {
                    throw 'Expected terminating parallel error.'
                }
                if ($InputValue -eq 3) {
                    Write-Error 'Expected nonterminating parallel error.'
                }
                $InputValue
            }
        }

        $merged = @(& $script:module {
            param($Worker)
            Invoke-WindowsAccessControlBatch `
                -InputObject @(1, 2, 3, 4) `
                -ScriptBlock $Worker `
                -ThrottleLimit 2 `
                -CommandName 'Test-ParallelWorkerErrors' `
                -ObjectFamily 'FileSystem' `
                -ErrorAction Continue
        } $worker 2>&1)
        $output = @($merged | Where-Object {
            $_ -isnot [System.Management.Automation.ErrorRecord]
        })
        $targetErrors = @($merged | Where-Object {
            $_ -is [System.Management.Automation.ErrorRecord]
        })
        $metric = Get-WindowsAccessControlMetric `
            -CommandName 'Test-ParallelWorkerErrors' `
            -ObjectFamily 'FileSystem'

        $output | Sort-Object | Should -Be @(1, 3, 4)
        $targetErrors | Should -HaveCount 2
        $targetErrors.Exception.Message | Should -Contain 'Expected terminating parallel error.'
        $targetErrors.Exception.Message | Should -Contain 'Expected nonterminating parallel error.'
        $metric.TargetCount | Should -Be 4
        $metric.SuccessCount | Should -Be 2
        $metric.FailureCount | Should -Be 2
    }

    It 'Should dispatch one worker per canonical target' {
        $worker = & $script:module {
            { param($InputValue) $InputValue.Value }
        }
        $targets = @(
            [pscustomobject]@{ CanonicalTarget = 'Registry:One'; Value = 1 }
            [pscustomobject]@{ CanonicalTarget = 'registry:one'; Value = 2 }
            [pscustomobject]@{ CanonicalTarget = 'Registry:Two'; Value = 3 }
        )

        $result = & $script:module {
            param($InputValues, $Worker)
            Invoke-WindowsAccessControlBatch `
                -InputObject $InputValues `
                -ScriptBlock $Worker `
                -CanonicalTargetProperty CanonicalTarget `
                -ThrottleLimit 2
        } $targets $worker

        $result | Sort-Object | Should -Be @(1, 3)
    }

    It 'Should process one canonical target with a parallel throttle' {
        $worker = & $script:module {
            { param($InputValue) $InputValue.Value }
        }
        $target = [pscustomobject]@{
            CanonicalTarget = 'FileSystem:One'
            Value           = 1
        }

        $result = & $script:module {
            param($InputValue, $Worker)
            Invoke-WindowsAccessControlBatch `
                -InputObject @($InputValue) `
                -ScriptBlock $Worker `
                -CanonicalTargetProperty CanonicalTarget `
                -ThrottleLimit 8
        } $target $worker

        $result | Should -Be 1
    }

    It 'Should serialize the same canonical target across invocations' {
        $counter = [WindowsAccessControlBatchTestCounter]::new()
        $invocationScript = @'
param($InputValue, $Counter)
$null = $Counter.InvocationReady.Signal()
if (-not $Counter.StartInvocations.Wait(3000)) {
    throw 'Concurrent invocation was not released.'
}
$module = Get-Module -Name 'WindowsAccessControl'
& $module {
    param($Target, $SharedCounter)
    $worker = {
        param($WorkerTarget, $WorkerCounter)
        $null = $WorkerCounter.Enter()
        try {
            if (-not $WorkerCounter.ReleaseWorkers.Wait(3000)) {
                throw 'Serialized worker was not released.'
            }
            $WorkerTarget.Value
        } finally {
            $WorkerCounter.Exit()
        }
    }
                Invoke-WindowsAccessControlBatch `
                    -InputObject @($Target) `
                    -ScriptBlock $worker `
                    -ArgumentList $SharedCounter `
                    -CanonicalTargetProperty CanonicalTarget `
                    -SerializeByCanonicalTarget `
                    -ThrottleLimit 1
} $InputValue $Counter
'@
        $firstTarget = [pscustomobject]@{
            CanonicalTarget = 'Registry:Shared'
            Value           = 1
        }
        $secondTarget = [pscustomobject]@{
            CanonicalTarget = 'registry:shared'
            Value           = 2
        }
        $initialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $initialSessionState.ImportPSModule(@($moduleManifest.FullName))
        $runspacePool = [runspacefactory]::CreateRunspacePool(
            1,
            2,
            $initialSessionState,
            $Host
        )
        $firstPowerShell = $null
        $secondPowerShell = $null
        try {
            $runspacePool.Open()
            $firstPowerShell = [powershell]::Create()
            $firstPowerShell.RunspacePool = $runspacePool
            $null = $firstPowerShell.AddScript($invocationScript).
                AddArgument($firstTarget).AddArgument($counter)
            $firstAsyncResult = $firstPowerShell.BeginInvoke()

            $secondPowerShell = [powershell]::Create()
            $secondPowerShell.RunspacePool = $runspacePool
            $null = $secondPowerShell.AddScript($invocationScript).
                AddArgument($secondTarget).AddArgument($counter)
            $secondAsyncResult = $secondPowerShell.BeginInvoke()

            $counter.InvocationReady.Wait(3000) | Should -BeTrue
            $counter.StartInvocations.Set()
            $counter.FirstEntered.Wait(3000) | Should -BeTrue
            $counter.Gate.Wait(1000) | Should -BeFalse
            $counter.ReleaseWorkers.Set()
            $firstResult = $firstPowerShell.EndInvoke($firstAsyncResult)
            $secondResult = $secondPowerShell.EndInvoke($secondAsyncResult)
        } finally {
            $counter.ReleaseWorkers.Set()
            if ($firstPowerShell) { $firstPowerShell.Dispose() }
            if ($secondPowerShell) { $secondPowerShell.Dispose() }
            if ($runspacePool) {
                $runspacePool.Close()
                $runspacePool.Dispose()
            }
            $counter.Gate.Dispose()
            $counter.FirstEntered.Dispose()
            $counter.ReleaseWorkers.Dispose()
            $counter.InvocationReady.Dispose()
            $counter.StartInvocations.Dispose()
        }

        $serializedResults = @($firstResult) + @($secondResult)
        $serializedResults |
            ForEach-Object { [int]$_ } |
            Sort-Object |
            Should -Be @(1, 2)
        $counter.Maximum | Should -Be 1
        $counter.Current | Should -Be 0
    }
}
