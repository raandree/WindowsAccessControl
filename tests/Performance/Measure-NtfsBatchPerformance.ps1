[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(2, 10000)]
    [int]$TargetCount = 512,

    [Parameter()]
    [ValidateRange(1, 20)]
    [int]$Iterations = 3,

    [Parameter()]
    [ValidateRange(2, 64)]
    [int]$ParallelThrottleLimit = [Math]::Max(
        2,
        [Math]::Min(8, [Environment]::ProcessorCount)
    ),

    [Parameter()]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$moduleManifest = Get-ChildItem -Path (
    Join-Path $repositoryRoot 'output\module\WindowsAccessControl\*\WindowsAccessControl.psd1'
) | Sort-Object -Property { [version]$_.Directory.Name } -Descending |
    Select-Object -First 1
if (-not $moduleManifest) {
    throw 'Build the module before running the performance benchmark.'
}

$benchmarkRoot = Join-Path $env:TEMP (
    'WindowsAccessControlBenchmark-{0}' -f [guid]::NewGuid().ToString('N')
)
$null = New-Item -ItemType Directory -Path $benchmarkRoot -ErrorAction Stop
$module = $null
try {
    for ($index = 0; $index -lt $TargetCount; $index++) {
        $targetPath = Join-Path $benchmarkRoot ('target-{0:D5}.txt' -f $index)
        [System.IO.File]::WriteAllText($targetPath, 'x')
    }
    $paths = [System.IO.Directory]::GetFiles($benchmarkRoot)
    $module = Import-Module -Name $moduleManifest.FullName -Force -PassThru
    $null = Get-NTFSItemOwner -LiteralPath $paths[0] -ThrottleLimit 1

    $measurements = [System.Collections.Generic.List[object]]::new()
    $configurations = @(
        [pscustomobject]@{ Mode = 'Sequential'; ThrottleLimit = 1 }
        [pscustomobject]@{ Mode = 'Parallel'; ThrottleLimit = $ParallelThrottleLimit }
    )
    for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
        $orderedConfigurations = if ($iteration % 2 -eq 0) {
            @($configurations[1], $configurations[0])
        } else {
            $configurations
        }
        foreach ($configuration in $orderedConfigurations) {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $result = @(Get-NTFSItemOwner `
                -LiteralPath $paths `
                -ThrottleLimit $configuration.ThrottleLimit)
            $stopwatch.Stop()
            if ($result.Count -ne $TargetCount) {
                throw "Expected $TargetCount benchmark results, received $($result.Count)."
            }
            $measurements.Add([pscustomobject][ordered]@{
                Iteration          = $iteration
                Mode               = $configuration.Mode
                ThrottleLimit      = $configuration.ThrottleLimit
                TargetCount        = $TargetCount
                ElapsedMilliseconds = [Math]::Round(
                    $stopwatch.Elapsed.TotalMilliseconds,
                    2
                )
                TargetsPerSecond   = [Math]::Round(
                    $TargetCount / $stopwatch.Elapsed.TotalSeconds,
                    2
                )
            })
        }
    }

    $summary = @(
        foreach ($group in $measurements | Group-Object -Property Mode) {
            $elapsed = $group.Group.ElapsedMilliseconds | Measure-Object `
                -Average `
                -Minimum `
                -Maximum
            $throughput = $group.Group.TargetsPerSecond | Measure-Object -Average
            [pscustomobject][ordered]@{
                Mode                       = $group.Name
                ThrottleLimit              = $group.Group[0].ThrottleLimit
                AverageElapsedMilliseconds = [Math]::Round($elapsed.Average, 2)
                MinimumElapsedMilliseconds = [Math]::Round($elapsed.Minimum, 2)
                MaximumElapsedMilliseconds = [Math]::Round($elapsed.Maximum, 2)
                AverageTargetsPerSecond    = [Math]::Round($throughput.Average, 2)
            }
        }
    )
    $benchmark = [pscustomobject][ordered]@{
        SchemaVersion         = 1
        MeasuredUtc           = [DateTime]::UtcNow.ToString('o')
        ModuleVersion         = $module.Version.ToString()
        PowerShellVersion     = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition     = $PSVersionTable.PSEdition
        OperatingSystem       = [Environment]::OSVersion.VersionString
        ProcessorCount        = [Environment]::ProcessorCount
        TargetCount           = $TargetCount
        Iterations            = $Iterations
        ParallelThrottleLimit = $ParallelThrottleLimit
        Runs                  = $measurements.ToArray()
        Summary               = $summary
    }

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $resolvedOutputPath = if ([System.IO.Path]::IsPathRooted($OutputPath)) {
            [System.IO.Path]::GetFullPath($OutputPath)
        } else {
            [System.IO.Path]::GetFullPath((
                Join-Path -Path (Get-Location).ProviderPath -ChildPath $OutputPath
            ))
        }
        $outputDirectory = [System.IO.Path]::GetDirectoryName($resolvedOutputPath)
        if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
            $null = [System.IO.Directory]::CreateDirectory($outputDirectory)
        }
        $json = $benchmark | ConvertTo-Json -Depth 6
        [System.IO.File]::WriteAllText(
            $resolvedOutputPath,
            $json,
            [System.Text.UTF8Encoding]::new($false)
        )
    }

    $benchmark
} finally {
    if ($module) {
        Remove-Module -Name $module.Name -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $benchmarkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
