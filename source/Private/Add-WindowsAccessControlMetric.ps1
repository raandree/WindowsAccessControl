function Add-WindowsAccessControlMetric {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CommandName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ObjectFamily,

        [Parameter(Mandatory)]
        [ValidateRange(0, [long]::MaxValue)]
        [long]$TargetCount,

        [Parameter(Mandatory)]
        [ValidateRange(0, [long]::MaxValue)]
        [long]$SuccessCount,

        [Parameter(Mandatory)]
        [ValidateRange(0, [long]::MaxValue)]
        [long]$FailureCount,

        [Parameter(Mandatory)]
        [ValidateRange(0, [double]::MaxValue)]
        [double]$ElapsedMilliseconds
    )

    $metricKey = '{0}{1}{2}' -f $CommandName, [char]0, $ObjectFamily
    [System.Threading.Monitor]::Enter(
        $script:WindowsAccessControlMetricSyncRoot
    )
    try {
        if (-not $script:WindowsAccessControlMetrics.ContainsKey($metricKey)) {
            $script:WindowsAccessControlMetrics[$metricKey] = [pscustomobject]@{
                CommandName         = $CommandName
                ObjectFamily        = $ObjectFamily
                OperationCount      = [long]0
                TargetCount         = [long]0
                SuccessCount        = [long]0
                FailureCount        = [long]0
                ElapsedMilliseconds = [double]0
                LastUpdatedUtc      = [DateTime]::MinValue
            }
        }
        $metric = $script:WindowsAccessControlMetrics[$metricKey]
        $metric.OperationCount = [long]$metric.OperationCount + 1
        $metric.TargetCount = [long]$metric.TargetCount + $TargetCount
        $metric.SuccessCount = [long]$metric.SuccessCount + $SuccessCount
        $metric.FailureCount = [long]$metric.FailureCount + $FailureCount
        $metric.ElapsedMilliseconds =
            [double]$metric.ElapsedMilliseconds + $ElapsedMilliseconds
        $metric.LastUpdatedUtc = [DateTime]::UtcNow
    } finally {
        [System.Threading.Monitor]::Exit(
            $script:WindowsAccessControlMetricSyncRoot
        )
    }
}
