function Get-WindowsAccessControlMetric {
    <#
    .SYNOPSIS
        Gets in-process Windows access-control operation metrics.
    .DESCRIPTION
        Returns thread-safe aggregate snapshots containing operation, target,
        success, failure, and elapsed counts by command and object family.
        Metrics never include SDDL or account secrets and reset when the module
        instance is removed or its hosting process exits.
    .PARAMETER CommandName
        Filters snapshots to one or more exact command names.
    .PARAMETER ObjectFamily
        Filters snapshots to one or more exact object-family names.
    .EXAMPLE
        Get-WindowsAccessControlMetric -ObjectFamily RegistryKey

        Gets metrics for registry-key operations in the current process.
    .INPUTS
        None
    .OUTPUTS
        WindowsAccessControl.Metric
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$CommandName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$ObjectFamily
    )

    $snapshots = [System.Collections.Generic.List[object]]::new()
    [System.Threading.Monitor]::Enter(
        $script:WindowsAccessControlMetricSyncRoot
    )
    try {
        foreach ($metric in $script:WindowsAccessControlMetrics.Values) {
            if ($CommandName -and $metric.CommandName -notin $CommandName) {
                continue
            }
            if ($ObjectFamily -and $metric.ObjectFamily -notin $ObjectFamily) {
                continue
            }
            $snapshot = [pscustomobject][ordered]@{
                CommandName         = $metric.CommandName
                ObjectFamily        = $metric.ObjectFamily
                OperationCount      = [long]$metric.OperationCount
                TargetCount         = [long]$metric.TargetCount
                SuccessCount        = [long]$metric.SuccessCount
                FailureCount        = [long]$metric.FailureCount
                ElapsedMilliseconds = [double]$metric.ElapsedMilliseconds
                Elapsed             = [TimeSpan]::FromMilliseconds(
                    [double]$metric.ElapsedMilliseconds
                )
                LastUpdatedUtc      = [DateTime]$metric.LastUpdatedUtc
            }
            $snapshot.PSObject.TypeNames.Insert(
                0,
                'WindowsAccessControl.Metric'
            )
            $snapshots.Add($snapshot)
        }
    } finally {
        [System.Threading.Monitor]::Exit(
            $script:WindowsAccessControlMetricSyncRoot
        )
    }
    $snapshots | Sort-Object CommandName, ObjectFamily
}
