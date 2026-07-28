function Invoke-WindowsTaskSchedulerCommandBatch {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CommandName,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$BoundParameters,

        [Parameter(Mandatory)]
        [object[]]$Path,

        [Parameter(Mandatory)]
        [ValidateSet('Path', 'TaskPath')]
        [string]$PathParameterName,

        [Parameter()]
        [string]$TaskName,

        [Parameter(Mandatory)]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit,

        [Parameter()]
        [switch]$SerializeByCanonicalTarget,

        [Parameter()]
        [System.Management.Automation.ConfirmImpact]$ConfirmationImpact =
            [System.Management.Automation.ConfirmImpact]::None
    )

    $forWrite = $BoundParameters.ContainsKey('AllowedRootPath')
    $targets = @(
        foreach ($pathValue in $Path) {
            $resolveParameters = @{ Path = [string]$pathValue }
            if ($PSBoundParameters.ContainsKey('TaskName')) {
                $resolveParameters.TaskName = $TaskName
            }
            if ($forWrite) {
                $resolveParameters.ForWrite = $true
                $resolveParameters.AllowedRootPath = $BoundParameters.AllowedRootPath
            }
            Resolve-WindowsTaskSchedulerTarget @resolveParameters
        }
    )
    $parameters = @{}
    foreach ($parameterName in $BoundParameters.Keys) {
        $parameters[$parameterName] = $BoundParameters[$parameterName]
    }
    $null = $parameters.Remove('Path')
    $null = $parameters.Remove('TaskPath')
    $null = $parameters.Remove('TaskName')
    $parameters.ThrottleLimit = 1
    $context = [pscustomobject]@{
        CommandName       = $CommandName
        Parameters        = $parameters
        PathParameterName = $PathParameterName
    }
    $worker = {
        param($Target, $Context)

        $targetParameters = @{}
        foreach ($parameterName in $Context.Parameters.Keys) {
            $targetParameters[$parameterName] = $Context.Parameters[$parameterName]
        }
        $targetParameters[$Context.PathParameterName] = $Target.TaskPath
        if ($Target.ObjectType -eq 'ScheduledTask') {
            $targetParameters.TaskName = $Target.TaskName
        }
        $script:WindowsAccessControlBatchWorker.Value = $true
        try {
            & $Context.CommandName @targetParameters
        }
        finally {
            $script:WindowsAccessControlBatchWorker.Value = $false
        }
    }
    $confirmationRequired = $ConfirmPreference -ne 'None' -and
        $ConfirmationImpact -ge $ConfirmPreference -and
        -not $WhatIfPreference
    $batchParameters = @{
        InputObject             = $targets
        ScriptBlock             = $worker
        ArgumentList            = $context
        CanonicalTargetProperty = 'CanonicalTarget'
        ThrottleLimit           = if ($confirmationRequired) { 1 } else { $ThrottleLimit }
        CommandName             = $CommandName
        ObjectFamily            = 'TaskScheduler'
        OwningModule            = $MyInvocation.MyCommand.Module
    }
    if ($SerializeByCanonicalTarget) {
        $batchParameters.SerializeByCanonicalTarget = $true
    }
    Invoke-WindowsAccessControlBatch @batchParameters
}