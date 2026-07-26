function Invoke-WindowsNtfsCommandBatch {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CommandName,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$BoundParameters,

        [Parameter()]
        [string[]]$Path,

        [Parameter()]
        [string[]]$LiteralPath,

        [Parameter(Mandatory)]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit,

        [Parameter()]
        [switch]$SerializeByCanonicalTarget,

        [Parameter()]
        [System.Management.Automation.ConfirmImpact]$ConfirmationImpact =
            [System.Management.Automation.ConfirmImpact]::None
    )

    $resolveParameters = if ($BoundParameters.Keys -contains 'LiteralPath') {
        @{ LiteralPath = $LiteralPath }
    } else {
        @{ Path = $Path }
    }
    $targets = @(
        foreach ($item in Resolve-NTFSPath @resolveParameters) {
            [pscustomobject]@{
                CanonicalTarget = 'FileSystem:{0}' -f
                    $item.FullName.ToUpperInvariant()
                LiteralPath     = $item.FullName
            }
        }
    )
    Initialize-WindowsAccessControlNativeType
    $parameters = @{}
    foreach ($parameterName in $BoundParameters.Keys) {
        $parameters[$parameterName] = $BoundParameters[$parameterName]
    }
    $null = $parameters.Remove('Path')
    $null = $parameters.Remove('LiteralPath')
    $parameters.ThrottleLimit = 1
    $context = [pscustomobject]@{
        CommandName = $CommandName
        Parameters  = $parameters
    }
    $worker = {
        param($Target, $Context)

        $targetParameters = @{}
        foreach ($parameterName in $Context.Parameters.Keys) {
            $targetParameters[$parameterName] =
                $Context.Parameters[$parameterName]
        }
        $targetParameters.LiteralPath = $Target.LiteralPath
        $script:WindowsAccessControlBatchWorker.Value = $true
        try {
            & $Context.CommandName @targetParameters
        } finally {
            $script:WindowsAccessControlBatchWorker.Value = $false
        }
    }
    $confirmationRequired = $ConfirmPreference -ne 'None' -and
        $ConfirmationImpact -ge $ConfirmPreference -and
        -not $WhatIfPreference
    $effectiveThrottleLimit = if ($confirmationRequired) {
        1
    } else {
        $ThrottleLimit
    }
    $batchParameters = @{
        InputObject             = $targets
        ScriptBlock             = $worker
        ArgumentList            = $context
        CanonicalTargetProperty = 'CanonicalTarget'
        ThrottleLimit           = $effectiveThrottleLimit
        CommandName             = $CommandName
        ObjectFamily            = 'FileSystem'
        OwningModule            = $MyInvocation.MyCommand.Module
    }
    if ($SerializeByCanonicalTarget) {
        $batchParameters.SerializeByCanonicalTarget = $true
    }
    Invoke-WindowsAccessControlBatch @batchParameters
}
