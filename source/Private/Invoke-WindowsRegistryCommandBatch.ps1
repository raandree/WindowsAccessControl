function Invoke-WindowsRegistryCommandBatch {
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
        [WindowsRegistryView]$RegistryView,

        [Parameter(Mandatory)]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit,

        [Parameter()]
        [switch]$SerializeByCanonicalTarget,

        [Parameter()]
        [System.Management.Automation.ConfirmImpact]$ConfirmationImpact =
            [System.Management.Automation.ConfirmImpact]::None
    )

    $targets = @(
        foreach ($pathValue in $Path) {
            $target = Resolve-RegistryKeyTarget `
                -Path $pathValue `
                -RegistryView $RegistryView
            [pscustomobject]@{
                CanonicalTarget = $target.CanonicalTarget
                TargetValue     = $target.Path
            }
        }
    )
    Initialize-WindowsAccessControlNativeType
    $parameters = @{}
    foreach ($parameterName in $BoundParameters.Keys) {
        $parameters[$parameterName] = $BoundParameters[$parameterName]
    }
    $null = $parameters.Remove('Path')
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
        $targetParameters.Path = $Target.TargetValue
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
        InputObject            = $targets
        ScriptBlock            = $worker
        ArgumentList           = $context
        CanonicalTargetProperty = 'CanonicalTarget'
        ThrottleLimit          = $effectiveThrottleLimit
        CommandName            = $CommandName
        ObjectFamily           = 'RegistryKey'
        OwningModule           = $MyInvocation.MyCommand.Module
    }
    if ($SerializeByCanonicalTarget) {
        $batchParameters.SerializeByCanonicalTarget = $true
    }
    Invoke-WindowsAccessControlBatch @batchParameters
}
