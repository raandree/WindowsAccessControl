function Invoke-WindowsServiceCommandBatch {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CommandName,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$BoundParameters,

        [Parameter()]
        [object[]]$Name,

        [Parameter()]
        [switch]$ServiceControlManager,

        [Parameter(Mandatory)]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit,

        [Parameter()]
        [switch]$SerializeByCanonicalTarget,

        [Parameter()]
        [System.Management.Automation.ConfirmImpact]$ConfirmationImpact =
            [System.Management.Automation.ConfirmImpact]::None
    )

    $targets = if ($ServiceControlManager) {
        $target = Resolve-WindowsServiceTarget -ServiceControlManager
        @([pscustomobject]@{
            CanonicalTarget = $target.CanonicalTarget
            ObjectFamily    = $target.ObjectType
            ServiceName     = $null
        })
    } else {
        @(
            foreach ($nameValue in $Name) {
                $target = Resolve-WindowsServiceTarget -Name $nameValue
                [pscustomobject]@{
                    CanonicalTarget = $target.CanonicalTarget
                    ObjectFamily    = $target.ObjectType
                    ServiceName     = $target.ServiceName
                }
            }
        )
    }
    Initialize-WindowsAccessControlNativeType
    $parameters = @{}
    foreach ($parameterName in $BoundParameters.Keys) {
        $parameters[$parameterName] = $BoundParameters[$parameterName]
    }
    $null = $parameters.Remove('Name')
    $null = $parameters.Remove('ServiceControlManager')
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
        if ($Target.ObjectFamily -eq 'ServiceControlManager') {
            $targetParameters.ServiceControlManager = $true
        } else {
            $targetParameters.Name = $Target.ServiceName
        }
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
        ObjectFamily            = if ($ServiceControlManager) {
            'ServiceControlManager'
        } else {
            'Service'
        }
        OwningModule            = $MyInvocation.MyCommand.Module
    }
    if ($SerializeByCanonicalTarget) {
        $batchParameters.SerializeByCanonicalTarget = $true
    }
    Invoke-WindowsAccessControlBatch @batchParameters
}
