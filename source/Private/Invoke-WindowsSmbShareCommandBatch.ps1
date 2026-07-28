function Invoke-WindowsSmbShareCommandBatch {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CommandName,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$BoundParameters,

        [Parameter(Mandatory)]
        [object[]]$Name,

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
        foreach ($nameValue in $Name) {
            $target = Resolve-WindowsSmbShareTarget -Name $nameValue
            [pscustomobject]@{
                CanonicalTarget = $target.CanonicalTarget
                ShareName       = $target.ShareName
            }
        }
    )
    Initialize-WindowsAccessControlNativeType
    $parameters = @{}
    foreach ($parameterName in $BoundParameters.Keys) {
        $parameters[$parameterName] = $BoundParameters[$parameterName]
    }
    $null = $parameters.Remove('Name')
    $parameters.ThrottleLimit = 1
    $context = [pscustomobject]@{
        CommandName = $CommandName
        Parameters  = $parameters
    }
    $worker = {
        param($Target, $Context)

        $targetParameters = @{}
        foreach ($parameterName in $Context.Parameters.Keys) {
            $targetParameters[$parameterName] = $Context.Parameters[$parameterName]
        }
        $targetParameters.Name = $Target.ShareName
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
        ObjectFamily            = 'SmbShare'
        OwningModule            = $MyInvocation.MyCommand.Module
    }
    if ($SerializeByCanonicalTarget) {
        $batchParameters.SerializeByCanonicalTarget = $true
    }
    Invoke-WindowsAccessControlBatch @batchParameters
}
