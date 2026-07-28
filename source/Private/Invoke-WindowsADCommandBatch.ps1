function Invoke-WindowsADCommandBatch {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string]$CommandName,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$BoundParameters,

        [Parameter(Mandatory)]
        [string]$Server,

        [Parameter(Mandatory)]
        [object[]]$DistinguishedName,

        [Parameter()]
        [pscredential]$Credential,

        [Parameter(Mandatory)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory)]
        [int]$ThrottleLimit,

        [Parameter()]
        [switch]$SerializeByCanonicalTarget,

        [Parameter()]
        [System.Management.Automation.ConfirmImpact]$ConfirmationImpact =
            [System.Management.Automation.ConfirmImpact]::None
    )

    $targets = @(
        foreach ($dnValue in $DistinguishedName) {
            $resolveParameters = @{
                Server = $Server
                DistinguishedName = [string]$dnValue
                Credential = $Credential
                TimeoutSeconds = $TimeoutSeconds
            }
            if ($BoundParameters.ContainsKey('AllowedBaseDistinguishedName')) {
                $resolveParameters.AllowedBaseDistinguishedName =
                    [string]$BoundParameters.AllowedBaseDistinguishedName
                $resolveParameters.ForWrite = $true
            }
            $target = Resolve-WindowsADObjectTarget @resolveParameters
            [pscustomobject]@{
                CanonicalTarget = $target.CanonicalTarget
                DistinguishedName = $target.DistinguishedName
            }
        }
    )
    $parameters = @{}
    foreach ($parameterName in $BoundParameters.Keys) {
        $parameters[$parameterName] = $BoundParameters[$parameterName]
    }
    $null = $parameters.Remove('DistinguishedName')
    $parameters.ThrottleLimit = 1
    $context = [pscustomobject]@{
        CommandName = $CommandName
        Parameters = $parameters
    }
    $worker = {
        param($Target, $Context)

        $targetParameters = @{}
        foreach ($parameterName in $Context.Parameters.Keys) {
            $targetParameters[$parameterName] = $Context.Parameters[$parameterName]
        }
        $targetParameters.DistinguishedName = $Target.DistinguishedName
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
        InputObject = $targets
        ScriptBlock = $worker
        ArgumentList = $context
        CanonicalTargetProperty = 'CanonicalTarget'
        ThrottleLimit = if ($confirmationRequired) { 1 } else { $ThrottleLimit }
        CommandName = $CommandName
        ObjectFamily = 'ADObject'
        OwningModule = $MyInvocation.MyCommand.Module
    }
    if ($SerializeByCanonicalTarget) {
        $batchParameters.SerializeByCanonicalTarget = $true
    }
    Invoke-WindowsAccessControlBatch @batchParameters
}
