function Invoke-WindowsProcessCommandBatch {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CommandName,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$BoundParameters,

        [Parameter()]
        [object[]]$InputObject,

        [Parameter()]
        [IntPtr[]]$Handle,

        [Parameter(Mandatory)]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit,

        [Parameter()]
        [switch]$SerializeByCanonicalTarget,

        [Parameter()]
        [System.Management.Automation.ConfirmImpact]$ConfirmationImpact =
            [System.Management.Automation.ConfirmImpact]::None
    )

    $targets = if ($BoundParameters.Keys -contains 'Handle') {
        @(
            foreach ($handleValue in $Handle) {
                $target = Resolve-WindowsProcessTarget -Handle $handleValue
                [pscustomobject]@{
                    CanonicalTarget = $target.CanonicalTarget
                    DescriptorSource = 'Handle'
                    TargetValue     = $target.Handle
                }
            }
        )
    } else {
        @(
            foreach ($inputValue in $InputObject) {
                $target = Resolve-WindowsProcessTarget -InputObject $inputValue
                [pscustomobject]@{
                    CanonicalTarget = $target.CanonicalTarget
                    DescriptorSource = $target.DescriptorSource
                    TargetValue     = if ($target.DescriptorSource -eq 'Handle') {
                        $target.Handle
                    } else {
                        $target
                    }
                }
            }
        )
    }
    Initialize-WindowsAccessControlNativeType
    $parameters = @{}
    foreach ($parameterName in $BoundParameters.Keys) {
        $parameters[$parameterName] = $BoundParameters[$parameterName]
    }
    $null = $parameters.Remove('InputObject')
    $null = $parameters.Remove('Handle')
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
        if ($Target.DescriptorSource -eq 'Handle') {
            $targetParameters.Handle = [IntPtr]$Target.TargetValue
        } else {
            $targetParameters.InputObject = $Target.TargetValue
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
        ObjectFamily            = 'Process'
        OwningModule            = $MyInvocation.MyCommand.Module
    }
    if ($SerializeByCanonicalTarget) {
        $batchParameters.SerializeByCanonicalTarget = $true
    }
    Invoke-WindowsAccessControlBatch @batchParameters
}
