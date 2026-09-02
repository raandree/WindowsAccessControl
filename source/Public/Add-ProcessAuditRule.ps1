function Add-ProcessAuditRule {
    <#
    .SYNOPSIS
        Adds audit rules to pinned live processes.
    .DESCRIPTION
        Adds explicit process SACL ACEs under scoped privileges after resolving
        and deduplicating identities and pinning PID targets by creation time.
    .PARAMETER InputObject
        One or more PIDs, Process objects, or process objects emitted by this module.
    .PARAMETER Handle
        One or more caller-owned process handles that the module never closes.
    .PARAMETER Account
        One or more account names, SIDs, identity references, or module identities.
    .PARAMETER ProcessRights
        Process rights audited by each selected account rule.
    .PARAMETER AuditFlags
        Selects successful access, failed access, or both for auditing.
    .PARAMETER ThrottleLimit
        Limits concurrently processed pinned targets. One requests
        deterministic sequential execution.
    .PARAMETER PassThru
        Returns each stored explicit process audit rule after persistence.
    .EXAMPLE
        Add-ProcessAuditRule -ProcessId $PID -Account Everyone -ProcessRights Terminate -AuditFlags Failure -WhatIf

        Previews adding a failed-terminate audit rule to the current process.
    .INPUTS
        System.Int32
        System.Diagnostics.Process
    .OUTPUTS
        None
        WindowsAccessControl.ProcessAuditRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Process')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Process')]
        [Alias('Process', 'Id', 'ProcessId')]
        [object[]]$InputObject,
        [Parameter(Mandatory, ParameterSetName = 'Handle')]
        [IntPtr[]]$Handle,
        [Parameter(Mandatory)]
        [Alias('IdentityReference')]
        [object[]]$Account,
        [Parameter(Mandatory)]
        [WindowsProcessRights]$ProcessRights,
        [Parameter()]
        [ValidateScript({ $_ -ne [System.Security.AccessControl.AuditFlags]::None })]
        [System.Security.AccessControl.AuditFlags]$AuditFlags =
            [System.Security.AccessControl.AuditFlags]::Success,
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount)),
        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $seen = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $identities = @(
            foreach ($accountValue in $Account) {
                $sid = Resolve-WindowsIdentityReference -Identity $accountValue
                if ($seen.Add($sid.Value)) { $sid }
            }
        )
    }
    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsProcessCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -InputObject $InputObject `
                -Handle $Handle `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact Medium
            return
        }
        $targets = if ($PSCmdlet.ParameterSetName -eq 'Handle') {
            @($Handle | ForEach-Object { Resolve-WindowsProcessTarget -Handle $_ })
        } else {
            @($InputObject | Resolve-WindowsProcessTarget)
        }
        foreach ($target in $targets) {
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Add $AuditFlags process audit rules")) {
                $parameters = @{
                    Target             = $target
                    RuleType           = 'Audit'
                    Operation          = 'Add'
                    SecurityIdentifier = $identities
                    AccessMask         = [int]$ProcessRights
                    AuditFlags         = $AuditFlags
                }
                Invoke-WindowsProcessAclRuleMutation @parameters
                if ($PassThru) {
                    $getRuleParameters = @{
                        Target           = $target
                        RuleType         = 'Audit'
                        Account          = $identities
                        ExcludeInherited = $true
                    }
                    Get-WindowsProcessAclRule @getRuleParameters
                }
            }
        }
    }
}
