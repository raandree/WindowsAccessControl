function Add-ProcessAccessRule {
    <#
    .SYNOPSIS
        Adds access rules to pinned live processes.
    .DESCRIPTION
        Resolves and deduplicates accounts, pins each PID by creation identity,
        and adds explicit process access ACEs with one handle and one write.
    .PARAMETER InputObject
        One or more PIDs, Process objects, or process objects emitted by this module.
    .PARAMETER Handle
        One or more caller-owned process handles that the module never closes.
    .PARAMETER Account
        One or more account names, SIDs, identity references, or module identities.
    .PARAMETER ProcessRights
        Process rights added to each selected account rule.
    .PARAMETER AccessControlType
        Creates an Allow rule by default or an explicit Deny rule.
    .PARAMETER ThrottleLimit
        Limits concurrently processed pinned targets. One requests
        deterministic sequential execution.
    .PARAMETER PassThru
        Returns each stored explicit process access rule after persistence.
    .EXAMPLE
        Add-ProcessAccessRule -ProcessId $PID -Account Everyone -ProcessRights QueryLimitedInformation -WhatIf

        Previews adding an Everyone query rule to the current process.
    .INPUTS
        System.Int32
        System.Diagnostics.Process
    .OUTPUTS
        None
        WindowsAccessControl.ProcessAccessRule
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
        [System.Security.AccessControl.AccessControlType]$AccessControlType =
            [System.Security.AccessControl.AccessControlType]::Allow,
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
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Add $AccessControlType process access rules")) {
                $parameters = @{
                    Target             = $target
                    RuleType           = 'Access'
                    Operation          = 'Add'
                    SecurityIdentifier = $identities
                    AccessMask         = [int]$ProcessRights
                    AccessControlType  = $AccessControlType
                }
                Invoke-WindowsProcessAclRuleMutation @parameters
                if ($PassThru) {
                    $getRuleParameters = @{
                        Target           = $target
                        RuleType         = 'Access'
                        Account          = $identities
                        ExcludeInherited = $true
                    }
                    Get-WindowsProcessAclRule @getRuleParameters
                }
            }
        }
    }
}
