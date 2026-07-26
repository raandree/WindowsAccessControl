function Set-ProcessAccessRule {
    <#
    .SYNOPSIS
        Replaces matching access rules on pinned live processes.
    .DESCRIPTION
        Replaces explicit process ACEs for each selected SID and allow or deny
        qualifier while preserving opposite qualifiers and unrelated entries.
    .PARAMETER InputObject
        One or more PIDs, Process objects, or process objects emitted by this module.
    .PARAMETER Handle
        One or more caller-owned process handles that the module never closes.
    .PARAMETER Account
        One or more account names, SIDs, identity references, or module identities.
    .PARAMETER ProcessRights
        Replacement process rights stored in each selected account rule.
    .PARAMETER AccessControlType
        Replaces Allow rules by default or explicit Deny rules.
    .PARAMETER ThrottleLimit
        Limits concurrently processed pinned targets. One requests
        deterministic sequential execution.
    .PARAMETER PassThru
        Returns each stored replacement rule after persistence.
    .EXAMPLE
        Set-ProcessAccessRule -ProcessId $PID -Account Everyone -ProcessRights Synchronize -Confirm:$false

        Replaces the Everyone allow rule on the current process.
    .INPUTS
        System.Int32
        System.Diagnostics.Process
    .OUTPUTS
        None
        WindowsAccessControl.ProcessAccessRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Process')]
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
        [int]$ThrottleLimit = [Math]::Max(
            1,
            [Math]::Min(8, [Environment]::ProcessorCount)
        ),
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
                -ConfirmationImpact High
            return
        }
        $targets = if ($PSCmdlet.ParameterSetName -eq 'Handle') {
            @($Handle | ForEach-Object { Resolve-WindowsProcessTarget -Handle $_ })
        } else {
            @($InputObject | Resolve-WindowsProcessTarget)
        }
        foreach ($target in $targets) {
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Replace $AccessControlType process access rules")) {
                $parameters = @{
                    Target             = $target
                    RuleType           = 'Access'
                    Operation          = 'Set'
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
