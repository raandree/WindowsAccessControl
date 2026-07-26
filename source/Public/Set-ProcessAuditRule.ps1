function Set-ProcessAuditRule {
    <#
    .SYNOPSIS
        Replaces matching audit rules on pinned live processes.
    .DESCRIPTION
        Replaces process audit ACEs for selected SIDs and success/failure flags
        while preserving opposite flags and unrelated descriptor entries.
    .PARAMETER InputObject
        One or more PIDs, Process objects, or process objects emitted by this module.
    .PARAMETER Handle
        One or more caller-owned process handles that the module never closes.
    .PARAMETER Account
        One or more account names, SIDs, identity references, or module identities.
    .PARAMETER ProcessRights
        Replacement process rights stored in each selected audit rule.
    .PARAMETER AuditFlags
        Selects successful access, failed access, or both for auditing.
    .PARAMETER PassThru
        Returns each stored replacement rule after persistence.
    .EXAMPLE
        Set-ProcessAuditRule -ProcessId $PID -Account Everyone -ProcessRights Terminate -AuditFlags Failure -Confirm:$false

        Replaces the matching current-process failure audit rule.
    .INPUTS
        System.Int32
        System.Diagnostics.Process
    .OUTPUTS
        None
        WindowsAccessControl.ProcessAuditRule
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
        [ValidateScript({ $_ -ne [System.Security.AccessControl.AuditFlags]::None })]
        [System.Security.AccessControl.AuditFlags]$AuditFlags =
            [System.Security.AccessControl.AuditFlags]::Success,
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
        $targets = if ($PSCmdlet.ParameterSetName -eq 'Handle') {
            @($Handle | ForEach-Object { Resolve-WindowsProcessTarget -Handle $_ })
        } else {
            @($InputObject | Resolve-WindowsProcessTarget)
        }
        foreach ($target in $targets) {
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Replace $AuditFlags process audit rules")) {
                $parameters = @{
                    Target             = $target
                    RuleType           = 'Audit'
                    Operation          = 'Set'
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
