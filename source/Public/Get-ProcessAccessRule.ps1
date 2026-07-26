function Get-ProcessAccessRule {
    <#
    .SYNOPSIS
        Gets access rules from pinned live processes.
    .DESCRIPTION
        Reads process DACLs through pinned PID or borrowed-handle targets and
        returns structured rules with normalized masks and WindowsProcessRights.
    .PARAMETER InputObject
        One or more PIDs, Process objects, or process objects emitted by this module.
    .PARAMETER Handle
        One or more caller-owned process handles that the module never closes.
    .PARAMETER Account
        Filters rules by account names, SIDs, identity references, or module identities.
    .PARAMETER ExcludeInherited
        Excludes inherited ACEs; process descriptors normally contain explicit ACEs only.
    .PARAMETER ExcludeExplicit
        Excludes explicit ACEs; process descriptors do not support inheritance.
    .EXAMPLE
        Get-ProcessAccessRule -ProcessId $PID -Account 'S-1-1-0'

        Gets current-process access rules for Everyone.
    .INPUTS
        System.Int32
        System.Diagnostics.Process
    .OUTPUTS
        WindowsAccessControl.ProcessAccessRule
    #>
    [CmdletBinding(DefaultParameterSetName = 'Process')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Process')]
        [Alias('Process', 'Id', 'ProcessId')]
        [object[]]$InputObject,
        [Parameter(Mandatory, ParameterSetName = 'Handle')]
        [IntPtr[]]$Handle,
        [Parameter()]
        [Alias('IdentityReference')]
        [object[]]$Account,
        [Parameter()]
        [switch]$ExcludeInherited,
        [Parameter()]
        [switch]$ExcludeExplicit
    )

    process {
        $targets = if ($PSCmdlet.ParameterSetName -eq 'Handle') {
            @($Handle | ForEach-Object { Resolve-WindowsProcessTarget -Handle $_ })
        } else {
            @($InputObject | Resolve-WindowsProcessTarget)
        }
        foreach ($target in $targets) {
            $parameters = @{
                Target           = $target
                RuleType         = 'Access'
                Account          = $Account
                ExcludeInherited = $ExcludeInherited
                ExcludeExplicit  = $ExcludeExplicit
            }
            Get-WindowsProcessAclRule @parameters
        }
    }
}
