function Clear-ProcessAccessRule {
    <#
    .SYNOPSIS
        Clears selected explicit access rules from pinned live processes.
    .DESCRIPTION
        Removes explicit process DACL entries for selected accounts, or every
        explicit access ACE when Account is omitted, on the pinned instance.
    .PARAMETER InputObject
        One or more PIDs, Process objects, or process objects emitted by this module.
    .PARAMETER Handle
        One or more caller-owned process handles that the module never closes.
    .PARAMETER Account
        Optional accounts or SIDs whose explicit access rules are removed.
    .PARAMETER PassThru
        Returns the rules selected for removal after successful persistence.
    .EXAMPLE
        Clear-ProcessAccessRule -ProcessId $PID -Account Everyone -WhatIf

        Previews removing explicit Everyone access rules from the current process.
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
        [Parameter()]
        [Alias('IdentityReference')]
        [object[]]$Account,
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
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, 'Clear explicit process access rules')) {
                $removed = if ($PassThru) {
                    $getRuleParameters = @{
                        Target           = $target
                        RuleType         = 'Access'
                        Account          = $identities
                        ExcludeInherited = $true
                    }
                    @(Get-WindowsProcessAclRule @getRuleParameters)
                }
                $parameters = @{
                    Target             = $target
                    RuleType           = 'Access'
                    Operation          = 'Clear'
                    SecurityIdentifier = $identities
                }
                Invoke-WindowsProcessAclRuleMutation @parameters
                if ($PassThru) { $removed }
            }
        }
    }
}
