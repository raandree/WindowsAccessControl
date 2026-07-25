function Clear-ServiceAccessRule {
    <#
    .SYNOPSIS
        Clears selected explicit access rules from local services or the SCM.
    .DESCRIPTION
        Removes explicit DACL entries for selected accounts, or every explicit
        access ACE when Account is omitted, while preserving unknown ACE types.
    .PARAMETER Name
        One or more local service names, ServiceController objects, or module outputs.
    .PARAMETER ServiceControlManager
        Selects the local Service Control Manager instead of a named service.
    .PARAMETER Account
        Optional accounts or SIDs whose explicit access rules are removed.
    .PARAMETER PassThru
        Returns the rules selected for removal after successful persistence.
    .EXAMPLE
        Clear-ServiceAccessRule -Name BITS -Account Everyone -WhatIf

        Previews removing explicit Everyone access rules from BITS.
    .INPUTS
        System.String
        System.ServiceProcess.ServiceController
    .OUTPUTS
        None
        WindowsAccessControl.ServiceAccessRule
        WindowsAccessControl.ServiceControlManagerAccessRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Service')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Service')]
        [Alias('ServiceName')]
        [object[]]$Name,
        [Parameter(Mandatory, ParameterSetName = 'ServiceControlManager')]
        [switch]$ServiceControlManager,
        [Parameter()]
        [Alias('IdentityReference', 'ID')]
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
        $targets = if ($ServiceControlManager) {
            @(Resolve-WindowsServiceTarget -ServiceControlManager)
        } else {
            @($Name | Resolve-WindowsServiceTarget)
        }
        foreach ($target in $targets) {
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, 'Clear explicit access rules')) {
                $removed = if ($PassThru) {
                    $getRuleParameters = @{
                        Target           = $target
                        RuleType         = 'Access'
                        Account          = $identities
                        ExcludeInherited = $true
                    }
                    @(Get-WindowsServiceAclRule @getRuleParameters)
                }
                $mutationParameters = @{
                    Target             = $target
                    RuleType           = 'Access'
                    Operation          = 'Clear'
                    SecurityIdentifier = $identities
                }
                $null = Invoke-WindowsServiceAclRuleMutation @mutationParameters
                if ($PassThru) { $removed }
            }
        }
    }
}
