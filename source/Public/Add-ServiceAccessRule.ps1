function Add-ServiceAccessRule {
    <#
    .SYNOPSIS
        Adds access rules to local services or the Service Control Manager.
    .DESCRIPTION
        Resolves and deduplicates accounts before adding explicit access ACEs
        with typed service or SCM rights and one descriptor write per target.
    .PARAMETER Name
        One or more local service names, ServiceController objects, or module outputs.
    .PARAMETER ServiceControlManager
        Selects the local Service Control Manager instead of a named service.
    .PARAMETER Account
        One or more account names, SIDs, identity references, or module identities.
    .PARAMETER ServiceRights
        Rights added to each named-service access rule.
    .PARAMETER ControlManagerRights
        Rights added to each Service Control Manager access rule.
    .PARAMETER AccessControlType
        Creates an Allow rule by default or an explicit Deny rule.
    .PARAMETER PassThru
        Returns each stored explicit access rule after persistence.
    .EXAMPLE
        Add-ServiceAccessRule -Name BITS -Account Everyone -ServiceRights QueryStatus -WhatIf

        Previews adding an Everyone query-status rule to BITS.
    .INPUTS
        System.String
        System.ServiceProcess.ServiceController
    .OUTPUTS
        None
        WindowsAccessControl.ServiceAccessRule
        WindowsAccessControl.ServiceControlManagerAccessRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Service')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Service')]
        [Alias('ServiceName')]
        [object[]]$Name,
        [Parameter(Mandatory, ParameterSetName = 'ServiceControlManager')]
        [switch]$ServiceControlManager,
        [Parameter(Mandatory)]
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,
        [Parameter(Mandatory, ParameterSetName = 'Service')]
        [WindowsServiceRights]$ServiceRights,
        [Parameter(Mandatory, ParameterSetName = 'ServiceControlManager')]
        [WindowsServiceControlManagerRights]$ControlManagerRights,
        [Parameter()]
        [System.Security.AccessControl.AccessControlType]$AccessControlType =
            [System.Security.AccessControl.AccessControlType]::Allow,
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
        $accessMask = if ($PSCmdlet.ParameterSetName -eq 'Service') {
            [int]$ServiceRights
        } else {
            [int]$ControlManagerRights
        }
    }
    process {
        $targets = if ($ServiceControlManager) {
            @(Resolve-WindowsServiceTarget -ServiceControlManager)
        } else {
            @($Name | Resolve-WindowsServiceTarget)
        }
        foreach ($target in $targets) {
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Add $AccessControlType access rules")) {
                $mutationParameters = @{
                    Target             = $target
                    RuleType           = 'Access'
                    Operation          = 'Add'
                    SecurityIdentifier = $identities
                    AccessMask         = $accessMask
                    AccessControlType  = $AccessControlType
                }
                $null = Invoke-WindowsServiceAclRuleMutation @mutationParameters
                if ($PassThru) {
                    $getRuleParameters = @{
                        Target           = $target
                        RuleType         = 'Access'
                        Account          = $identities
                        ExcludeInherited = $true
                    }
                    Get-WindowsServiceAclRule @getRuleParameters
                }
            }
        }
    }
}
