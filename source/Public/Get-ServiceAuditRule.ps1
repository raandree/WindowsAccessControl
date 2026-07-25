function Get-ServiceAuditRule {
    <#
    .SYNOPSIS
        Gets audit rules from local services or the Service Control Manager.
    .DESCRIPTION
        Reads service or SCM SACLs under a scoped security privilege and
        returns structured rules with typed rights and success/failure flags.
    .PARAMETER Name
        One or more local service names, ServiceController objects, or module outputs.
    .PARAMETER ServiceControlManager
        Selects the local Service Control Manager instead of a named service.
    .PARAMETER Account
        Filters rules by account names, SIDs, identity references, or module identities.
    .PARAMETER ExcludeInherited
        Excludes inherited ACEs; service descriptors normally contain explicit ACEs only.
    .PARAMETER ExcludeExplicit
        Excludes explicit ACEs; service descriptors do not support inheritance.
    .EXAMPLE
        Get-ServiceAuditRule -Name BITS -Account 'S-1-1-0'

        Gets BITS service audit rules for Everyone.
    .INPUTS
        System.String
        System.ServiceProcess.ServiceController
    .OUTPUTS
        WindowsAccessControl.ServiceAuditRule
        WindowsAccessControl.ServiceControlManagerAuditRule
    #>
    [CmdletBinding(DefaultParameterSetName = 'Service')]
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
        [switch]$ExcludeInherited,

        [Parameter()]
        [switch]$ExcludeExplicit
    )

    process {
        $targets = if ($ServiceControlManager) {
            @(Resolve-WindowsServiceTarget -ServiceControlManager)
        } else {
            @($Name | Resolve-WindowsServiceTarget)
        }
        foreach ($target in $targets) {
            $parameters = @{
                Target           = $target
                RuleType         = 'Audit'
                Account          = $Account
                ExcludeInherited = $ExcludeInherited
                ExcludeExplicit  = $ExcludeExplicit
            }
            Get-WindowsServiceAclRule @parameters
        }
    }
}
