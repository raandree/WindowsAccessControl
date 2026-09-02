function Get-ServiceAccessRule {
    <#
    .SYNOPSIS
        Gets access rules from local services or the Service Control Manager.
    .DESCRIPTION
        Reads service or SCM DACLs and returns structured rules with SID,
        account, qualifier, and the corresponding typed service rights enum.
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
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical targets. One requests
        deterministic sequential execution.
    .EXAMPLE
        Get-ServiceAccessRule -Name BITS -Account 'BUILTIN\Users'

        Gets BITS service access rules for the Users group.
    .INPUTS
        System.String
        System.ServiceProcess.ServiceController
    .OUTPUTS
        WindowsAccessControl.ServiceAccessRule
        WindowsAccessControl.ServiceControlManagerAccessRule
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
        [switch]$ExcludeExplicit,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount))
    )

    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsServiceCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Name $Name `
                -ServiceControlManager:$ServiceControlManager `
                -ThrottleLimit $ThrottleLimit
            return
        }
        $targets = if ($ServiceControlManager) {
            @(Resolve-WindowsServiceTarget -ServiceControlManager)
        } else {
            @($Name | Resolve-WindowsServiceTarget)
        }
        foreach ($target in $targets) {
            $parameters = @{
                Target           = $target
                RuleType         = 'Access'
                Account          = $Account
                ExcludeInherited = $ExcludeInherited
                ExcludeExplicit  = $ExcludeExplicit
            }
            Get-WindowsServiceAclRule @parameters
        }
    }
}
