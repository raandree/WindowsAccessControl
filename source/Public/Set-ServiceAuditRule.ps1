function Set-ServiceAuditRule {
    <#
    .SYNOPSIS
        Replaces matching audit rules on local services or the SCM.
    .DESCRIPTION
        Replaces explicit audit ACEs for each selected SID and success/failure
        combination while preserving opposite audit flags and unrelated rules.
    .PARAMETER Name
        One or more local service names, ServiceController objects, or module outputs.
    .PARAMETER ServiceControlManager
        Selects the local Service Control Manager instead of a named service.
    .PARAMETER Account
        One or more account names, SIDs, identity references, or module identities.
    .PARAMETER ServiceRights
        Replacement rights stored in each named-service audit rule.
    .PARAMETER ControlManagerRights
        Replacement rights stored in each Service Control Manager audit rule.
    .PARAMETER AuditFlags
        Selects successful access, failed access, or both for auditing.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical targets. One requests
        deterministic sequential execution.
    .PARAMETER PassThru
        Returns each stored replacement rule after persistence.
    .EXAMPLE
        Set-ServiceAuditRule -Name BITS -Account Everyone -ServiceRights Start -AuditFlags Failure -Confirm:$false

        Replaces the matching failed-access audit rule on BITS.
    .INPUTS
        System.String
        System.ServiceProcess.ServiceController
    .OUTPUTS
        None
        WindowsAccessControl.ServiceAuditRule
        WindowsAccessControl.ServiceControlManagerAuditRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Service')]
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
        $accessMask = if ($PSCmdlet.ParameterSetName -eq 'Service') {
            [int]$ServiceRights
        } else {
            [int]$ControlManagerRights
        }
    }
    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsServiceCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Name $Name `
                -ServiceControlManager:$ServiceControlManager `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact High
            return
        }
        $targets = if ($ServiceControlManager) {
            @(Resolve-WindowsServiceTarget -ServiceControlManager)
        } else {
            @($Name | Resolve-WindowsServiceTarget)
        }
        foreach ($target in $targets) {
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Replace $AuditFlags audit rules")) {
                $mutationParameters = @{
                    Target             = $target
                    RuleType           = 'Audit'
                    Operation          = 'Set'
                    SecurityIdentifier = $identities
                    AccessMask         = $accessMask
                    AuditFlags         = $AuditFlags
                }
                $null = Invoke-WindowsServiceAclRuleMutation @mutationParameters
                if ($PassThru) {
                    $getRuleParameters = @{
                        Target           = $target
                        RuleType         = 'Audit'
                        Account          = $identities
                        ExcludeInherited = $true
                    }
                    Get-WindowsServiceAclRule @getRuleParameters
                }
            }
        }
    }
}
