function Add-ServiceAuditRule {
    <#
    .SYNOPSIS
        Adds audit rules to local services or the Service Control Manager.
    .DESCRIPTION
        Resolves and deduplicates accounts before adding explicit SACL ACEs
        with typed rights and scoped SeSecurityPrivilege for each target.
    .PARAMETER Name
        One or more local service names, ServiceController objects, or module outputs.
    .PARAMETER ServiceControlManager
        Selects the local Service Control Manager instead of a named service.
    .PARAMETER Account
        One or more account names, SIDs, identity references, or module identities.
    .PARAMETER ServiceRights
        Rights audited by each named-service rule.
    .PARAMETER ControlManagerRights
        Rights audited by each Service Control Manager rule.
    .PARAMETER AuditFlags
        Selects successful access, failed access, or both for auditing.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical targets. One requests
        deterministic sequential execution.
    .PARAMETER PassThru
        Returns each stored explicit audit rule after persistence.
    .EXAMPLE
        Add-ServiceAuditRule -Name BITS -Account Everyone -ServiceRights Start -AuditFlags Failure -WhatIf

        Previews adding a failed-start audit rule to BITS.
    .INPUTS
        System.String
        System.ServiceProcess.ServiceController
    .OUTPUTS
        None
        WindowsAccessControl.ServiceAuditRule
        WindowsAccessControl.ServiceControlManagerAuditRule
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
                -ConfirmationImpact Medium
            return
        }
        $targets = if ($ServiceControlManager) {
            @(Resolve-WindowsServiceTarget -ServiceControlManager)
        } else {
            @($Name | Resolve-WindowsServiceTarget)
        }
        foreach ($target in $targets) {
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Add $AuditFlags audit rules")) {
                $mutationParameters = @{
                    Target             = $target
                    RuleType           = 'Audit'
                    Operation          = 'Add'
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
