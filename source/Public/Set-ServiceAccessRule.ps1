function Set-ServiceAccessRule {
    <#
    .SYNOPSIS
        Replaces matching access rules on local services or the SCM.
    .DESCRIPTION
        Replaces explicit access ACEs for each selected SID and allow or deny
        qualifier while preserving opposite qualifiers and unrelated rules.
    .PARAMETER Name
        One or more local service names, ServiceController objects, or module outputs.
    .PARAMETER ServiceControlManager
        Selects the local Service Control Manager instead of a named service.
    .PARAMETER Account
        One or more account names, SIDs, identity references, or module identities.
    .PARAMETER ServiceRights
        Replacement rights stored in each named-service rule.
    .PARAMETER ControlManagerRights
        Replacement rights stored in each Service Control Manager rule.
    .PARAMETER AccessControlType
        Replaces Allow rules by default or explicit Deny rules.
    .PARAMETER PassThru
        Returns each stored replacement rule after persistence.
    .EXAMPLE
        Set-ServiceAccessRule -Name BITS -Account Everyone -ServiceRights QueryStatus -Confirm:$false

        Replaces the Everyone allow rule on BITS.
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
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Replace $AccessControlType access rules")) {
                $mutationParameters = @{
                    Target             = $target
                    RuleType           = 'Access'
                    Operation          = 'Set'
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
