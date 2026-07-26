function Get-WindowsProcessAclRule {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,
        [Parameter(Mandatory)]
        [ValidateSet('Access', 'Audit')]
        [string]$RuleType,
        [Parameter()]
        [object[]]$Account,
        [Parameter()]
        [switch]$ExcludeInherited,
        [Parameter()]
        [switch]$ExcludeExplicit
    )

    $parameters = @{
        Target           = $Target
        RuleType         = $RuleType
        Account          = $Account
        ExcludeInherited = $ExcludeInherited
        ExcludeExplicit  = $ExcludeExplicit
        TypeName         = 'WindowsAccessControl.Process{0}Rule' -f $RuleType
    }
    Get-WindowsAclRule @parameters
}
