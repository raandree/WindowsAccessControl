function Get-WindowsServiceAclRule {
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

    $typeName = 'WindowsAccessControl.{0}{1}Rule' -f $Target.ObjectType, $RuleType
    $parameters = @{
        Target           = $Target
        RuleType         = $RuleType
        Account          = $Account
        ExcludeInherited = $ExcludeInherited
        ExcludeExplicit  = $ExcludeExplicit
        TypeName         = $typeName
    }
    Get-WindowsAclRule @parameters
}
