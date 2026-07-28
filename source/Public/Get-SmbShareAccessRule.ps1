function Get-SmbShareAccessRule {
    <#
    .SYNOPSIS
        Gets access rules from local SMB share DACLs.
    .DESCRIPTION
        Reads ordinary local share DACLs and emits exact typed access rules
        without combining them with permissions on the backing filesystem.
    .PARAMETER Name
        One or more unqualified local SMB share names.
    .PARAMETER Account
        Filters results by account names, SIDs, identity references, or module identities.
    .PARAMETER ExcludeInherited
        Excludes inherited ACEs; managed share ACEs are normally explicit.
    .PARAMETER ExcludeExplicit
        Excludes explicit ACEs; share DACLs do not define inheritance semantics.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical share targets from 1 through 64.
    .EXAMPLE
        Get-SmbShareAccessRule -Name 'Data$' -Account Everyone

        Gets Everyone rules from the local Data share DACL.
    .INPUTS
        System.String
    .OUTPUTS
        WindowsAccessControl.SmbShareAccessRule
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('ShareName')]
        [object[]]$Name,

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
            Invoke-WindowsSmbShareCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Name $Name `
                -ThrottleLimit $ThrottleLimit
            return
        }
        foreach ($nameValue in $Name) {
            $target = Resolve-WindowsSmbShareTarget -Name $nameValue
            Get-WindowsAclRule `
                -Target $target `
                -RuleType Access `
                -Account $Account `
                -ExcludeInherited:$ExcludeInherited `
                -ExcludeExplicit:$ExcludeExplicit `
                -TypeName 'WindowsAccessControl.SmbShareAccessRule'
        }
    }
}
