function Get-TaskFolderAccessRule {
    <#
    .SYNOPSIS
        Gets typed access rules from local Task Scheduler folder DACLs.
    .DESCRIPTION
        Reads the folder DACL through the in-box Task Scheduler COM API and
        emits exact typed access rules with Task Scheduler rights and folder
        inheritance scope. No remote target or credential parameter is exposed.
    .PARAMETER Path
        One or more absolute local Task Scheduler folder paths.
    .PARAMETER Account
        Filters results by account names, SIDs, identity references, or module identities.
    .PARAMETER ExcludeInherited
        Excludes ACEs inherited from a parent task folder.
    .PARAMETER ExcludeExplicit
        Excludes ACEs defined directly on the folder.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical folder targets from 1 to 64.
    .EXAMPLE
        Get-TaskFolderAccessRule -Path '\Operations' -ExcludeInherited

        Gets the explicit access rules on the local Operations task folder.
    .INPUTS
        System.String
    .OUTPUTS
        WindowsAccessControl.TaskFolderAccessRule
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('TaskPath')]
        [object[]]$Path,

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
            Invoke-WindowsTaskSchedulerCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -PathParameterName Path `
                -ThrottleLimit $ThrottleLimit
            return
        }
        foreach ($pathValue in $Path) {
            $target = Resolve-WindowsTaskSchedulerTarget -Path ([string]$pathValue)
            Get-WindowsTaskSchedulerAclRule `
                -Target $target `
                -Account $Account `
                -ExcludeInherited:$ExcludeInherited `
                -ExcludeExplicit:$ExcludeExplicit `
                -TypeName 'WindowsAccessControl.TaskFolderAccessRule'
        }
    }
}
