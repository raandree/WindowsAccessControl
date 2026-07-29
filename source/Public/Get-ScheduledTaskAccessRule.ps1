function Get-ScheduledTaskAccessRule {
    <#
    .SYNOPSIS
        Gets typed access rules from local registered-task DACLs.
    .DESCRIPTION
        Resolves a task by its canonical local parent folder and leaf name,
        reads its DACL through the in-box Task Scheduler COM API, and emits
        exact typed access rules with Task Scheduler rights.
    .PARAMETER TaskPath
        One or more absolute local Task Scheduler parent-folder paths.
    .PARAMETER TaskName
        The exact leaf name of the registered task in each supplied folder.
    .PARAMETER Account
        Filters results by account names, SIDs, identity references, or module identities.
    .PARAMETER ExcludeInherited
        Excludes ACEs inherited from the parent task folder.
    .PARAMETER ExcludeExplicit
        Excludes ACEs defined directly on the registered task.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical task targets from 1 to 64.
    .EXAMPLE
        Get-ScheduledTaskAccessRule -TaskPath '\Operations' -TaskName 'Cleanup'

        Gets every access rule on the local Cleanup task.
    .INPUTS
        System.String
    .OUTPUTS
        WindowsAccessControl.ScheduledTaskAccessRule
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [object[]]$TaskPath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TaskName,

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
                -Path $TaskPath `
                -PathParameterName TaskPath `
                -TaskName $TaskName `
                -ThrottleLimit $ThrottleLimit
            return
        }
        foreach ($pathValue in $TaskPath) {
            $target = Resolve-WindowsTaskSchedulerTarget `
                -Path ([string]$pathValue) `
                -TaskName $TaskName
            Get-WindowsTaskSchedulerAclRule `
                -Target $target `
                -Account $Account `
                -ExcludeInherited:$ExcludeInherited `
                -ExcludeExplicit:$ExcludeExplicit `
                -TypeName 'WindowsAccessControl.ScheduledTaskAccessRule'
        }
    }
}
