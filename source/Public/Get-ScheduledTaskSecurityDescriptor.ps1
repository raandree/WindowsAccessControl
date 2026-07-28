function Get-ScheduledTaskSecurityDescriptor {
    <#
    .SYNOPSIS
        Gets the DACL descriptor for local registered tasks.
    .DESCRIPTION
        Resolves a task by its canonical local parent folder and leaf name,
        then reads only its DACL through the in-box Task Scheduler COM API.
    .PARAMETER TaskPath
        One or more absolute local Task Scheduler parent-folder paths.
    .PARAMETER TaskName
        The exact leaf name of the registered task in each supplied folder.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical task targets from 1 to 64.
    .EXAMPLE
        Get-ScheduledTaskSecurityDescriptor -TaskPath '\Operations' -TaskName 'Cleanup'

        Gets the DACL descriptor for the local Cleanup task.
    .INPUTS
        System.String
    .OUTPUTS
        WindowsAccessControl.ScheduledTaskSecurityDescriptor
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
            $descriptor = Get-WindowsTaskSchedulerSecurityDescriptor -Target $target
            ConvertTo-WindowsSecurityDescriptorObject `
                -Target $target `
                -Sections Access `
                -SecurityDescriptor $descriptor `
                -TypeName 'WindowsAccessControl.ScheduledTaskSecurityDescriptor'
        }
    }
}