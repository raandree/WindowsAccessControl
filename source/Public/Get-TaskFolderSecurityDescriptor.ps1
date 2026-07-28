function Get-TaskFolderSecurityDescriptor {
    <#
    .SYNOPSIS
        Gets DACL descriptors for local Task Scheduler folders.
    .DESCRIPTION
        Resolves canonical local Task Scheduler folder paths and reads only
        their DACL through the in-box Task Scheduler COM API. No remote target
        or credential parameter is exposed.
    .PARAMETER Path
        One or more absolute local Task Scheduler folder paths.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical folder targets from 1 to 64.
    .EXAMPLE
        Get-TaskFolderSecurityDescriptor -Path '\Operations'

        Gets the DACL descriptor for the local Operations task folder.
    .INPUTS
        System.String
    .OUTPUTS
        WindowsAccessControl.TaskFolderSecurityDescriptor
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('TaskPath')]
        [object[]]$Path,

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
            $descriptor = Get-WindowsTaskSchedulerSecurityDescriptor -Target $target
            ConvertTo-WindowsSecurityDescriptorObject `
                -Target $target `
                -Sections Access `
                -SecurityDescriptor $descriptor `
                -TypeName 'WindowsAccessControl.TaskFolderSecurityDescriptor'
        }
    }
}