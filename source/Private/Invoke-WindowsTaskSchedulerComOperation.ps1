function Invoke-WindowsTaskSchedulerComOperation {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [scriptblock]$Operation
    )

    $service = $null
    $folder = $null
    $task = $null
    $result = $null
    $operationError = $null
    $cleanupErrors = [Collections.Generic.List[Exception]]::new()
    try {
        $service = New-WindowsTaskSchedulerService
        $service.Connect()
        $folder = $service.GetFolder($Target.TaskPath)
        if ([string]$folder.Path -ine [string]$Target.TaskPath) {
            throw [InvalidOperationException]::new(
                "Task Scheduler returned folder '$($folder.Path)' for '$($Target.TaskPath)'."
            )
        }

        $nativeTarget = $folder
        if ($Target.ObjectType -eq 'ScheduledTask') {
            $task = $folder.GetTask($Target.TaskName)
            if ([string]$task.Name -ine [string]$Target.TaskName) {
                throw [InvalidOperationException]::new(
                    "Task Scheduler returned task '$($task.Name)' for '$($Target.TaskName)'."
                )
            }
            $nativeTarget = $task
        }
        $result = & $Operation $nativeTarget
    }
    catch {
        $operationError = $_
    }
    finally {
        foreach ($comObject in @($task, $folder, $service)) {
            if ($null -ne $comObject) {
                try {
                    Close-WindowsTaskSchedulerComObject -InputObject $comObject
                }
                catch {
                    $cleanupErrors.Add($_.Exception)
                }
            }
        }
    }

    if ($operationError -and $cleanupErrors.Count -gt 0) {
        throw [AggregateException]::new(
            'The Task Scheduler operation and COM cleanup both failed.',
            [Exception[]]@($operationError.Exception) + $cleanupErrors.ToArray()
        )
    }
    if ($operationError) {
        throw $operationError
    }
    if ($cleanupErrors.Count -gt 0) {
        throw [AggregateException]::new(
            'Task Scheduler COM cleanup failed.',
            $cleanupErrors.ToArray()
        )
    }

    $result
}