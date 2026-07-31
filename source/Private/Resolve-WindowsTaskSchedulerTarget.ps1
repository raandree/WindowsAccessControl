function Resolve-WindowsTaskSchedulerTarget {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$TaskName,

        [Parameter()]
        [switch]$ForWrite,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$AllowedRootPath
    )

    process {
        $taskPath = ConvertTo-WindowsTaskSchedulerPath -Path $Path
        if ($PSBoundParameters.ContainsKey('TaskName')) {
            $normalizedTaskName = $TaskName.Trim()
            if ([string]::IsNullOrEmpty($normalizedTaskName) -or
                $normalizedTaskName -in @('.', '..') -or
                $normalizedTaskName -match '[\\/:]' -or
                $normalizedTaskName.Contains([char]0) -or
                [Management.Automation.WildcardPattern]::ContainsWildcardCharacters(
                    $normalizedTaskName
                )) {
                throw [ArgumentException]::new(
                    "Task Scheduler task name '$TaskName' is not a canonical local name."
                )
            }
        }

        if ($ForWrite) {
            if ([string]::IsNullOrWhiteSpace($AllowedRootPath)) {
                throw [ArgumentException]::new(
                    'Task Scheduler writes require AllowedRootPath.'
                )
            }
            $allowedRoot = ConvertTo-WindowsTaskSchedulerPath -Path $AllowedRootPath
            if ($taskPath -eq '\' -or $allowedRoot -eq '\' -or
                $taskPath -ieq '\Microsoft' -or
                $taskPath.StartsWith(
                    '\Microsoft\',
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                $allowedRoot -ieq '\Microsoft' -or
                $allowedRoot.StartsWith(
                    '\Microsoft\',
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw [NotSupportedException]::new(
                    'Task Scheduler root and Microsoft system-tree writes are not supported.'
                )
            }
            if ($taskPath -ine $allowedRoot -and
                -not $taskPath.StartsWith(
                    "$allowedRoot\",
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw [NotSupportedException]::new(
                    "Task Scheduler target '$taskPath' is outside AllowedRootPath '$allowedRoot'."
                )
            }
        }

        $objectType = if ($PSBoundParameters.ContainsKey('TaskName')) {
            'ScheduledTask'
        }
        else {
            'TaskFolder'
        }
        $targetPath = $taskPath
        $targetTaskName = $null
        if ($objectType -eq 'ScheduledTask') {
            $targetPath = "$taskPath\$normalizedTaskName"
            $targetTaskName = $normalizedTaskName
        }
        # The owning computer qualifies the identity so a portability record
        # cannot be replayed against another machine's task store.
        $serverName = [System.Environment]::MachineName.ToUpperInvariant()

        [pscustomobject]@{
            ObjectType       = $objectType
            Path             = $targetPath
            TaskPath         = $taskPath
            TaskName         = $targetTaskName
            Server           = $serverName
            CanonicalTarget  = '{0}:{1}:{2}' -f
                $objectType, $serverName, $targetPath.ToUpperInvariant()
            DescriptorSource = 'TaskSchedulerCom'
        }
    }
}