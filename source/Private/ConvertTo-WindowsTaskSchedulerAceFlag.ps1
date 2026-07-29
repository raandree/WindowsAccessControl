function ConvertTo-WindowsTaskSchedulerAceFlag {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.AceFlags])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'ThisFolderOnly',
            'ThisFolderSubfoldersAndTasks',
            'ThisFolderAndSubfolders',
            'ThisFolderAndTasks',
            'SubfoldersAndTasksOnly',
            'SubfoldersOnly',
            'TasksOnly'
        )]
        [string]$AppliesTo
    )

    $containerInherit = [int][System.Security.AccessControl.AceFlags]::ContainerInherit
    $objectInherit = [int][System.Security.AccessControl.AceFlags]::ObjectInherit
    $inheritOnly = [int][System.Security.AccessControl.AceFlags]::InheritOnly

    $flags = switch ($AppliesTo) {
        'ThisFolderOnly' { 0 }
        'ThisFolderSubfoldersAndTasks' { $containerInherit -bor $objectInherit }
        'ThisFolderAndSubfolders' { $containerInherit }
        'ThisFolderAndTasks' { $objectInherit }
        'SubfoldersAndTasksOnly' { $containerInherit -bor $objectInherit -bor $inheritOnly }
        'SubfoldersOnly' { $containerInherit -bor $inheritOnly }
        'TasksOnly' { $objectInherit -bor $inheritOnly }
    }
    [System.Security.AccessControl.AceFlags]$flags
}
