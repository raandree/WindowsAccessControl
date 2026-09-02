# Task Scheduler

Task Scheduler stores folder and task descriptors on a file-backed store, so a
task folder behaves like a directory and a registered task behaves like a file.
Each gets its own rights enumeration for that reason.

Run these commands on the computer that owns the folder or task, and use
absolute Task Scheduler paths such as `\Operations`.

This family manages the DACL only. It exposes no audit rules, no SACL, and no
direct remote target parameters.

## The write boundary

Every mutator requires an explicit `AllowedRootPath`, so a configuration states
its own containment boundary. On top of that, a write is rejected when it:

- targets the scheduler root or the `\Microsoft` tree;
- fails to retain the current literal Local System ACEs;
- adds an explicit Local System deny ACE;
- newly denies any identity in the Task Scheduler service token; or
- contains an object or compound ACE that the store would silently re-revision.

Task Scheduler may reorder ACEs and add its own derived auto-inherited flag
after a write. The module verifies the native ACE set and the caller-controlled
protection state after persistence rather than demanding byte equality.

## Read a descriptor

```powershell
$taskPath = '\Operations'

$folder = Get-TaskFolderSecurityDescriptor -Path $taskPath
$task   = Get-ScheduledTaskSecurityDescriptor `
    -TaskPath $taskPath `
    -TaskName 'Cleanup'
```

## Write a descriptor

```powershell
Set-TaskFolderSecurityDescriptor `
    -Path $taskPath `
    -AllowedRootPath $taskPath `
    -Sddl $folder.Sddl `
    -WhatIf

Set-ScheduledTaskSecurityDescriptor `
    -TaskPath $taskPath `
    -TaskName 'Cleanup' `
    -AllowedRootPath $taskPath `
    -Sddl $task.Sddl `
    -WhatIf
```

## Typed access rules

Typed rules use the same boundary and the same object-specific rights model:

```powershell
Get-TaskFolderAccessRule -Path $taskPath -ExcludeInherited

Add-TaskFolderAccessRule `
    -Path $taskPath `
    -AllowedRootPath $taskPath `
    -Account 'CONTOSO\Operators' `
    -AccessRights ReadAndTraverse `
    -AppliesTo ThisFolderSubfoldersAndTasks `
    -WhatIf

Get-ScheduledTaskAccessRule -TaskPath $taskPath -TaskName 'Cleanup' -ExcludeInherited |
    Where-Object SID -EQ 'S-1-1-0' |
    Remove-ScheduledTaskAccessRule -AllowedRootPath $taskPath -WhatIf
```

Removal is exact, is idempotent when the ACE is already absent, and refuses an
inherited rule. Remove an inherited rule on the folder that defines it.

## Rights

A task folder is a container and a registered task is a leaf, so the same mask
bit means different things and each object type has its own enumeration:

| `WindowsTaskFolderRights` | Authorizes |
| --- | --- |
| `ListTasks` | Listing the tasks in the folder |
| `CreateTask` | Registering a task in the folder |
| `CreateSubfolder` | Creating a child folder |
| `Traverse` | Traversing into child folders |
| `DeleteChild` | Deleting a child object |

| `WindowsScheduledTaskRights` | Authorizes |
| --- | --- |
| `ReadTaskDefinition` | Reading the task definition |
| `WriteTaskDefinition` | Changing the task definition |
| `RunTask` | Running the task on demand |

Both enumerations also carry `ReadProperties`, `WriteProperties`,
`ReadExtendedProperties`, `WriteExtendedProperties`, `Delete`,
`ReadPermissions`, `ChangePermissions`, `TakeOwnership`, and the generic
rights, plus these composites:

| Composite | Folder meaning | Task meaning |
| --- | --- | --- |
| `Read` | Read folder metadata | Read task metadata |
| `ReadAndTraverse` / `ReadAndRun` | Read and traverse | Read and run |
| `Write` | Write folder metadata | Write task metadata |
| `Modify` | Read, write, and delete | Read, write, and delete |
| `FullControl` | Everything, including permission changes | Everything, including permission changes |

## Rule scope with AppliesTo

`AppliesTo` applies to task folders only. A registered task is a leaf object, so
its rules have no scope to choose:

| Value | Applies to |
| --- | --- |
| `ThisFolderOnly` (default) | The folder itself |
| `ThisFolderSubfoldersAndTasks` | The folder, child folders, and tasks |
| `ThisFolderAndSubfolders` | The folder and child folders |
| `ThisFolderAndTasks` | The folder and tasks in it |
| `SubfoldersAndTasksOnly` | Child folders and tasks only |
| `SubfoldersOnly` | Child folders only |
| `TasksOnly` | Tasks only |

## Portability

Task Scheduler descriptors join the unified backup as record version 2 and are
bound to the owning computer, so a record cannot be replayed elsewhere. A
restore requires the same `AllowedRootPath` boundary as a direct write:

```powershell
Get-TaskFolderSecurityDescriptor -Path $taskPath |
    Backup-WindowsSecurityDescriptor -DestinationPath 'C:\Backup\tasks.json'

Restore-WindowsSecurityDescriptor `
    -BackupPath 'C:\Backup\tasks.json' `
    -AllowedRootPath $taskPath `
    -Confirm:$false
```

## Commands on this page

| Area | Commands |
| --- | --- |
| Folder descriptors | `Get-TaskFolderSecurityDescriptor`, `Set-TaskFolderSecurityDescriptor` |
| Folder access rules | `Get-TaskFolderAccessRule`, `Add-TaskFolderAccessRule`, `Remove-TaskFolderAccessRule` |
| Task descriptors | `Get-ScheduledTaskSecurityDescriptor`, `Set-ScheduledTaskSecurityDescriptor` |
| Task access rules | `Get-ScheduledTaskAccessRule`, `Add-ScheduledTaskAccessRule`, `Remove-ScheduledTaskAccessRule` |

## See also

- [Desired State Configuration](dsc.md#task-scheduler-resources)
- [Backup, restore, and copy](backup-and-restore.md)
- [Task Scheduler DACL management](../../specs/0010-task-scheduler-dacl-management.md)
- [Task Scheduler portability and desired state](../../specs/0014-task-scheduler-portability-and-desired-state.md)
