# Task Scheduler DACL management

Status: Accepted. This specification defines local-on-target DACL descriptor
management for Task Scheduler folders and registered tasks.

## Scope

The increment exports ten commands:

| Task folders | Registered tasks |
| --- | --- |
| `Get-TaskFolderSecurityDescriptor` | `Get-ScheduledTaskSecurityDescriptor` |
| `Set-TaskFolderSecurityDescriptor` | `Set-ScheduledTaskSecurityDescriptor` |
| `Get-TaskFolderAccessRule` | `Get-ScheduledTaskAccessRule` |
| `Add-TaskFolderAccessRule` | `Add-ScheduledTaskAccessRule` |
| `Remove-TaskFolderAccessRule` | `Remove-ScheduledTaskAccessRule` |

The commands read and persist only the DACL through the in-box Task Scheduler
COM API. They expose no server, computer, session, credential, SACL,
owner/group, audit-rule, backup/restore, effective-access, or DSC surface.

## Rights model

Task Scheduler stores folder and task descriptors on the file-backed task
store. A task folder is a directory and a registered task is a file, so the
same mask bits authorize different operations and each object type has its own
enum.

| Mask | `WindowsTaskFolderRights` | `WindowsScheduledTaskRights` |
| --- | --- | --- |
| `0x00000001` | `ListTasks` | `ReadTaskDefinition` |
| `0x00000002` | `CreateTask` | `WriteTaskDefinition` |
| `0x00000004` | `CreateSubfolder` | not exposed |
| `0x00000020` | `Traverse` | `RunTask` |
| `0x00000040` | `DeleteChild` | not exposed |

Both enums also expose `ReadExtendedProperties`, `WriteExtendedProperties`,
`ReadProperties`, `WriteProperties`, `Delete`, `ReadPermissions`,
`ChangePermissions`, `TakeOwnership`, `Synchronize`, the four generic rights,
and the `Read`, `Write`, `Modify`, and `FullControl` composites. The folder
enum names the read-and-traverse composite `ReadAndTraverse`; the task enum
names it `ReadAndRun`. Neither enum exposes `ACCESS_SYSTEM_SECURITY`, because
this increment has no SACL surface. The module never surfaces
`FileSystemRights` as a Task Scheduler right.

A task ACE that inherits a folder-only bit outside the `Write`, `Modify`, or
`FullControl` composites reads back as a numeric `AccessRights` value, because
`WindowsScheduledTaskRights` deliberately has no name for an operation a leaf
task cannot perform. `AccessRightsDisplay` reports that bit as a hexadecimal
remainder beside the names it can resolve. `AccessMask` stays exact in every
case, and exact removal is unaffected because it matches the native ACE.

Task folders are containers and carry inheritance. `AppliesTo` covers
`ThisFolderOnly`, `ThisFolderAndTasks`, `ThisFolderAndSubfolders`,
`ThisFolderSubfoldersAndTasks`, `TasksOnly`, `SubfoldersOnly`, and
`SubfoldersAndTasksOnly`; any other stored combination reads back as `Custom`
and is preserved unchanged. Registered tasks are leaf objects, inherit from
their parent folder, and expose no `AppliesTo` parameter.

## Target and authority contract

Paths are absolute local Task Scheduler paths. UNC syntax, wildcards, forward
slashes, duplicate separators, relative segments, root writes, and the
`\Microsoft` system tree are rejected before COM activation. A registered task
is addressed by its parent `TaskPath` plus exact leaf `TaskName`.

Every write requires `AllowedRootPath`. The target must equal that non-root,
non-system path or be its descendant. This is an explicit operator-selected
containment boundary, not proof of ownership. Domain-lab mutation remains
restricted to the marked disposable fixture. Direct remote APIs are excluded;
an administrator runs the commands on the target computer through separately
approved orchestration.

The local caller token supplies `READ_CONTROL` or `WRITE_DAC` authority through
Task Scheduler. The adapter enables no privilege and sends no outbound request.

## Persistence and safety

- Input SDDL is parsed as data and must contain a non-null DACL.
- `ShouldProcess` gates every write with high confirmation impact.
- The target is resolved again inside the operation-scoped COM boundary.
- Every current literal Local System ACE must remain byte-identical, and the
  candidate must not add an explicit Local System deny ACE.
- A write is rejected when the candidate newly denies any identity in the Task
  Scheduler service token and the denied mask intersects the read, write, or
  run access the service requires. The evaluated set is the live LocalSystem
  token group membership captured for the `Schedule` service: SYSTEM, Everyone,
  LOCAL, CONSOLE LOGON, SERVICE, Authenticated Users, This Organization,
  Administrators, Users, Pre-Windows 2000 Compatible Access, ALL SERVICES, and
  the resolved `NT SERVICE\Schedule` identity. That list is best effort: a
  different Windows SKU or build can carry additional groups. A deny ACE
  already present on the target is not re-evaluated, so an affected target
  stays manageable and recoverable; the write warns about it instead. A new
  deny that removes `WRITE_DAC` or `WRITE_OWNER` also warns, because recovering
  from it requires ownership.
- Object and compound ACEs are rejected. They carry no Task Scheduler meaning,
  and the store normalizes the DACL revision from 2 to 4 when one is present,
  which makes exact-persistence verification impossible.
- Registered-task writes use `TASK_DONT_ADD_PRINCIPAL_ACE`.
- The service can reorder ACEs and add the system-derived
  `DACL_AUTO_INHERITED` flag. Verification compares DACL protection,
  auto-inherit-required state, ACL revision, and the duplicate-sensitive native
  ACE multiset while ignoring order and only that derived flag. ACE order is
  therefore neither preserved nor verified.
- A failed or mismatched write attempts exact DACL rollback and verifies it.
  When the rollback cannot be verified the command reports that the stored
  descriptor state is indeterminate.
- Rule mutation reads the DACL once, stages every ACE change in memory, and
  performs at most one verified write per target. The write boundary re-reads
  the target and rejects the write when the DACL changed after the staging
  read, so a change made after that read is rejected instead of clobbered. The
  residual window inside the COM operation scope is narrowed, not eliminated.
  Removal is exact, idempotent when the ACE is already absent, refuses an
  inherited rule, and revalidates canonical identity and containment first. An
  add distinguishes ACEs by inheritance scope, so changing `AppliesTo` for an
  existing account and rights combination adds a distinct ACE instead of being
  suppressed as a duplicate.
- COM objects are released leaf-to-root in `finally`; operation and cleanup
  failures are aggregated.
- Canonical target deduplication and same-target write serialization precede
  bounded dispatch for the path-driven descriptor and add commands. The two
  rule-removal commands take one rule object and do not participate in bounded
  dispatch; the read-time concurrency check is what protects them.

## Verification

Unit tests cover path normalization, containment, system-tree rejection, COM
cleanup after failure, setter flags, Local System preservation, service-token
deny rejection, object-ACE rejection, stale-descriptor rejection, the two
rights-model mask tables, `AppliesTo` flag conversion, inheritance-sensitive
duplicate detection, inherited-rule rejection, canonical-identity revalidation,
and canonical DACL comparison. Public contract tests cover all ten exports.

Disposable live acceptance creates one disabled inert task inside the marked
folder, proves typed and deduplicated reads, `WhatIf`, unsafe-boundary rejection,
folder and task DACL round trips, typed rule add and exact removal with
unrelated-ACE preservation, Local System preservation, task-definition
preservation, rollback, COM release, and task deletion in Windows PowerShell
5.1 and PowerShell 7.6.3. The complete lab must remain ready afterward.

## Later work

Specification 0014 accepts schema-version-2 portability and desired state for
both families. Audit rules, SACL, and direct remote APIs require a separately
accepted contract.

## See also

- [Enterprise expansion](0008-enterprise-access-control-expansion.md)
- [Task Scheduler portability and desired state](0014-task-scheduler-portability-and-desired-state.md)
- [Security and persistence](0004-security-and-persistence.md)
- [Local Task Scheduler authority decision](decisions/0018-use-local-task-and-software-key-authority.md)
- [Open issues](open-issues.md)
