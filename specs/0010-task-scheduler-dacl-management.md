# Task Scheduler DACL management

Status: Accepted. This specification defines local-on-target DACL descriptor
management for Task Scheduler folders and registered tasks.

## Scope

The increment exports four commands:

| Task folders | Registered tasks |
| --- | --- |
| `Get-TaskFolderSecurityDescriptor` | `Get-ScheduledTaskSecurityDescriptor` |
| `Set-TaskFolderSecurityDescriptor` | `Set-ScheduledTaskSecurityDescriptor` |

The commands read and persist only the DACL through the in-box Task Scheduler
COM API. They expose no server, computer, session, credential, SACL,
owner/group, rule, backup/restore, effective-access, or DSC surface.

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
  candidate must not add an explicit Local System deny ACE. Broader deny ACEs
  whose group membership could affect the service token are not evaluated in
  this descriptor-only increment and remain an operator responsibility.
- Registered-task writes use `TASK_DONT_ADD_PRINCIPAL_ACE`.
- The service can reorder ACEs and add the system-derived
  `DACL_AUTO_INHERITED` flag. Verification compares DACL protection,
  auto-inherit-required state, ACL revision, and the duplicate-sensitive native
  ACE multiset while ignoring order and only that derived flag.
- A failed or mismatched write attempts exact DACL rollback before returning.
- COM objects are released leaf-to-root in `finally`; operation and cleanup
  failures are aggregated.
- Canonical target deduplication and same-target write serialization precede
  bounded dispatch.

## Verification

Unit tests cover path normalization, containment, system-tree rejection, COM
cleanup after failure, setter flags, Local System preservation, and canonical
DACL comparison. Public contract tests cover all four exports.

Disposable live acceptance creates one disabled inert task inside the marked
folder, proves typed and deduplicated reads, `WhatIf`, unsafe-boundary rejection,
folder and task DACL round trips, Local System preservation, task-definition
preservation, rollback, COM release, and task deletion in Windows PowerShell
5.1 and PowerShell 7.6.3. The complete lab must remain ready afterward.

## Later work

OI-19 tracks a verified Task Scheduler rights model, typed access-rule commands,
and broader service-token deny analysis. It also records whether the service
normalizes ACL revision for object or compound ACEs. OI-20 tracks
schema-version-2 portability and DSC. SACL and direct remote APIs require a
separately accepted contract.

## See also

- [Enterprise expansion](0008-enterprise-access-control-expansion.md)
- [Security and persistence](0004-security-and-persistence.md)
- [Local Task Scheduler authority decision](decisions/0018-use-local-task-and-software-key-authority.md)
- [Open issues](open-issues.md)
