# Task Scheduler portability and desired state

Status: Accepted. This specification defines schema-version-2 descriptor
portability, computer-qualified Task Scheduler canonical identity, and
object-specific desired-state resources for the accepted Task Scheduler DACL
increment.

## Scope

The increment adds no new command noun. It extends three existing surfaces:

| Surface | Change |
| --- | --- |
| Task Scheduler canonical identity | The canonical target and lock key are qualified by the owning computer name |
| `Backup-WindowsSecurityDescriptor` | Emits schema-version-2 records for task folder and registered-task descriptors |
| `Restore-WindowsSecurityDescriptor` | Gains `AllowedRootPath` and restores both Task Scheduler families |
| DSC | Adds four class-based resources for task folder and registered-task DACLs |

Audit rules, SACL, owner and group mutation, and direct remote Task Scheduler
APIs remain outside this contract, as specification 0010 already states.

## Computer-qualified identity

A task folder canonical target is `TaskFolder:<COMPUTER>:<PATH>` and a
registered task canonical target is `ScheduledTask:<COMPUTER>:<PATH>`, where
`<COMPUTER>` is the uppercase name of the computer that owns the task store and
`<PATH>` is the uppercase absolute task path. A registered task path is its
parent folder path joined to its leaf name with one separator. The root task
folder is not a supported target for either family, so a task path always names
a real subfolder. The resolved target
additionally reports `Server`, so descriptors, rules, metrics, and the
process-wide canonical write lock all carry the owning computer.

The change does not admit a remote target. ADR 0018 still requires every Task
Scheduler command to execute on the computer that owns the task. The
qualification exists so a portability record cannot be replayed against a
different computer and so evidence names the machine that produced it.

## Backup schema version 2

Record version stays a property of the object family:

| Object family | Record version |
| --- | ---: |
| `FileSystem`, `RegistryKey`, `Service`, `ServiceControlManager`, `Process` | 1 |
| `SmbShare`, `ADObject`, `TaskFolder`, `ScheduledTask` | 2 |

A record whose family and version disagree is rejected in both directions, so a
version-2 record can never be replayed as a local target and a version-1 record
can never claim computer authority.

Task Scheduler records reuse the version-2 `Server` field and carry no new
hashed field. `Target` is the absolute task path, so the canonical target is
exactly `<family>:<SERVER>:<TARGET>` in uppercase and both parts are already
covered by the SHA-256 record digest. Restore derives the folder path and the
leaf task name by splitting `Target` at its last separator, which is
unambiguous because a task name never contains one, and rejects a
registered-task record whose split would name the unsupported root folder.
Because no hashed field was
added, every existing version-1 and version-2 backup still validates.

Both Task Scheduler families select the access section only. A record that
selects any other section is rejected at backup time as well as at restore
time, so an unrestorable record is never persisted.

## Portability restore boundary

- A Task Scheduler record restores only on the computer named in the record. A
  record captured elsewhere is rejected before any COM object is created.
- `Restore-WindowsSecurityDescriptor` requires `AllowedRootPath` when the
  backup contains Task Scheduler records. Every target is resolved for write
  during preparation, so the root, `\Microsoft` system tree, and containment
  rules from specification 0010 reject a bad record before the first write.
- Preparation also re-reads each target and compares the live canonical target
  to the record, which proves both the derived split and the target's existence
  before any earlier record is written.
- The write passes through `Set-TaskFolderSecurityDescriptor` or
  `Set-ScheduledTaskSecurityDescriptor`, which revalidate containment and apply
  the specification 0010 descriptor write gates: non-null DACL, Local System
  preservation, service-token deny rejection, object and compound ACE
  rejection, post-write exact-persistence verification, and verified rollback.
  Specification 0010 scopes its read-time staleness check to rule mutation, so
  a descriptor write remains last-writer-wins against a change made between the
  preparation read and the write.
- Restoring a version-2 record without a verification certificate warns. The
  SHA-256 digest is unkeyed, so it detects accidental damage rather than
  deliberate modification. Sign any backup that leaves the computer that
  produced it, and choose the narrowest `AllowedRootPath` that satisfies the
  restore, because that boundary is the control that bounds a tampered record.

## Desired-state resources

| Resource | Composite keys | State |
| --- | --- | --- |
| `WindowsAccessControlTaskFolderSecurityDescriptor` | `Path`, `Sections` | `AllowedRootPath`, `Sddl` |
| `WindowsAccessControlScheduledTaskSecurityDescriptor` | `TaskPath`, `TaskName`, `Sections` | `AllowedRootPath`, `Sddl` |
| `WindowsAccessControlTaskFolderAccessRule` | `Path`, `Account`, `AccessRights`, `AccessControlType`, `AppliesTo` | `AllowedRootPath`, `Ensure` |
| `WindowsAccessControlScheduledTaskAccessRule` | `TaskPath`, `TaskName`, `Account`, `AccessRights`, `AccessControlType` | `AllowedRootPath`, `Ensure` |

- `Sections` must be `Access`. Any other selection fails closed rather than
  silently managing a section the family does not expose.
- Every resource requires `AllowedRootPath` before a write, so a configuration
  states its own containment boundary the same way the directory resources
  state theirs.
- Descriptor compliance compares DACL protection, auto-inherit-required state,
  ACL revision, and the duplicate-sensitive ACE multiset while ignoring ACE
  order and the derived `DACL_AUTO_INHERITED` flag. Exact SDDL equality would
  report drift on every consistency run because the Task Scheduler service
  canonicalizes ACE order after a write. Windows evaluates a DACL in order, so
  these resources cannot detect or correct a reordering that moves an allow ACE
  ahead of a deny ACE. Do not use them as the sole drift control for an
  order-sensitive deny ACE; model that ACE with a rule-presence resource or an
  external audit instead.
- Folder rule identity includes the inheritance scope, so a rule scoped to
  subfolders never converges by replacing a folder-only ACE. Registered tasks
  are leaf objects and expose no `AppliesTo`.
- The resources take no credential. The Local Configuration Manager runs on the
  computer that owns the task store, which is the only supported authority.
- `Absent` removes every duplicate exact ACE and preserves partial rights,
  inherited ACEs, opposite qualifiers, other scopes, and unrelated accounts.

## Verification

- Unit tests cover the computer-qualified canonical target, version-2 record
  construction for both families, the derived folder and leaf split, rejection
  of a retargeted canonical identity, rejection of a registered-task record
  that names the root folder, the required allowed root path, the
  foreign-computer rejection, and the access-section gate at backup time.
- Unit tests cover DSC routing for both families, the access-section gate, the
  required allowed root path on descriptor and rule writes, and folder rule
  matching on inheritance scope.
- Contract tests assert the exported resource names, composite keys, property
  sets, mandatory `Sddl`, non-configurable `Reasons`, and that the folder
  resource advertises the same `AppliesTo` values as
  `Add-TaskFolderAccessRule`.
- The fixed version-1 record-hash test proves existing local backups still
  validate, and no hashed field was added to version 2.
- Domain-lab acceptance executes the backup round trip, the computer-qualified
  canonical target, the `AllowedRootPath` requirement, and desired-state
  convergence against a live Task Scheduler store. It also proves that a
  drifted descriptor converges in one `Set` and then reports no drift on
  repeated consistency passes for both descriptor resources, so the ACE order
  the service canonicalizes after a write cannot reopen the difference and
  drive an endless correction loop.

## See also

- [Task Scheduler DACL management](0010-task-scheduler-dacl-management.md)
- [Enterprise portability and desired state](0013-enterprise-portability-and-desired-state.md)
- [Public API](0003-public-api.md)
- [Security and persistence](0004-security-and-persistence.md)
- [Enterprise backup schema decision](decisions/0016-require-schema-v2-for-enterprise-targets.md)
- [Task Scheduler portability decision](decisions/0023-qualify-task-scheduler-identity-by-computer.md)
