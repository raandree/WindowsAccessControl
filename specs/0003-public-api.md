# Public API

Status: Accepted. This specification defines the exported command catalog,
pipeline contracts, return types, and cross-cutting conventions for
the original NTFS surface in `WindowsAccessControl`.

This document is the design contract. Exhaustive parameter descriptions and
examples live as comment-based help beside each function and are available
through `Get-Help` (ADR 0001).

## API documentation layers

| Layer | Answers | Source of truth |
| --- | --- | --- |
| Design contract | Commands, parameter sets, pipeline, output, safety | This specification |
| Command reference | Every parameter and example | Comment-based help in `source/Public` |

## Cross-cutting conventions

### Naming and structure

- Filesystem commands use approved verbs and singular `NTFS`-prefixed nouns.
- Registry commands use approved verbs and singular `RegistryKey`-prefixed nouns.
- Cross-domain identity, privilege, backup, and restore commands use
  `Windows`-prefixed nouns.
- Every public function uses `CmdletBinding` and declares `OutputType`.
- Every public function has synopsis, description, parameter, example, input,
  and output help where applicable.
- Commands emit structured objects, never formatted text. The module-level
  format file controls only default display.

### Paths and pipeline input

- Filesystem commands provide separate `Path` and `LiteralPath` parameter sets.
- `Path` expands FileSystem-provider wildcards and accepts path strings through
  the pipeline.
- `LiteralPath` treats values exactly and binds filesystem objects through
  their `PSPath` property.
- `FullName` is the by-property alias for wildcard path input.
- Query commands emit one object per rule or target so output can re-enter
  another module command.
- Registry commands accept local provider/native paths and `RegistryKey`
  objects. `WindowsRegistryView` selects the default, 32-bit, or 64-bit view;
  native remote registry paths and remote `RegistryKey` objects are rejected.

### Identity input

- Account-valued input accepts an account name or SID string.
- Multi-account additions resolve every value before mutation, deduplicate by
  SID, and write each target descriptor once (ADR 0006).
- `IdentityReference` and `ID` are compatibility aliases where the add commands
  accept account collections.
- An unresolvable but valid SID remains inspectable and is not discarded.

### State changes and safety

- Every mutator supports `ShouldProcess`, `WhatIf`, and `Confirm` (FR-17).
- Mutators emit nothing by default. `PassThru` returns affected module objects
  where output is useful.
- Remove, clear, owner, copy, restore, and privilege operations use confirmation
  impact appropriate to their destructive reach.
- Whole-operation validation errors terminate before mutation. Target arrays
  are normalized and deduplicated before bounded dispatch.

### Bounded execution and observability

- Ordinary target-array commands accept `ThrottleLimit` from 1 through 64.
- The default is $\max(1, \min(8, \text{ProcessorCount}))$.
- `ThrottleLimit 1` preserves deterministic input order. Parallel commands
  emit output and target-local errors in completion order.
- With `ErrorAction Stop`, already-dispatched parallel targets can finish before
  the batch terminates; no transactional rollback is implied.
- Targets bound together in one array share a batch. Pipeline records preserve
  streaming behavior and enter separate batches; callers collect them before
  invocation when bounded concurrency is required.
- Case-insensitive canonical target deduplication precedes dispatch. Mutations
  of the same canonical target are serialized across module instances in one
  hosting process (ADR 0013).
- Interactive confirmation forces sequential dispatch so prompts do not
  overlap. `WhatIf` continues to flow to every target operation.
- `Get-WindowsAccessControlMetric` returns redacted aggregate operation,
  target, success, failure, and elapsed counters by command and object family.
  Metrics never include SDDL or account secrets.
- Exact rule-object removals remain scalar because each input object already
  identifies one native ACE. Path-based NTFS removals use bounded dispatch.

### Output types

Stable PowerShell type names identify module output:

- `WindowsAccessControl.AccessRule`
- `WindowsAccessControl.AuditRule`
- `WindowsAccessControl.Owner`
- `WindowsAccessControl.Inheritance`
- `WindowsAccessControl.SecurityDescriptor`
- `WindowsAccessControl.SecurityDescriptorBackupRecord`
- `WindowsAccessControl.Identity`
- `WindowsAccessControl.EffectiveAccess`
- `WindowsAccessControl.AclTest`
- `WindowsAccessControl.Privilege`
- `WindowsAccessControl.RegistryKeyAccessRule`
- `WindowsAccessControl.RegistryKeyAuditRule`
- `WindowsAccessControl.RegistryKeyInheritance`
- `WindowsAccessControl.RegistryKeySecurityDescriptor`
- `WindowsAccessControl.ServiceAccessRule`
- `WindowsAccessControl.ServiceAuditRule`
- `WindowsAccessControl.ServiceSecurityDescriptor`
- `WindowsAccessControl.ServiceControlManagerAccessRule`
- `WindowsAccessControl.ServiceControlManagerAuditRule`
- `WindowsAccessControl.ServiceControlManagerSecurityDescriptor`
- `WindowsAccessControl.ProcessAccessRule`
- `WindowsAccessControl.ProcessAuditRule`
- `WindowsAccessControl.ProcessSecurityDescriptor`
- `WindowsAccessControl.SmbShareAccessRule`
- `WindowsAccessControl.SmbShareSecurityDescriptor`
- `WindowsAccessControl.ADObjectAccessRule`
- `WindowsAccessControl.ADObjectSecurityDescriptor`
- `WindowsAccessControl.Metric`

Native .NET rule or descriptor objects remain available as properties where a
caller needs exact Windows semantics.

NTFS `AccessRule` objects expose `InheritedFrom`. It is null for explicit
rules and for inherited rules whose source Windows cannot determine. Otherwise
it contains the normalized local ancestor path returned by the Windows
inheritance-source API. The module does not infer the source by comparing an
ACE with rules on parent directories.

`RegistryKeyAccessRule` objects expose `InheritedFrom` with the same contract,
reported as a provider path such as `HKCU:\Control Panel`. Windows rejects the
`Registry32` and `Registry64` object types for inheritance-source lookups, so
those views always return null rather than an ancestor resolved against a
different view.

`ADObjectAccessRule` objects expose `InheritedFrom` as the distinguished name of
the nearest ancestor object that holds the originating explicit inheritable ACE.
Windows offers no inheritance-source call that can honor the selected domain
controller and credential, so the directory family resolves the source by
walking the ancestor chain over the same bound connection. The value is null for
an explicit rule, for an inherited rule whose origin lies above an ancestor the
caller cannot read, and when the lookup fails.

Every other object family that shares the rule shape carries
the property for a uniform output contract but never populates it, because the
module does not resolve provenance for registry audit rules, service, SCM,
process, or SMB share rules.

Every registry, service, SCM, and process rule object exposes `AccessMask` as a
`UInt64` containing the normalized unsigned 32-bit native mask. `AccessRights`
uses the object family's public enum; exact removal uses the preserved native
ACE rather than reconstructing it from display properties.

The module ships curated default table views for `AccessRule`, `AuditRule`,
`Owner`, `EffectiveAccess`, and `Privilege`. Other result types remain fully
inspectable without a mandatory default view.

## Access-rule commands

| Command | Primary parameter sets | Pipeline input | Returns |
| --- | --- | --- | --- |
| `New-NTFSAccessRule` | (single) | account strings | `AccessRule` |
| `Get-NTFSAccessRule` | Path, LiteralPath | paths, filesystem objects | `AccessRule` |
| `Add-NTFSAccessRule` | Path, LiteralPath, SecurityDescriptor | paths, filesystem objects, descriptors | none / `AccessRule` / descriptor |
| `Set-NTFSAccessRule` | Path, LiteralPath, SecurityDescriptor | paths, filesystem objects, descriptors | none / `AccessRule` / descriptor |
| `Remove-NTFSAccessRule` | Rule, Path, LiteralPath, SecurityDescriptor | path-bound `AccessRule`, descriptors | none / `AccessRule` / descriptor |
| `Clear-NTFSAccessRule` | Path, LiteralPath, SecurityDescriptor | paths, filesystem objects, descriptors | none / descriptor |

`Add-NTFSAccessRule` accumulates rights. `Set-NTFSAccessRule` replaces rules
for the same SID and allow/deny qualifier while preserving unrelated rules.
`Remove-NTFSAccessRule` exposes three explicit modes (ADR 0004):

- `Exact` removes an identical ACE.
- `Rights` subtracts matching rights and may split an ACE.
- `All` purges every explicit ACE for the selected SID.

`Clear-NTFSAccessRule` removes every explicit DACL rule and leaves inherited
rules unchanged.

## Audit-rule commands

| Command | Primary parameter sets | Pipeline input | Returns |
| --- | --- | --- | --- |
| `New-NTFSAuditRule` | (single) | account strings | `AuditRule` |
| `Get-NTFSAuditRule` | Path, LiteralPath | paths, filesystem objects | `AuditRule` |
| `Add-NTFSAuditRule` | Path, LiteralPath, SecurityDescriptor | paths, filesystem objects, descriptors | none / `AuditRule` / descriptor |
| `Set-NTFSAuditRule` | Path, LiteralPath, SecurityDescriptor | paths, filesystem objects, descriptors | none / `AuditRule` / descriptor |
| `Remove-NTFSAuditRule` | Rule, Path, LiteralPath, SecurityDescriptor | path-bound `AuditRule`, descriptors | none / `AuditRule` / descriptor |
| `Clear-NTFSAuditRule` | Path, LiteralPath, SecurityDescriptor | paths, filesystem objects, descriptors | none / descriptor |

Audit commands mirror access-rule semantics but operate on the SACL and require
`SeSecurityPrivilege` for live descriptor reads or writes. They acquire that
privilege only when it exists in the token, reference-count nested use, and
restore the original state (0004, ADR 0008).

## Owner and inheritance commands

| Command | Primary parameter sets | Pipeline input | Returns |
| --- | --- | --- | --- |
| `Get-NTFSItemOwner` | Path, LiteralPath | paths, filesystem objects | `Owner` |
| `Set-NTFSItemOwner` | Path, LiteralPath, SecurityDescriptor | paths, filesystem objects, descriptors | none / `Owner` / descriptor |
| `Get-NTFSItemInheritance` | Path, LiteralPath | paths, filesystem objects | `Inheritance` |
| `Enable-NTFSItemInheritance` | Path, LiteralPath, SecurityDescriptor | paths, filesystem objects, descriptors | none / `Inheritance` / descriptor |
| `Disable-NTFSItemInheritance` | Path, LiteralPath, SecurityDescriptor | paths, filesystem objects, descriptors | none / `Inheritance` / descriptor |

Inheritance commands select `Access`, `Audit`, or `All`. Disabling inheritance
preserves inherited rules as explicit rules by default. Enabling inheritance
can remove explicit rules from the selected ACL with `RemoveExplicitRules`.
Arbitrary owner assignment can require `SeRestorePrivilege`.

## Descriptor portability commands

| Command | Primary parameter sets | Pipeline input | Returns |
| --- | --- | --- | --- |
| `Get-NTFSItemSecurityDescriptor` | Path, LiteralPath | paths, filesystem objects | `SecurityDescriptor` |
| `Edit-NTFSItemSecurityDescriptor` | Path, LiteralPath | paths, filesystem objects | none / `SecurityDescriptor` |
| `Set-NTFSItemSecurityDescriptor` | InputObject | `SecurityDescriptor` objects | none / `SecurityDescriptor` |
| `Copy-NTFSItemSecurityDescriptor` | Path, LiteralPath | destination paths/objects | none / `SecurityDescriptor` |
| `Backup-NTFSItemSecurityDescriptor` | Path, LiteralPath | paths, filesystem objects | none / backup records |
| `Restore-NTFSItemSecurityDescriptor` | (single) | none | none / `SecurityDescriptor` |
| `Backup-WindowsSecurityDescriptor` | InputObject | descriptor objects | none / backup records |
| `Restore-WindowsSecurityDescriptor` | (single) | none | none / family descriptor objects |

The `Sections` value selects any combination of owner, group, DACL, and SACL.
Copy, backup, and restore preserve sections outside that selection (ADR 0003).
The unified backup accepts descriptor output from filesystem, registry,
service/SCM, and pinned process commands. Schema-version 1 records contain
object family, target and canonical identity, native section mask, SDDL, and a
SHA-256 digest. Process records include PID and creation `FILETIME`.

`SigningCertificate` signs every record hash with RSA/SHA-256. Signed records
require the matching `VerificationCertificate`; supplying a verification
certificate also requires every record to be signed. Restore validates every
record and signature, rejects duplicate canonical targets, and prepares all
targets before the first write (ADR 0005). The NTFS-specific commands emit the
same envelope, while restore retains read compatibility with historical NTFS
schema-version 1 files.

Backup signs only after `ShouldProcess` approves the operation and atomically
moves or replaces the completed envelope. Selected absent SACLs use the
explicit `S:NO_ACCESS_CONTROL` representation; omission of a selected SACL and
all null DACLs are rejected.

`Backup-NTFSItemSecurityDescriptor` reads a deduplicated target set with
bounded execution, aborts on any descriptor-read failure, and submits the
complete descriptor array to one atomic envelope write.

`Get-NTFSItemSecurityDescriptor` returns a `SecurityDescriptor` whose
`NativeSecurity` is a live, editable descriptor. Piping that object to a
filesystem mutator's `SecurityDescriptor` parameter set stages the change in
memory and returns the same object without writing. The access, audit, owner,
and inheritance mutators all accept a descriptor this way.
`Set-NTFSItemSecurityDescriptor` then persists the recorded `Sections` back to
the item with a single write under `ShouldProcess`, including the selected ACL
protection state. Path-bound commands remain the read-modify-write default;
this round-trip is the in-memory editing model from specification 0007.

A descriptor-bound mutation fails closed when the required section was not
loaded, because persisting an unloaded section would replace a live ACL with an
empty one. In-memory mutation has no side effect, so it neither calls
`ShouldProcess` nor prompts, and it returns the descriptor regardless of
`PassThru` so mutations can be chained. Each mutation also refreshes the
descriptor's own SDDL, owner, group, and protection projection, so the object
never disagrees with the native descriptor it wraps.

`Edit-NTFSItemSecurityDescriptor` bounds that round trip to one command. It
reads the selected sections once, supplies the detached descriptor as the first
script-block argument, appends `ArgumentList`, suppresses callback output,
rejects unloaded-section expansion, and persists at most once under
`ShouldProcess`. `PassThru` refreshes output from the edited in-memory native
descriptor without a second read.

Every descriptor records a `ConcurrencyToken` over its selected-section SDDL at
read time. `Set-NTFSItemSecurityDescriptor` and `Edit-NTFSItemSecurityDescriptor`
default to last-writer-wins. `RequireUnchanged` re-reads the live sections
before the write and refuses to persist when the token no longer matches,
requiring an explicit re-read. The check narrows but does not eliminate the
race; it is not a transactional guarantee. In-memory mutation never refreshes
the token. A successful persist refreshes it from the descriptor that was
written, without a second read, so a `PassThru` descriptor is reusable only
when Windows stored that descriptor unchanged. Windows can recompute inherited
ACEs and auto-inherit control bits on write, so re-read the descriptor before a
second `RequireUnchanged` write.

The command accepts `ThrottleLimit` for target-array contract consistency but
executes caller callbacks sequentially to preserve script-block runspace
affinity. `WhatIf` skips descriptor persistence; it cannot suppress raw side
effects performed directly by trusted callback code.

## Registry-key commands

| Command | Pipeline input | Returns |
| --- | --- | --- |
| `Get-RegistryKeySecurityDescriptor` | paths, `RegistryKey` objects | `RegistryKeySecurityDescriptor` |
| `Set-RegistryKeySecurityDescriptor` | paths, `RegistryKey` objects, `RegistryKeySecurityDescriptor` | none / `RegistryKeySecurityDescriptor` |
| `Edit-RegistryKeySecurityDescriptor` | paths, `RegistryKey` objects | none / `RegistryKeySecurityDescriptor` |
| `Get-RegistryKeyAccessRule` | paths, `RegistryKey` objects | `RegistryKeyAccessRule` |
| `Add-RegistryKeyAccessRule` | paths, `RegistryKey` objects, `RegistryKeySecurityDescriptor` | none / `RegistryKeyAccessRule` / descriptor |
| `Set-RegistryKeyAccessRule` | paths, `RegistryKey` objects, `RegistryKeySecurityDescriptor` | none / `RegistryKeyAccessRule` / descriptor |
| `Remove-RegistryKeyAccessRule` | path-bound `RegistryKeyAccessRule`, `RegistryKeySecurityDescriptor` | none / `RegistryKeyAccessRule` / descriptor |
| `Clear-RegistryKeyAccessRule` | paths, `RegistryKey` objects, `RegistryKeySecurityDescriptor` | none / `RegistryKeyAccessRule` / descriptor |
| `Get-RegistryKeyAuditRule` | paths, `RegistryKey` objects | `RegistryKeyAuditRule` |
| `Add-RegistryKeyAuditRule` | paths, `RegistryKey` objects, `RegistryKeySecurityDescriptor` | none / `RegistryKeyAuditRule` / descriptor |
| `Set-RegistryKeyAuditRule` | paths, `RegistryKey` objects, `RegistryKeySecurityDescriptor` | none / `RegistryKeyAuditRule` / descriptor |
| `Remove-RegistryKeyAuditRule` | path-bound `RegistryKeyAuditRule`, `RegistryKeySecurityDescriptor` | none / `RegistryKeyAuditRule` / descriptor |
| `Clear-RegistryKeyAuditRule` | paths, `RegistryKey` objects, `RegistryKeySecurityDescriptor` | none / `RegistryKeyAuditRule` / descriptor |
| `Get-RegistryKeyInheritance` | paths, `RegistryKey` objects | `RegistryKeyInheritance` |
| `Enable-RegistryKeyInheritance` | paths, `RegistryKey` objects, `RegistryKeySecurityDescriptor` | none / `RegistryKeyInheritance` / descriptor |
| `Disable-RegistryKeyInheritance` | paths, `RegistryKey` objects, `RegistryKeySecurityDescriptor` | none / `RegistryKeyInheritance` / descriptor |

Registry-rule commands expose `System.Security.AccessControl.RegistryRights`
and preserve unknown or unrelated ACEs. Audit and audit-inheritance operations
scope `SeSecurityPrivilege` to each read/write operation. Registry values do not
have independent security descriptors; callers manage the containing key.

The registry family supports the same detached editing model as the filesystem
family. A descriptor-bound mutation updates the descriptor's binary form, SDDL,
owner, group, and protection projection in place and returns the same object.
`Set-RegistryKeySecurityDescriptor` persists it using the target, registry view,
and sections recorded on the descriptor.
`Edit-RegistryKeySecurityDescriptor` bounds the round trip to one read and at
most one write per canonical target, dispatches callbacks sequentially, and
rejects unloaded-section expansion. Both persist steps accept
`RequireUnchanged` for opt-in optimistic concurrency. Exact ACE removal from a
descriptor takes the rule through `-Rule` because the descriptor occupies the
pipeline.

## Service and Service Control Manager commands

| Command | Primary parameter sets | Pipeline input | Returns |
| --- | --- | --- | --- |
| `Get-ServiceSecurityDescriptor` | Service, ServiceControlManager | service names, `ServiceController` objects | service / SCM descriptor |
| `Set-ServiceSecurityDescriptor` | Service, ServiceControlManager | service names, `ServiceController` objects | none / service / SCM descriptor |
| `Get-ServiceAccessRule` | Service, ServiceControlManager | service names, `ServiceController` objects | service / SCM access rules |
| `Add-ServiceAccessRule` | Service, ServiceControlManager | service names, `ServiceController` objects | none / service / SCM access rules |
| `Set-ServiceAccessRule` | Service, ServiceControlManager | service names, `ServiceController` objects | none / service / SCM access rules |
| `Remove-ServiceAccessRule` | Rule | path-bound service / SCM access rules | none / removed rule |
| `Clear-ServiceAccessRule` | Service, ServiceControlManager | service names, `ServiceController` objects | none / removed rules |
| `Get-ServiceAuditRule` | Service, ServiceControlManager | service names, `ServiceController` objects | service / SCM audit rules |
| `Add-ServiceAuditRule` | Service, ServiceControlManager | service names, `ServiceController` objects | none / service / SCM audit rules |
| `Set-ServiceAuditRule` | Service, ServiceControlManager | service names, `ServiceController` objects | none / service / SCM audit rules |
| `Remove-ServiceAuditRule` | Rule | path-bound service / SCM audit rules | none / removed rule |
| `Clear-ServiceAuditRule` | Service, ServiceControlManager | service names, `ServiceController` objects | none / removed rules |

Named service inputs are service names, not display names. Remote controllers
and qualified service names are rejected. `ServiceControlManager` is an
explicit parameter set, and rule mutations use `WindowsServiceRights` or
`WindowsServiceControlManagerRights` respectively. Service objects do not
support ACL inheritance, so this family exports no inheritance commands and
rule outputs leave inheritance scope empty.

## Process commands

| Command | Primary parameter sets | Pipeline input | Returns |
| --- | --- | --- | --- |
| `Get-ProcessSecurityDescriptor` | Process, Handle | PID, `Process`, module output | `ProcessSecurityDescriptor` |
| `Set-ProcessSecurityDescriptor` | Process, Handle | PID, `Process`, module output | none / `ProcessSecurityDescriptor` |
| `Get-ProcessAccessRule` | Process, Handle | PID, `Process`, module output | `ProcessAccessRule` |
| `Add-ProcessAccessRule` | Process, Handle | PID, `Process`, module output | none / `ProcessAccessRule` |
| `Set-ProcessAccessRule` | Process, Handle | PID, `Process`, module output | none / `ProcessAccessRule` |
| `Remove-ProcessAccessRule` | Rule | path-bound `ProcessAccessRule` | none / removed rule |
| `Clear-ProcessAccessRule` | Process, Handle | PID, `Process`, module output | none / removed rules |
| `Get-ProcessAuditRule` | Process, Handle | PID, `Process`, module output | `ProcessAuditRule` |
| `Add-ProcessAuditRule` | Process, Handle | PID, `Process`, module output | none / `ProcessAuditRule` |
| `Set-ProcessAuditRule` | Process, Handle | PID, `Process`, module output | none / `ProcessAuditRule` |
| `Remove-ProcessAuditRule` | Rule | path-bound `ProcessAuditRule` | none / removed rule |
| `Clear-ProcessAuditRule` | Process, Handle | PID, `Process`, module output | none / removed rules |

PID and `Process` targets are pinned by PID plus creation `FILETIME`; module
output preserves that instance identity for later operations. A mismatched or
missing creation identity fails closed. Explicit caller-owned handles are never
closed by the module and identify the process instance through the handle
lifetime. Process rules use `WindowsProcessRights`, do not support inheritance,
and cease to be meaningful when the process instance exits.

## Identity, diagnostics, and effective access

| Command | Primary parameter sets | Pipeline input | Returns |
| --- | --- | --- | --- |
| `Resolve-WindowsIdentity` | (single) | names, SIDs, identity references | `Identity` |
| `Test-NTFSItemAcl` | Path, LiteralPath | paths, filesystem objects | Boolean / `AclTest` |
| `Get-NTFSItemEffectiveAccess` | Path, LiteralPath | paths, filesystem objects | `EffectiveAccess` |

`Test-NTFSItemAcl` reports preferred Windows ACE order and never repairs the
descriptor automatically. Effective access uses a SID-derived Authz context and
does not include share permissions or every logon-specific group (0004).

## SMB-share commands

| Command | Pipeline input | Returns |
| --- | --- | --- |
| `Get-SmbShareSecurityDescriptor` | local share names | `SmbShareSecurityDescriptor` |
| `Set-SmbShareSecurityDescriptor` | local share names | none / `SmbShareSecurityDescriptor` |
| `Get-SmbShareAccessRule` | local share names | `SmbShareAccessRule` |
| `Get-SmbShareEffectiveAccess` | local share names | `SmbShareEffectiveAccess` |
| `Add-SmbShareAccessRule` | local share names | none / `SmbShareAccessRule` |
| `Remove-SmbShareAccessRule` | path-bound `SmbShareAccessRule` | none / removed rule |

SMB commands accept unqualified local share names only. `WindowsSmbShareRights`
contains `Read`, `Change`, and `Full`. The descriptor setter accepts DACL SDDL;
the add command accepts one or more accounts plus allow/deny; removal is exact.
The commands never modify or claim to evaluate the backing NTFS DACL.
Exact removal is idempotent when the path-bound ACE is already absent.

`Get-SmbShareEffectiveAccess` evaluates only the local share descriptor through
a SID-derived Authz context. Output includes `AuthorizationContext` set to
`LocalSidDerived` and `IncludesBackingNtfs` set to false. The command does not
model a network logon token, a remote resource manager, or the backing NTFS
DACL; ADR 0017 continues to prohibit remote and combined claims.

## Task Scheduler commands

| Command | Pipeline input | Returns |
| --- | --- | --- |
| `Get-TaskFolderSecurityDescriptor` | local task-folder paths | `TaskFolderSecurityDescriptor` |
| `Set-TaskFolderSecurityDescriptor` | local task-folder paths | none / `TaskFolderSecurityDescriptor` |
| `Get-TaskFolderAccessRule` | local task-folder paths | `TaskFolderAccessRule` |
| `Add-TaskFolderAccessRule` | local task-folder paths | none / `TaskFolderAccessRule` |
| `Remove-TaskFolderAccessRule` | path-bound `TaskFolderAccessRule` | none / removed rule |
| `Get-ScheduledTaskSecurityDescriptor` | local parent-folder paths | `ScheduledTaskSecurityDescriptor` |
| `Set-ScheduledTaskSecurityDescriptor` | local parent-folder paths | none / `ScheduledTaskSecurityDescriptor` |
| `Get-ScheduledTaskAccessRule` | local parent-folder paths | `ScheduledTaskAccessRule` |
| `Add-ScheduledTaskAccessRule` | local parent-folder paths | none / `ScheduledTaskAccessRule` |
| `Remove-ScheduledTaskAccessRule` | path-bound `ScheduledTaskAccessRule` | none / removed rule |

Task Scheduler commands use absolute local paths and expose no direct remote
or credential parameter. Registered tasks bind an exact `TaskName` beneath each
`TaskPath`. Every mutator requires an explicit `AllowedRootPath`, rejects root
and `\Microsoft` system-tree writes, parses DACL SDDL as data, preserves current
literal Local System ACEs, rejects explicit Local System deny ACEs, and
participates in high-impact `ShouldProcess`.

`WindowsTaskFolderRights` and `WindowsScheduledTaskRights` are object-specific
rights models. Task folders are directories on the file-backed task store and
registered tasks are files, so the same mask means different things: `0x1` is
`ListTasks` on a folder and `ReadTaskDefinition` on a task, `0x2` is
`CreateTask` versus `WriteTaskDefinition`, and `0x20` is `Traverse` versus
`RunTask`. Both enums expose the shared `Delete`, `ReadPermissions`,
`ChangePermissions`, `TakeOwnership`, generic, `Read`, `Write`, `Modify`, and
`FullControl` members; neither exposes `ACCESS_SYSTEM_SECURITY`. The module
never presents `FileSystemRights` as Task Scheduler rights.

Task-folder rules expose an `AppliesTo` scope of `ThisFolderOnly`,
`ThisFolderAndTasks`, `ThisFolderAndSubfolders`, `ThisFolderSubfoldersAndTasks`,
`TasksOnly`, `SubfoldersOnly`, or `SubfoldersAndTasksOnly`; any other stored
combination reads back as `Custom`. Registered tasks are leaf objects and
expose no `AppliesTo` parameter. An add treats inheritance scope as part of ACE
identity, so changing `AppliesTo` adds a distinct ACE. Removal is exact,
idempotent when the ACE is already absent, refuses an inherited rule, and
revalidates canonical identity and containment before writing.

Every write rejects a candidate that newly denies an identity in the Task
Scheduler service token, rejects object or compound ACEs because the store
normalizes the DACL revision and the write cannot then be verified exactly, and
rejects a candidate whose target changed after the staging read. Task Scheduler
can reorder ACEs and add `DACL_AUTO_INHERITED`; stored-state verification
ignores only those system-derived differences while retaining
duplicate-sensitive native ACE and caller-controlled flag comparison, so ACE
order is neither preserved nor verified. Audit rules, SACL, backup/restore,
DSC, and direct remote APIs remain outside this contract.

## Certificate private-key commands

| Command | Pipeline input | Returns |
| --- | --- | --- |
| `Get-CertificatePrivateKeySecurityDescriptor` | exact `X509Certificate2` | `CertificatePrivateKeySecurityDescriptor` |

The read-only command requires the exact expected CNG provider and persisted
key name in addition to the certificate selector. It supports only RSA keys in
Microsoft Software Key Storage Provider and emits the DACL descriptor plus
stable provider identity metadata. It never searches stores, exports key
material, disposes the caller certificate, or exposes a mutation surface.

## Active Directory object commands

| Command | Pipeline input | Returns |
| --- | --- | --- |
| `Get-ADObjectSecurityDescriptor` | distinguished names | `ADObjectSecurityDescriptor` |
| `Set-ADObjectSecurityDescriptor` | distinguished names | none / `ADObjectSecurityDescriptor` |
| `Get-ADObjectAccessRule` | distinguished names | `ADObjectAccessRule` |
| `Add-ADObjectAccessRule` | distinguished names | none / `ADObjectAccessRule` |
| `Remove-ADObjectAccessRule` | path-bound `ADObjectAccessRule` | none / removed rule |

`Server` is optional on every AD command except `Remove-ADObjectAccessRule`,
which takes it from the path-bound rule. When it is omitted, one writable domain
controller is located in the calling computer's domain, validated by the same
explicit-name rules, and pinned for the whole invocation. Mutators additionally
require `AllowedBaseDistinguishedName`. Query output includes `Server`, current
`DistinguishedName`, immutable `ObjectGuid`, SID/account state, unsigned access
mask, `WindowsActiveDirectoryRights`, allow/deny qualifier, inheritance,
`InheritedFrom`, `ObjectTypeGuid`, `ObjectTypeName`, `InheritedObjectTypeGuid`,
`InheritedObjectTypeName`, and the exact native ACE. The two name properties
report the schema class, attribute, property set, validated write, or extended
right that each GUID identifies, and are null when the GUID is absent or
unresolved.

An optional credential binds directly to the selected DC. It is never emitted,
and it is not used to locate a domain controller. The first increment operates
on DACLs only and exposes no SACL, backup, DSC, replication, or effective-access
contract.
Exact removal is idempotent when the path-bound ACE is already absent.

## Local impersonation

| Command | Primary parameters | Pipeline input | Returns |
| --- | --- | --- | --- |
| `Invoke-WindowsAccessControl` | `Credential`, `ScriptBlock`, `ArgumentList` | none | script-block output |

`Invoke-WindowsAccessControl` creates an opt-in local interactive logon scope.
It restores the caller identity after success or failure and disposes the logon
token before returning. The command does not accept remote target parameters,
serialize credentials, or write passwords to output, errors, logs, metrics, or
backup documents. Commands invoked inside the script block retain their normal
parameter, pipeline, `ShouldProcess`, and output contracts.
The caller must hold the Windows authority required to impersonate, and the
supplied identity must have the local interactive logon right. Windows
PowerShell 5.1 requires .NET Framework 4.6 or later for the managed scoped
impersonation API. Impersonation is thread-scoped; work dispatched to another
job, runspace, or thread does not inherit this command's identity.

## Privilege commands

| Command | Pipeline input | Returns |
| --- | --- | --- |
| `Get-WindowsPrivilege` | none | `Privilege` |
| `Test-WindowsPrivilege` | privilege names | Boolean |
| `Enable-WindowsPrivilege` | privilege names | none / Boolean |
| `Disable-WindowsPrivilege` | privilege names | none / Boolean |

`Get-WindowsPrivilege` is read-only. Enable and disable operations can change only
privileges already present in the current process token. Disabling a privilege
absent from the token is an idempotent no-op; enabling it fails explicitly.
Commands that require SACL, restore, or arbitrary-owner authority use scoped
automatic privilege leases rather than requiring caller choreography.

## Metric command

| Command | Pipeline input | Returns |
| --- | --- | --- |
| `Get-WindowsAccessControlMetric` | none | `Metric` |

Metrics are snapshots from the current module instance. Filters use exact
command and object-family names. Removing the module or ending the hosting
process resets the counters.

## Exact descriptor DSC resources

| Resource | Composite keys | Mandatory state |
| --- | --- | --- |
| `WindowsAccessControlNtfsSecurityDescriptor` | `Path`, `Sections` | `Sddl` |
| `WindowsAccessControlRegistryKeySecurityDescriptor` | `Path`, `RegistryView`, `Sections` | `Sddl` |
| `WindowsAccessControlServiceSecurityDescriptor` | `Name`, `Sections` | `Sddl` |
| `WindowsAccessControlServiceControlManagerSecurityDescriptor` | `Sections` | `Sddl` |
| `WindowsAccessControlProcessSecurityDescriptor` | `ProcessId`, `CreationTimeFileTime`, `Sections` | `Sddl` |

Every resource is class-based, has `Get()`, `Test()`, and `Set()` methods, and
returns `WindowsAccessControlDscReason` entries for selected-section SDDL
drift. Methods are thin adapters over the corresponding commands and private
NTFS persistence boundary. `Set()` converts command errors to terminating DSC
errors and never prompts for confirmation.

Exact comparison includes every selected ACE plus protected/unprotected ACL
state. It excludes only `DiscretionaryAclAutoInherited` and
`SystemAclAutoInherited`, which Windows derives and can add after persistence.
Process keys include creation `FILETIME`; an exited or reused PID fails closed
instead of applying state to a different process.

Desired SDDL should come from the matching descriptor query. A DACL that must
remain exact should normally be protected, because inherited ACEs can be added
after persistence. A node declares at most one SCM exact-descriptor resource;
separate instances with overlapping section keys would express conflicting
ownership of the singleton descriptor. Process resources are ephemeral and
reconverge only while the pinned instance remains alive.
An absent SACL (`S:NO_ACCESS_CONTROL`) remains distinct from a protected empty
SACL (`S:P`); use the latter when inherited audit ACEs must remain absent.

## Access-rule presence DSC resources

| Resource | Composite keys | Configurable state |
| --- | --- | --- |
| `WindowsAccessControlNtfsAccessRule` | `Path`, `Account`, `AccessRights`, `AccessControlType`, `AppliesTo` | `Ensure` |
| `WindowsAccessControlRegistryKeyAccessRule` | `Path`, `RegistryView`, `Account`, `AccessRights`, `AccessControlType`, `AppliesTo` | `Ensure` |
| `WindowsAccessControlServiceAccessRule` | `Name`, `Account`, `ServiceRights`, `AccessControlType` | `Ensure` |
| `WindowsAccessControlServiceControlManagerAccessRule` | `Account`, `ControlManagerRights`, `AccessControlType` | `Ensure` |
| `WindowsAccessControlProcessAccessRule` | `ProcessId`, `CreationTimeFileTime`, `Account`, `ProcessRights`, `AccessControlType` | `Ensure` |

`WindowsAccessControlDscEnsure` exposes `Absent` and `Present`; the resource
default is `Present`. Exact identity is SID, normalized unsigned 32-bit rights
mask, allow/deny qualifier, explicit origin, and inheritance scope where the
target supports inheritance. `Absent` removes every duplicate exact ACE and
does not purge partial rights, inherited rules, opposite qualifiers, other
scopes, or unrelated accounts.

NTFS matching normalizes desired rights through `FileSystemAccessRule` so the
automatic `Synchronize` bit on allowed ACEs does not cause permanent drift.
Registry view and process creation `FILETIME` remain part of target identity.
Because Windows can merge same-account, qualifier, and scope ACEs, a narrower
exact `Present` rule cannot converge beside an existing rights superset; callers
model the superset or use an exact-descriptor resource.

## See also

- [Requirements](0002-requirements.md)
- [Security and persistence](0004-security-and-persistence.md)
- [API documentation ADR](decisions/0001-document-api-contract-in-specs-and-help.md)
