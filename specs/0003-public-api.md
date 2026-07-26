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
- Cross-domain identity and privilege commands use `Windows`-prefixed nouns.
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
- Whole-operation validation errors terminate before mutation. Rule queries and
  path pipelines process one target at a time.

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

Native .NET rule or descriptor objects remain available as properties where a
caller needs exact Windows semantics.

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
| `Add-NTFSAccessRule` | Path, LiteralPath | paths, filesystem objects | none / `AccessRule` |
| `Set-NTFSAccessRule` | Path, LiteralPath | paths, filesystem objects | none / `AccessRule` |
| `Remove-NTFSAccessRule` | Rule, Path, LiteralPath | path-bound `AccessRule` | none / `AccessRule` |
| `Clear-NTFSAccessRule` | Path, LiteralPath | paths, filesystem objects | none |

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
| `Add-NTFSAuditRule` | Path, LiteralPath | paths, filesystem objects | none / `AuditRule` |
| `Set-NTFSAuditRule` | Path, LiteralPath | paths, filesystem objects | none / `AuditRule` |
| `Remove-NTFSAuditRule` | Rule, Path, LiteralPath | path-bound `AuditRule` | none / `AuditRule` |
| `Clear-NTFSAuditRule` | Path, LiteralPath | paths, filesystem objects | none |

Audit commands mirror access-rule semantics but operate on the SACL and require
`SeSecurityPrivilege` for live descriptor reads or writes. They acquire that
privilege only when it exists in the token, reference-count nested use, and
restore the original state (0004, ADR 0008).

## Owner and inheritance commands

| Command | Primary parameter sets | Pipeline input | Returns |
| --- | --- | --- | --- |
| `Get-NTFSItemOwner` | Path, LiteralPath | paths, filesystem objects | `Owner` |
| `Set-NTFSItemOwner` | Path, LiteralPath | paths, filesystem objects | none / `Owner` |
| `Get-NTFSItemInheritance` | Path, LiteralPath | paths, filesystem objects | `Inheritance` |
| `Enable-NTFSItemInheritance` | Path, LiteralPath | paths, filesystem objects | none / `Inheritance` |
| `Disable-NTFSItemInheritance` | Path, LiteralPath | paths, filesystem objects | none / `Inheritance` |

Inheritance commands select `Access`, `Audit`, or `All`. Disabling inheritance
preserves inherited rules as explicit rules by default. Enabling inheritance
can remove explicit rules from the selected ACL with `RemoveExplicitRules`.
Arbitrary owner assignment can require `SeRestorePrivilege`.

## Descriptor portability commands

| Command | Primary parameter sets | Pipeline input | Returns |
| --- | --- | --- | --- |
| `Get-NTFSItemSecurityDescriptor` | Path, LiteralPath | paths, filesystem objects | `SecurityDescriptor` |
| `Copy-NTFSItemSecurityDescriptor` | Path, LiteralPath | destination paths/objects | none / `SecurityDescriptor` |
| `Backup-NTFSItemSecurityDescriptor` | Path, LiteralPath | paths, filesystem objects | none / backup records |
| `Restore-NTFSItemSecurityDescriptor` | (single) | none | none / `SecurityDescriptor` |

The `Sections` value selects any combination of owner, group, DACL, and SACL.
Copy, backup, and restore preserve sections outside that selection (ADR 0003).
Restore reads the target paths from the trusted backup document and validates
every record before the first write (ADR 0005).

## Registry-key commands

| Command | Pipeline input | Returns |
| --- | --- | --- |
| `Get-RegistryKeySecurityDescriptor` | paths, `RegistryKey` objects | `RegistryKeySecurityDescriptor` |
| `Set-RegistryKeySecurityDescriptor` | paths, `RegistryKey` objects | none / `RegistryKeySecurityDescriptor` |
| `Get-RegistryKeyAccessRule` | paths, `RegistryKey` objects | `RegistryKeyAccessRule` |
| `Add-RegistryKeyAccessRule` | paths, `RegistryKey` objects | none / `RegistryKeyAccessRule` |
| `Set-RegistryKeyAccessRule` | paths, `RegistryKey` objects | none / `RegistryKeyAccessRule` |
| `Remove-RegistryKeyAccessRule` | path-bound `RegistryKeyAccessRule` | none / `RegistryKeyAccessRule` |
| `Clear-RegistryKeyAccessRule` | paths, `RegistryKey` objects | none / `RegistryKeyAccessRule` |
| `Get-RegistryKeyAuditRule` | paths, `RegistryKey` objects | `RegistryKeyAuditRule` |
| `Add-RegistryKeyAuditRule` | paths, `RegistryKey` objects | none / `RegistryKeyAuditRule` |
| `Set-RegistryKeyAuditRule` | paths, `RegistryKey` objects | none / `RegistryKeyAuditRule` |
| `Remove-RegistryKeyAuditRule` | path-bound `RegistryKeyAuditRule` | none / `RegistryKeyAuditRule` |
| `Clear-RegistryKeyAuditRule` | paths, `RegistryKey` objects | none / `RegistryKeyAuditRule` |
| `Get-RegistryKeyInheritance` | paths, `RegistryKey` objects | `RegistryKeyInheritance` |
| `Enable-RegistryKeyInheritance` | paths, `RegistryKey` objects | none / `RegistryKeyInheritance` |
| `Disable-RegistryKeyInheritance` | paths, `RegistryKey` objects | none / `RegistryKeyInheritance` |

Registry-rule commands expose `System.Security.AccessControl.RegistryRights`
and preserve unknown or unrelated ACEs. Audit and audit-inheritance operations
scope `SeSecurityPrivilege` to each read/write operation. Registry values do not
have independent security descriptors; callers manage the containing key.

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

## See also

- [Requirements](0002-requirements.md)
- [Security and persistence](0004-security-and-persistence.md)
- [API documentation ADR](decisions/0001-document-api-contract-in-specs-and-help.md)
