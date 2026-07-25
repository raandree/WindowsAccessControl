# Public API

Status: Accepted. This specification defines the exported command catalog,
pipeline contracts, return types, and cross-cutting conventions for
`NTFSPermission` 0.1.0.

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

- Commands use approved verbs and singular `NTFS`-prefixed nouns.
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

- `NTFSPermission.AccessRule`
- `NTFSPermission.AuditRule`
- `NTFSPermission.Owner`
- `NTFSPermission.Inheritance`
- `NTFSPermission.SecurityDescriptor`
- `NTFSPermission.SecurityDescriptorBackupRecord`
- `NTFSPermission.Identity`
- `NTFSPermission.EffectiveAccess`
- `NTFSPermission.AclTest`
- `NTFSPermission.Privilege`

Native .NET rule or descriptor objects remain available as properties where a
caller needs exact Windows semantics.

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
`SeSecurityPrivilege` for live descriptor reads or writes (0004, ADR 0007).
They do not enable that privilege implicitly.

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

## Identity, diagnostics, and effective access

| Command | Primary parameter sets | Pipeline input | Returns |
| --- | --- | --- | --- |
| `Resolve-NTFSIdentity` | (single) | names, SIDs, identity references | `Identity` |
| `Test-NTFSItemAcl` | Path, LiteralPath | paths, filesystem objects | Boolean / `AclTest` |
| `Get-NTFSItemEffectiveAccess` | Path, LiteralPath | paths, filesystem objects | `EffectiveAccess` |

`Test-NTFSItemAcl` reports preferred Windows ACE order and never repairs the
descriptor automatically. Effective access uses a SID-derived Authz context and
does not include share permissions or every logon-specific group (0004).

## Privilege commands

| Command | Pipeline input | Returns |
| --- | --- | --- |
| `Get-NTFSPrivilege` | none | `Privilege` |
| `Test-NTFSPrivilege` | privilege names | Boolean |
| `Enable-NTFSPrivilege` | privilege names | none / Boolean |
| `Disable-NTFSPrivilege` | privilege names | none / Boolean |

`Get-NTFSPrivilege` is read-only. Enable and disable operations can change only
privileges already present in the current process token. Disabling a privilege
absent from the token is an idempotent no-op; enabling it fails explicitly.

## See also

- [Requirements](0002-requirements.md)
- [Security and persistence](0004-security-and-persistence.md)
- [API documentation ADR](decisions/0001-document-api-contract-in-specs-and-help.md)
