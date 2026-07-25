# Security and persistence

Status: Accepted. This specification defines NTFS descriptor boundaries,
privilege behavior, persistence guarantees, backup trust, and effective-access
limits.

## Security descriptor model

The module operates on four independently selectable descriptor sections:

- Owner
- Primary group
- DACL (`Access`)
- SACL (`Audit`)

Public objects include portable metadata and keep the native descriptor or rule
where exact Windows semantics matter. The module does not invent an alternative
ACL engine.

## Section-scoped persistence

An operation loads the sections it needs and persists the modified descriptor
through the runtime-specific filesystem access-control API (ADR 0003):

- PowerShell 7 uses `FileSystemAclExtensions`.
- Windows PowerShell 5.1 uses the .NET Framework file or directory security
  methods.

A DACL operation must not request SACL privileges or overwrite SACL, owner, or
group state. An owner-only operation must not rewrite access rules. Copy and
restore write exactly the recorded section set.

## Access and audit mutation semantics

The managed ACL methods are not interchangeable (ADR 0004):

- Add accumulates or combines rights.
- Set replaces rules for one SID and qualifier.
- Exact removal removes an identical ACE.
- Rights removal subtracts a matching mask and may split an ACE.
- Account purge removes every explicit ACE for a SID.
- Clear removes every explicit rule in the selected ACL.

Whole-list reset is not exposed as a routine rule operation because it can
destroy unrelated permissions.

## Identity prevalidation and batching

Multi-account additions resolve every account before any target descriptor is
loaded for mutation. Resolved identities are deduplicated by SID, including
different names that translate to the same SID. One invalid identity terminates
the operation before persistence. Each target is written once (ADR 0006).

An orphaned SID remains a valid identity. Queries mark it unresolved instead of
aborting enumeration. Administrators must not assume that an unresolved SID is
deleted; domain connectivity can also prevent translation.

## Inheritance

Protection enabled means inheritance disabled. When disabling inheritance:

- `PreserveInherited = true` converts inherited ACEs to explicit ACEs.
- `PreserveInherited = false` discards inherited ACEs.

The default preserves effective access. When enabling inheritance,
`RemoveExplicitRules` removes only explicit ACEs from the selected ACL before
the descriptor is persisted. Inherited ACEs are not selected for removal.

## Privilege boundary

The module recognizes the Windows privilege boundary without broadening it as a
side effect (ADR 0007):

- `SeSecurityPrivilege` gates SACL reads and writes.
- `SeRestorePrivilege` can permit arbitrary valid owner assignment and restore
  writes.
- `SeTakeOwnershipPrivilege` can permit taking ownership.
- `SeBackupPrivilege` can permit backup-oriented reads.

Privilege inventory opens the token for query only. Explicit enable/disable
commands call `AdjustTokenPrivileges`, check `ERROR_NOT_ALL_ASSIGNED`, and
cannot add a privilege to the token. Importing the module, querying an ACL, or
computing effective access never silently enables broad privileges.

The module does not temporarily set the owner after authorization failure.
Such fallback changes an additional security boundary and can fail to restore
the original owner.

## Native resource safety

The privilege and Authz interop uses handle-safe and architecture-neutral
layouts:

- Native handles and unmanaged buffers are released in `finally` blocks.
- Variable-length token privilege entries use `Marshal.OffsetOf` and
  `Marshal.SizeOf`, not hard-coded pointer offsets.
- `GetLastWin32Error` is read immediately after APIs declared with
  `SetLastError`.
- Authz contexts and resource managers are freed even when access evaluation
  fails.

## Backup and restore trust model

Backups use schema version 1 and contain:

- canonical target path
- item type (`File` or `Directory`)
- selected section bitmask
- SDDL for those sections

JSON is parsed as data and never evaluated. Restore validates schema, required
fields, section range, unique targets, target existence, item type, and SDDL for
every record before the first write (ADR 0005). This prevents a malformed later
record from causing a partial restore.

A validated restore can still stop after an earlier successful write if the
filesystem fails during persistence. The same backup can be rerun after the I/O
condition is corrected.

Backup files control restore paths. They are trusted administrative input and
must not be accepted from an untrusted source without review.

## Effective-access boundary

`Get-NTFSItemEffectiveAccess` uses `AuthzInitializeContextFromSid` and
`AuthzAccessCheck` with `MAXIMUM_ALLOWED`. It reports a bounded NTFS result:

- A SID-derived context can omit logon-specific groups such as Interactive or
  Network.
- Share permissions are not intersected with the NTFS mask.
- Remote resource-manager policy is not queried.

The command therefore does not claim to reproduce every access check made by a
live logon token or SMB server.

## Paths and time-of-check/time-of-use

`Path` follows FileSystem-provider wildcard and reparse-point behavior.
`LiteralPath` suppresses wildcard expansion but does not pin the target object.
Extended `\\?\` and `\\?\UNC\` paths are passed to the host runtime.

A path or reparse target can change between resolution and persistence.
Privileged automation must use trusted paths and protect their parent
directories from untrusted mutation.

## See also

- [Public API](0003-public-api.md)
- [Verification and traceability](0005-verification-and-traceability.md)
- [Research sources](../docs/research.md)
