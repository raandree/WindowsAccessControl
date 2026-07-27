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

Access-rule queries resolve inherited ACE provenance with
`GetInheritanceSourceW` against the same DACL returned to the caller. Explicit
ACEs have no source. An inherited ACE keeps its inherited state but reports a
null source when Windows cannot determine its ancestor. Native source rows are
filtered to the `CommonAce` allow/deny subset exposed by .NET access-rule
enumeration, so unrelated object or other non-standard ACEs remain in the
descriptor without breaking the query. Explicit-only queries do not enter the
native inheritance-source path. The native name allocations are released with
`FreeInheritedFromArray`, and a Windows failure terminates that target rather
than falling back to heuristic parent-rule comparison. Concurrent hierarchy
changes can make the native operation fail; no stale source is invented.

## Privilege boundary

The module recognizes the Windows privilege boundary and scopes required
authority to one operation (ADR 0008):

- `SeSecurityPrivilege` gates SACL reads and writes.
- `SeRestorePrivilege` can permit arbitrary valid owner assignment and restore
  writes.
- `SeTakeOwnershipPrivilege` can permit taking ownership.
- `SeBackupPrivilege` can permit backup-oriented reads.

Privilege inventory opens the token for query only. Explicit enable/disable
commands call `AdjustTokenPrivileges`, check `ERROR_NOT_ALL_ASSIGNED`, and
cannot add a privilege to the token. SACL and owner/group persistence acquires
only required privileges already present in the token, reference-counts nested
workers, and restores the original state in `finally`. Importing the module
never enables privileges.

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

## Bounded execution and target serialization

Target arrays are normalized and case-insensitively deduplicated by canonical
identity before worker dispatch (ADR 0013). Mutating commands acquire a
reference-counted `SemaphoreSlim` for that canonical identity. The lock
registry is scoped to the hosting application domain so concurrent isolated
module instances cannot race writes to one descriptor. Locks are released in
`finally` and removed when their reference count reaches zero.

Worker runspaces import isolated module instances rather than concurrently
entering one `PSModuleInfo` session state. Parent module state owns target-lock
references and metric publication. Target-local failures are nonterminating;
global normalization and validation failures remain terminating.

Metrics contain command name, object family, counts, elapsed duration, and an
update timestamp. They never contain SDDL, identity secrets, signing material,
or native buffers.

## Exact descriptor DSC boundary

Exact DSC resources persist only their selected descriptor sections and route
all errors as terminating failures from `Set()`. NTFS DACL/SACL protection is
persisted through the native section-scoped boundary. Registry view and process
creation identity are part of target identity; process exit or PID reuse fails
closed.

Windows can add DACL/SACL `AUTO_INHERITED` control flags after persistence.
DSC comparison excludes only those system-derived flags so convergence is
stable. It still compares protected/unprotected state and every selected ACE.
Null DACLs and omitted selected owner, group, DACL, or SACL data are rejected.
An explicitly absent selected SACL remains valid state; because it has no SACL
pointer, native protection persistence skips only that SACL while still writing
the selected Audit section and any selected DACL protection.

## Access-rule presence DSC boundary

Rule-presence resources own one exact explicit access ACE rather than an entire
DACL. Account input is normalized to SID before comparison. Matching requires
the normalized unsigned rights mask, allow/deny qualifier, and inheritance
scope where supported; inherited and partial-right rules never satisfy the
resource. `Absent` removes all duplicate exact matches through path-bound native
ACE output while preserving unrelated descriptor entries.

NTFS allow-rule comparison accounts for the `Synchronize` bit added by the
.NET `FileSystemAccessRule` constructor. Service, SCM, and process high-bit
generic rights retain their unsigned 32-bit identity across both editions.
Process operations remain pinned by PID plus creation `FILETIME`.

## Backup and restore trust model

Backups use schema version 1 and contain:

- object family, target, and canonical target identity
- object-specific metadata such as filesystem item type, registry view, or
  process PID and creation `FILETIME`
- selected native section bitmask
- SDDL for those sections
- SHA-256 integrity metadata

JSON is parsed as data and never evaluated. Restore validates schema, required
fields, section range, digest, unique canonical targets, target existence,
object-family metadata, canonical identity, and SDDL for every record before
the first write (ADR 0005). This prevents a malformed later record from causing
a partial restore. Process validation rechecks PID plus creation `FILETIME`.

SHA-256 detects modification only when the expected digest is itself protected.
When an RSA X.509 signing certificate is supplied, each record hash is signed.
Signed records require an explicit matching verification certificate, and all
signatures are verified before target preparation. The supplied certificate is
the trust anchor; the module checks thumbprint, validity period, and signature
but does not build an operating-system certificate trust chain.

Signatures bind individual records but not the envelope record set. Record
omission and replay of an older record signed by the same certificate are not
detected. Verification requires the certificate to be within its validity
period at restore time. Workflows that require set completeness, freshness, or
long-term archival must protect an external manifest and retain an appropriate
certificate lifecycle.

Signing occurs only after `ShouldProcess` approves the destination operation.
The completed JSON is written to the destination directory and atomically moved
or replaced, with temporary and rollback files removed in `finally`. Selected
absent SACLs are normalized to `S:NO_ACCESS_CONTROL`; a selected but omitted
SACL and every null DACL fail before persistence.

A validated restore can still stop after an earlier successful write if a
target exits, disappears, or fails during persistence. The same backup can be
rerun after the runtime condition is corrected; process records remain valid
only while the pinned instance exists.

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
