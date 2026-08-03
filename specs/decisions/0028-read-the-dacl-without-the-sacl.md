# Read the DACL without the SACL and graft the audited SACL

- Status: Accepted
- Date: 2026-08-03
- Deciders: user, software-engineer agent

## Context and problem statement

`GetNamedSecurityInfo` does not return the same DACL for the same object
depending on which sections the caller requests. Requesting
`SACL_SECURITY_INFORMATION` clears `INHERITED_ACE` on every DACL ACE.

Measured on one file, at one moment, with `SeSecurityPrivilege` held:

| Requested `SECURITY_INFORMATION` | DACL ACE flag bytes |
| --- | --- |
| `0x4` (DACL) | `0x10 0x10 0x10` |
| `0x7` (owner, group, DACL) | `0x10 0x10 0x10` |
| `0xF` (owner, group, DACL, SACL) | `0x00 0x00 0x00` |

The difference is in the returned descriptor bytes, not in a serializer:
converting the `0xF` descriptor with DACL-only information reproduces the
cleared flags. Both PowerShell editions observe it, because both reach the same
Win32 entry point.

It only appears while the object's DACL has no `SE_DACL_AUTO_INHERITED` bit,
which is the state of a file that has never had a descriptor written to it. Any
write through `SetNamedSecurityInfo` sets that bit, after which the combined
read reports the inherited ACEs correctly. A test that prepares its fixture
with an ACL write therefore cannot observe the defect at all.

The module read owner, group, DACL, and SACL in one `Get-Acl -Audit` call, so
`Get-NTFSItemSecurityDescriptor -Sections All` reported inherited ACEs as
explicit. Replaying that SDDL wrote the inherited ACEs as explicit ACEs, and
Windows then re-applied inheritance and added the parent's ACEs back. The
exact-descriptor DSC resource therefore never converged, and copy, backup, and
restore silently detached targets from their parent ACL.

## Decision

Never take a DACL from a read that also requests the SACL.

`Get-NTFSSecurityDescriptorForItem` reads owner, group, and the DACL from a
request that omits the SACL. When the caller selects both `Access` and `Audit`,
it grafts the audited SACL onto that descriptor through
`SetSecurityDescriptorBinaryForm` with the `Audit` section only.

An `Audit`-only read keeps its single privileged call, because no DACL is
selected.

## Consequences

- Inherited ACEs stay inherited in every reported and captured SDDL, so the
  exact-descriptor round trip converges and inherited ACEs are no longer
  rewritten as explicit.
- A combined read costs two `Get-Acl` calls and observes the DACL and the SACL
  at slightly different moments.
- Grafting marks the audit section modified, so a later persist writes the SACL
  that the caller already selected. This is narrower than it looks: only
  callers that select `Access` and `Audit` together are affected, and those
  paths already write every selected section. ADR 0003 stays intact for
  `Access`-only and `Audit`-only work.

## Alternatives considered

- Ignore `Inherited` when comparing descriptors: rejected. It would hide the
  mismatch while still replaying inherited ACEs as explicit ACEs.
- Rebuild one descriptor object from a merged binary form: rejected. That marks
  every selected section modified and breaks the section-scoped persistence
  guarantee in ADR 0003.
- Declare `-Sections All` non-portable: rejected. Specifications 0013 and 0017
  depend on a whole-descriptor capture.
- Tolerate the failing test as environmental: rejected. The behavior is
  reproducible in both editions and directly in Win32, and it corrupts
  inheritance rather than only failing a test.

## See also

- [Persist only selected descriptor sections](0003-persist-only-selected-descriptor-sections.md)
- [Security and persistence](../0004-security-and-persistence.md)
- [Verification and traceability](../0005-verification-and-traceability.md)
