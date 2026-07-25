# Open issues

This register tracks agreed validation gaps and deferred extensions to the
accepted specifications. When an item ships, remove it here and record the
change in `CHANGELOG.md`. Rejected out-of-scope ideas remain in the research
note rather than this list.

## OI-1: Execute privileged release acceptance

Specifications: 0004, 0005. Requirements: FR-6, FR-7, FR-8, FR-10, NFR-7.

The six real SACL and arbitrary-owner acceptance scenarios are implemented and
discovered, but the current token does not contain `SeSecurityPrivilege` or
`SeRestorePrivilege`. Before publishing a release, run
`tests/Integration/Elevated-NTFSPermission.Tests.ps1` from a suitably privileged
isolated process and retain the NUnit evidence.

## OI-2: Add live SACL descriptor-copy acceptance

Specifications: 0004, 0005. Requirements: FR-9, NFR-3, NFR-7.

Selected-section descriptor copy is live-tested for DACL state. Add a
privilege-gated scenario that copies only `Audit`, verifies the target SACL, and
proves owner, group, and DACL preservation.

## OI-3: Report inherited-rule provenance

Specifications: 0003, 0004. Requirement: FR-1.

Administrators may need the ancestor from which an inherited ACE originated.
Implement this only through the Windows inheritance-source API. Comparing
parent rules heuristically is insufficient because identical ACEs can exist at
multiple ancestors.

## OI-4: Evaluate remote effective-access context

Specifications: 0003, 0004. Requirement: FR-13.

The current Authz calculation is local and SID-derived. A remote mode could use
the target computer's group context, but it introduces RPC, trust, credential,
and authorization boundaries. Add it only with a separate security design and
explicit failure behavior; do not silently reinterpret the local result.

## OI-5: Define in-memory descriptor mutation

Specifications: 0003, 0004. Requirements: FR-3 to FR-10.

Legacy NTFSSecurity commands can mutate descriptor objects without immediate
filesystem persistence. Adding that model here would create a second command
contract beside path-bound operations. Specify object ownership, section state,
`ShouldProcess`, and explicit persistence before implementation.

## See also

- [Specification index](README.md)
- [NTFSSecurity comparison](../docs/research.md#detailed-ntfssecurity-comparison)
