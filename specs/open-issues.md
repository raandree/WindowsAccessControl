# Open issues

This register tracks agreed validation gaps and deferred extensions to the
accepted specifications. When an item ships, remove it here and record the
change in `CHANGELOG.md`. Rejected out-of-scope ideas remain in the research
note rather than this list.

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
