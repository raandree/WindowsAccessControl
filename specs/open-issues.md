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
This item must close before task SMB-6 or any combined SMB, NTFS, and domain
effective-access claim can ship.

## OI-5: Define in-memory descriptor mutation

Specifications: 0003, 0004. Requirements: FR-3 to FR-10.

Legacy NTFSSecurity commands can mutate descriptor objects without immediate
filesystem persistence. Adding that model here would create a second command
contract beside path-bound operations. Specify object ownership, section state,
`ShouldProcess`, and explicit persistence before implementation.

A Draft design contract exists in
[0007-in-memory-descriptor-mutation.md](0007-in-memory-descriptor-mutation.md).
This item remains open until the Draft is accepted, implemented, and verified.

## OI-6: Establish the enterprise domain-lab and security foundation

Specification: 0008. Tasks: ENT-1 to ENT-5.

Inventory the supplied machines, domain topology, Windows roles, certificate
providers, PowerShell editions, credentials boundary, and reset mechanism.
Create disposable targets and identities, complete the remote/credential threat
model, and decide backup-schema compatibility before production code begins.

This item blocks implementation of OI-7 through OI-10. It closes only when the lab setup and
teardown are repeatable, secrets remain outside repository evidence, and the
security and remote-target contracts are accepted.

## OI-7: Add scheduled-task and task-folder access control

Specification: 0008. Tasks: TASK-1 to TASK-7.

Add object-specific descriptor, access/audit rule, backup/restore, and supported
DSC workflows for registered tasks and task folders. Prove folder inheritance,
Task Scheduler COM cleanup, required service access, local/remote identity, and
disposable rollback in both PowerShell editions.

## OI-8: Add certificate private-key access control

Specification: 0008. Tasks: KEY-1 to KEY-8.

Add CAPI and CNG software-key capability discovery, stable provider/container
identity, descriptor and rule workflows, descriptor-only backup/restore, and
supported DSC convergence. Never export or serialize private key material;
unsupported hardware or remote providers must fail explicitly.

## OI-9: Add SMB-share and layered effective access

Specifications: 0008, 0004. Tasks: SMB-1 to SMB-7. Blocking item for SMB-6:
OI-4.

Add server-qualified SMB-share descriptor and rule workflows while keeping the
share DACL distinct from the backing NTFS DACL. First prove share-only effective
access in an explicit server context; add combined share-and-NTFS results only
after domain group expansion and remote authorization behavior are executable.

Specification 0009 admits the local-to-target DACL descriptor, add, query, and
exact-remove increment. Remote SMB APIs, backup/restore, DSC, and effective
access remain open here.

## OI-10: Add Active Directory object access control

Specification: 0008. Tasks: AD-1 to AD-9.

Add schema-aware descriptor and object-specific ACE workflows for objects in a
disposable organizational unit. Preserve GUID semantics and directory
inheritance, define DC and LDAP security behavior, test replication and object
renames, and prohibit writes to protected or forest-wide partitions until a
later contract explicitly admits them.

Specification 0009 admits explicit-DC signed/sealed DACL descriptor, add,
query, and exact-remove behavior. Schema-name resolution, broader mutation,
backup/restore, DSC, SACL, replication, and effective access remain open here.

## OI-11: Complete shared enterprise integration and release gates

Specification: 0008. Tasks: ENT-6 to ENT-8.

Extend shared dispatch, capability discovery, metrics, error taxonomy, target
locking, and the domain-lab runner as each family is implemented. This item does
not block family implementation after OI-6 closes, but ENT-6 and ENT-7 block
the first family release and ENT-8 blocks every enterprise release candidate.

## See also

- [Specification index](README.md)
- [NTFSSecurity comparison](../docs/research.md#detailed-ntfssecurity-comparison)
