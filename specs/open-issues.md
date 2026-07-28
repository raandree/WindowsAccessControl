# Open issues

This register tracks agreed validation gaps and deferred extensions to the
accepted specifications. When an item ships, remove it here and record the
change in `CHANGELOG.md`. Rejected out-of-scope ideas remain in the research
note rather than this list.

## OI-8: Add certificate private-key access control

Specification: 0008. Tasks: KEY-1 to KEY-8.

Add CAPI and CNG software-key capability discovery, stable provider/container
identity, descriptor and rule workflows, descriptor-only backup/restore, and
supported DSC convergence. Never export or serialize private key material;
unsupported hardware or remote providers must fail explicitly.

## OI-11: Complete shared enterprise integration and release gates

Specification: 0008. Tasks: ENT-6 to ENT-8.

Extend shared dispatch, capability discovery, metrics, error taxonomy, target
locking, and the domain-lab runner as each family is implemented. The enterprise
foundation is accepted; ENT-6 and ENT-7 still block the first family release,
and ENT-8 blocks every enterprise release candidate.

## OI-12: Complete bounded NTFS descriptor editing

Specification: 0007. Requirements: FR-3 to FR-9.

Add the bounded `Edit-NTFSItemSecurityDescriptor` scope and descriptor-input
support for the remaining NTFS access, audit, owner, and inheritance mutators.
Prove one persistence operation, section preservation, `WhatIf`, and explicit
process-family rejection.

## OI-13: Add registry descriptor editing and optimistic concurrency

Specification: 0007. Requirements: FR-3 to FR-10.

Extend detached editing to registry-key descriptors and add an opt-in section
digest that rejects a stale target before persistence. Keep last-writer-wins as
the compatibility default.

## OI-14: Add SMB portability and desired state

Specifications: 0008, 0009. Tasks: SMB-4 and SMB-7.

Add schema-version-2 SMB backup/restore, server-qualified canonical locking,
and exact-descriptor/rule DSC resources for the accepted local-on-target share
boundary. Direct remote APIs remain excluded by ADR 0015.

## OI-15: Decide share-only effective access

Specifications: 0004, 0008. Task: SMB-5.

Determine whether a bounded local-on-target share-only result can model the
server access check defensibly. Remote and combined SMB-plus-NTFS claims remain
deferred by ADR 0017 regardless of this decision.

## OI-16: Add AD schema resolution and broader DACL mutation

Specifications: 0008, 0009. Tasks: AD-2, AD-4, and AD-5.

Resolve schema, property-set, extended-right, and object-class names while
preserving GUIDs. Add set, rights-removal, account-purge, and clear semantics
without flattening object ACEs.

## OI-17: Add AD portability, desired state, and access decision

Specifications: 0008, 0009. Tasks: AD-6 to AD-8 excluding replication.

Add schema-version-2 backup/restore and object-specific DSC resources, then
make an explicit evidence-based decision on bounded AD effective access. Keep
SACL and protected/forest-wide writes outside the accepted boundary.

## OI-18: Validate AD replication and failover

Specification: 0008. Tasks: AD-3 and AD-6.

Add rename, move, domain-controller switch, replication, and convergence
evidence when a second writable domain controller exists. The current
two-machine topology leaves this issue externally blocked; do not repurpose the
member server that hosts SMB, Task Scheduler, and software-key fixtures.

## OI-19: Add typed Task Scheduler access-rule commands

Specifications: 0008, 0010. Tasks: TASK-1 and TASK-4.

Build and verify an object-specific rights model for task folders and registered
tasks before exposing access-rule query or mutation commands. Preserve
inheritance and service-required ACEs without treating filesystem rights as
Task Scheduler rights. Define broader deny-group evaluation for the Task
Scheduler service token and verify ACL-revision normalization for object or
compound ACEs.

## OI-20: Add Task Scheduler portability and desired state

Specifications: 0008, 0010. Tasks: TASK-5 to TASK-7.

Add schema-version-2 backup/restore, target locking evidence, and exact
descriptor/rule DSC resources where convergence is safe. SACL and direct remote
APIs remain separately gated.

## See also

- [Specification index](README.md)
- [NTFSSecurity comparison](../docs/research.md#detailed-ntfssecurity-comparison)
