# Open issues

This register tracks agreed validation gaps and deferred extensions to the
accepted specifications. When an item ships, remove it here and record the
change in `CHANGELOG.md`. Rejected out-of-scope ideas remain in the research
note rather than this list.

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

## OI-21: Extend descriptor-aware NTFS mutators

Specification: 0007. Requirements: FR-3 to FR-9.

Add descriptor-input parameter sets for NTFS access set/remove/clear, audit,
owner, and inheritance mutators. Preserve explicit mutation semantics and
loaded-section enforcement. Live-process descriptors remain excluded because
their read and write must stay on one pinned handle.

## OI-22: Add fail-closed CNG private-key mutation

Specifications: 0008, 0012. Tasks: KEY-1, KEY-3, KEY-4, KEY-7, and KEY-8.

Add provider implementation/hardware rejection, HTTP.sys/WinRM/RDP/LDAPS
critical-binding detection, SYSTEM/Administrators/original-service-ACE
preservation, typed add/exact-remove semantics, exact rollback, negative live
fixtures, and independent cryptographic review before any CNG DACL write ships.

## OI-23: Add CAPI private-key capability and mutation

Specification: 0008. Tasks: KEY-1 to KEY-4 and KEY-7.

Probe and implement the separate CAPI software-provider identity, handle,
descriptor, and rejection boundary in both PowerShell editions. Do not infer
CAPI key-file paths or reuse CNG assumptions.

## OI-24: Add private-key portability and desired state

Specification: 0008. Tasks: KEY-5 and KEY-6.

After safe typed mutation exists, add schema-version-2 descriptor-only
backup/restore and DSC only for stable supported software-key identities.
Never store certificate or private-key material in portability records.

## See also

- [Specification index](README.md)
- [NTFSSecurity comparison](../docs/research.md#detailed-ntfssecurity-comparison)
