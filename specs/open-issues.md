# Open issues

This register tracks agreed validation gaps and deferred extensions to the
accepted specifications. When an item ships, remove it here and record the
change in `CHANGELOG.md`. Rejected out-of-scope ideas remain in the research
note rather than this list.

## OI-18: Validate AD replication and failover

Specification: 0008. Tasks: AD-3 and AD-6.

Add rename, move, domain-controller switch, replication, and convergence
evidence when a second writable domain controller exists. The current
two-machine topology leaves this issue externally blocked; do not repurpose the
member server that hosts SMB, Task Scheduler, and software-key fixtures.

## OI-20: Add Task Scheduler portability and desired state

Specifications: 0008, 0010. Tasks: TASK-5 to TASK-7.

Add schema-version-2 backup/restore, target locking evidence, and exact
descriptor/rule DSC resources where convergence is safe. SACL and direct remote
APIs remain separately gated. Specification 0013 is the reference contract for
the equivalent SMB share and Active Directory work.

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
