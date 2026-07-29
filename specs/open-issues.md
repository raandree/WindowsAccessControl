# Open issues

This register tracks agreed validation gaps and deferred extensions to the
accepted specifications. When an item ships, remove it here and record the
change in `CHANGELOG.md`. Rejected out-of-scope ideas remain in the research
note rather than this list.

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

## OI-20: Add Task Scheduler portability and desired state

Specifications: 0008, 0010. Tasks: TASK-5 to TASK-7.

Add schema-version-2 backup/restore, target locking evidence, and exact
descriptor/rule DSC resources where convergence is safe. SACL and direct remote
APIs remain separately gated.

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

## OI-25: Detect registry inheritance scope in duplicate suppression

Specification: 0003.

`Add-RegistryKeyAccessRule` and `Add-RegistryKeyAuditRule` suppress an ACE as a
duplicate when the account, qualifier, and rights match, ignoring `AppliesTo`.
Adding an existing account and rights combination with a different inheritance
scope therefore succeeds without writing anything and returns nothing through
`PassThru`. The Task Scheduler family opts into the flag-sensitive comparison
through `Invoke-WindowsAclRuleMutation -MatchAceFlags`; extend it to the
registry family with regression coverage and confirm that no existing `Set` or
`Clear` behavior changes.

## OI-26: Stop the batch dispatcher downgrading downstream terminating errors

Specification: 0003.

`Invoke-WindowsAccessControlBatch` catches an exception raised while writing a
target result and re-emits it through `$PSCmdlet.WriteError`. When a command is
piped into a mutator, a terminating error thrown by the downstream command
surfaces in that frame and is downgraded to a non-terminating error, so
`Get-NTFSItemSecurityDescriptor -Sections Owner | Add-NTFSAccessRule
-ErrorAction Stop` reports the fail-closed section rejection without throwing.
The same statement throws when the descriptor is bound from a variable. Two
integration tests assert the throwing form and are therefore sensitive to the
caller's effective `$ErrorActionPreference`. Distinguish a worker failure from
a downstream pipeline failure and rethrow the latter.

## See also

- [Specification index](README.md)
- [NTFSSecurity comparison](../docs/research.md#detailed-ntfssecurity-comparison)
