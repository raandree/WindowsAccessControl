# Domain lab inventory

Status: Partial

Last verified: 2026-07-28

This document records the secret-free evidence for task `ENT-1`. Actual machine
names, domain names, credentials, recovery material, and symbolic-role mappings
remain outside the repository.

## Safety status

| Gate | State | Evidence or required action |
| --- | --- | --- |
| Non-production forest isolation | Unverified | Confirm that the forest has no production trust or routable production path. |
| Trust isolation | Verified | The selected forest contains one domain and reports no trusts. |
| Machine reset | Unverified | Record a snapshot, rebuild, or equivalent reset mechanism for each mutable machine. |
| Recovery identity | Unverified | Reserve an identity that tests never modify and prove it can perform teardown. |
| Secret handling | Verified for discovery | No credentials, domain names, host names, addresses, key material, or recovery data were retained. |

Remote mutation tests remain disabled until the isolation, reset, and recovery
gates are verified.

## Topology

| Symbolic role | Count | Verified properties |
| --- | ---: | --- |
| Forest | 1 | Windows Server 2016 forest functional level |
| Domain | 1 | Windows Server 2016 domain functional level |
| Writable domain controller | 1 | Global catalog; Windows Server 2022 Datacenter |
| Read-only domain controller | 0 | None discovered |
| Member server | 1 | Domain joined; Windows Server 2022 Datacenter |
| Management host | 1 | Domain joined; Windows Server 2022 Datacenter |

One writable domain controller supports inventory and read-only API probes. It
does not satisfy replication, domain-controller switch, or failover evidence.

## Role capabilities

| Symbolic role | Windows PowerShell | PowerShell 7 | Active Directory module | LDAP protocol API | Relevant services |
| --- | --- | --- | --- | --- | --- |
| Management host | Installed | 7.6.3 | Available | Available | Not evaluated |
| Domain controller | 5.1.20348.4294 | Installed | Available | Available | Directory service running |
| Member server | 5.1.20348.4294 | Not installed | Not installed | Available | Task Scheduler, SMB server, and WinRM running |

The member server can host Windows PowerShell 5.1 Task Scheduler, certificate
provider, SMB, and local-object probes. PowerShell 7 must be installed there or
provided on another equivalent member server before cross-edition live
acceptance can pass.

## Remote transport evidence

- The management host resolved and reached the member server through WinRM
  with explicit Kerberos authentication.
- The management host reached the writable domain controller through WinRM
  with explicit Kerberos authentication.
- Both remote sessions were authenticated and used full language mode.
- The member server exposes one HTTP listener and no HTTPS listener.
- The member server currently enables Kerberos and Negotiate authentication,
  but it also enables Basic and CredSSP authentication and permits unencrypted
  service traffic.

The successful Kerberos probes establish connectivity only. The member-server
WinRM baseline does not satisfy the planned downgrade policy. Enterprise tests
must never select Basic or CredSSP, and task `ENT-4` must define and test the
approved encrypted transport before a remote public API is implemented.

## Active Directory read probe

A read-only `AD-1` capability probe passed in PowerShell 7.6.3 and Windows
PowerShell 5.1. Each edition independently:

- selected one writable domain controller explicitly before connecting
- bound with Negotiate authentication, LDAP signing, and LDAP sealing enabled
- read the RootDSE default, schema, and configuration naming contexts
- requested the domain object's owner, group, and DACL through the LDAP
  security-descriptor control
- parsed the returned binary descriptor as a `RawSecurityDescriptor`

No directory object or descriptor was modified. Referral, timeout, consistency,
downgrade-rejection, schema-resolution, and disposable-OU behavior remain open
parts of `AD-1`.

## Work now unblocked

- Complete the remaining secret-free `ENT-1` safety and reset inventory.
- Design idempotent `ENT-2` setup and teardown without applying it yet.
- Turn the successful cross-edition `AD-1` baseline into a repeatable,
  repository-controlled probe and extend it with the remaining connection
  semantics.
- Run read-only `TASK-1`, `KEY-1`, and `SMB-1` capability probes on the member
  server.
- Develop the `ENT-3` threat model and the `ENT-4` and `ENT-5` decisions.

## Additional environment

The present three-role topology is sufficient for the entry-gate design and
read-only probes. The following additions are required by later gates:

- Confirm or provide reset capability and an untouched recovery identity before
  any disposable directory or member-server mutation.
- Install PowerShell 7 on the member server, or provide an equivalent member
  server with both supported PowerShell editions.
- Add a second writable domain controller before `AD-6` replication,
  domain-controller switch, or failover tests.
- Add a certification authority or another domain or forest only when a later
  accepted work package requires it.

## See also

- [Enterprise access-control expansion](../specs/0008-enterprise-access-control-expansion.md)
- [Enterprise domain-lab decision](../specs/decisions/0014-stage-enterprise-expansion-behind-domain-lab.md)
- [Enterprise open-work register](../specs/open-issues.md)
