# Domain lab inventory

Status: Verified (`ENT-1` and `ENT-2` complete; `ENT-3` to `ENT-5` decisions accepted)

Last verified: 2026-07-28

This document records the secret-free evidence for task `ENT-1`. Actual machine
names, domain names, credentials, recovery material, and symbolic-role mappings
remain outside the repository.

## Safety status

| Gate | State | Evidence or required action |
| --- | --- | --- |
| Non-production use | Verified | The operator confirmed that the two-machine environment is unused and disposable. |
| Trust isolation | Verified | The selected forest contains one domain and reports no trusts. |
| Production network route isolation | Verified | The operator attested that the disposable lab has no production-directory trust or routable production path. This is operator attestation, not an independent network map. |
| Machine reset | Verified | The operator captured snapshots of both machines before fixture mutation. |
| Recovery identity | Verified | The untouched RID-500 identity is enabled, has domain recovery authority, and performed successful teardown. |
| Secret handling | Verified | Fixture users remain disabled; no credentials, passwords, private-key material, or recovery data were retained. |

Disposable fixture mutation and accepted local-on-target enterprise increments
are enabled for this lab. Direct remote public APIs remain outside the accepted
contracts.

## Topology

| Symbolic role | Count | Verified properties |
| --- | ---: | --- |
| Forest | 1 | Windows Server 2016 forest functional level |
| Domain | 1 | Windows Server 2016 domain functional level |
| Writable domain controller | 1 | Global catalog; Windows Server 2022 Datacenter |
| Read-only domain controller | 0 | None discovered |
| Member server | 1 | Domain joined; Windows Server 2022 Datacenter |
| Management host | 1 | Co-located on the writable domain controller |

The management and domain-controller roles share one machine, so the topology
contains two unique machines. One writable domain controller supports inventory,
fixture lifecycle, and read-only API probes. It does not satisfy replication,
domain-controller switch, or failover evidence.

## Role capabilities

| Symbolic role | Windows PowerShell | PowerShell 7 | Active Directory module | LDAP protocol API | Relevant services |
| --- | --- | --- | --- | --- | --- |
| Management host | Installed | 7.6.3 | Available | Available | Not evaluated |
| Domain controller | 5.1.20348.4294 | Installed | Available | Available | Directory service running |
| Member server | 5.1.20348.4294 | 7.6.3 | Not installed | Available | Task Scheduler, SMB server, and WinRM running |

The member server hosts Windows PowerShell 5.1 and a Microsoft-signed
PowerShell 7.6.3 payload copied from the management host over Kerberos after the
isolated member could not resolve the official download host. The remote
`pwsh.exe` signature and version were independently verified before use.

## Disposable fixture lifecycle

The test-only harness in
[WindowsAccessControl.DomainLab.psm1](../tests/Lab/WindowsAccessControl.DomainLab.psm1)
owns resources through exact identities and markers. It provides plan, setup,
status, and teardown commands with `ShouldProcess` on both mutation boundaries.
The marker is an accidental-collision and cleanup-ownership guard inside this
trusted disposable lab; it is not an authorization control against a malicious
directory or machine administrator.

The ready fixture contains:

- one marked root OU with `Identities`, `Groups`, and `Targets` child OUs
- four disabled fixture users and two security groups
- direct and nested group membership for later authorization probes
- the untouched RID-500 recovery identity outside the fixture OU
- one marked member-server directory and SMB share
- one Task Scheduler folder
- one non-exportable software-backed RSA CNG key selected through a self-signed
  certificate with a deterministic provider and container identity

Live evidence proved:

- first setup created 12 domain changes and five member-server resources
- a second setup created zero resources and retained complete readiness
- a forced member-boundary setup failure triggered clean compensating teardown
- first teardown removed every owned resource and second teardown reported every
  resource already absent
- certificate teardown explicitly deleted the persisted CNG private key
- setup detected and repaired a marked certificate whose CNG key was missing
- setup deleted a remaining deterministic key before recreating its missing
  certificate selector
- three orphan keys created while reproducing the pre-fix failure were removed,
  while the final deterministic fixture key remained available
- the final setup left all ten marked directory objects and all member-server
  fixtures ready
- Task Scheduler DACL acceptance passed against the marked folder and a
  disposable disabled task in Windows PowerShell 5.1 and PowerShell 7.6.3,
  with exact semantic rollback, task-definition preservation, zero leaked
  tasks, and the complete fixture remaining ready

Five focused unit tests and four explicit live tests retain this behavior. The
live suite is outside the default CI paths and requires the member-server role
through `WAC_DOMAIN_LAB_MEMBER`; its `AfterAll` restores the ready fixture set.

## Unattended acceptance profile

`Invoke-WindowsAccessControlDomainLabAcceptance` in the test harness runs the
fixture lifecycle, Task Scheduler, SMB-share, and Active Directory suites in a
fixed order. It requires explicit repository, domain-DN, member-server, and
evidence-path inputs; the member-server environment variable exists only for
the duration of the call and is restored afterward. The suites create their
own ephemeral test credentials, so no secret-bearing environment variable is
required.

Each suite emits start/end heartbeat records and is followed by an independent
domain/member readiness check. The runner stops before the next suite when a
test fails, no test passes, any test is skipped, or the lab is not ready. It
writes one atomic UTF-8 JSON summary with suite counts, exact sanitized skip
reasons, heartbeat timestamps, and a cleanup ledger. The summary sanitizes
known infrastructure value classes, rejects retained plan identifiers, and
records credential handling only as `SuiteEphemeralRuntime`. Sanitization
applies to the persisted evidence; thrown errors remain operator-facing and
must not be copied into a shared log that requires redaction.

The first complete profile executed 17 tests across four suites with zero
failures or skips. All four cleanup checks were ready, retained evidence
contained no infrastructure identifiers, and a fresh harness import confirmed
the complete lab ready afterward. The runner contract passes 13 tests in both
PowerShell 7 and Windows PowerShell 5.1.

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
WinRM baseline does not admit a direct remote public API. Enterprise tests must
select explicit Kerberos and never Basic or CredSSP. ADR 0018 keeps Task
Scheduler and software-key object adapters local-on-target; remoting is separate
operator-controlled orchestration.

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

## Accepted foundation

- `ENT-1`: the secret-free inventory, topology, reset capability, trust state,
  and operator isolation attestation are recorded.
- `ENT-2`: marked setup, status, teardown, repair, compensation, recovery, and
  key-deletion behavior are repeatable.
- `ENT-3`: specification 0009 and ADR 0018 record per-family data, authority,
  outbound-channel, credential, and destructive containment boundaries.
- `ENT-4`: ADRs 0015 and 0018 require explicit final-target authority and keep
  first SMB, Task Scheduler, and software-key adapters local-on-target; AD uses
  direct Kerberos LDAP.
- `ENT-5`: ADR 0016 requires schema version 2 before enterprise targets enter
  unified backup and restore.
- `ENT-6`: current SMB, AD, and Task Scheduler adapters use the shared bounded
  dispatcher, canonical deduplication, metrics, and same-target locks with
  family contract tests.
- `ENT-7`: the unattended acceptance profile retains redacted heartbeats,
  exact skip reasons, suite counts, and cleanup ledgers without external test
  secrets.

## Additional environment

The present two-machine, three-role topology is sufficient for the entry-gate
design, disposable fixtures, and read-only probes. The following additions or
changes are required by later gates:

- Add a second writable domain controller before `AD-6` replication,
  domain-controller switch, or failover tests.
- Add a certification authority or another domain or forest only when a later
  accepted work package requires it.

## See also

- [Enterprise access-control expansion](../specs/0008-enterprise-access-control-expansion.md)
- [Enterprise domain-lab decision](../specs/decisions/0014-stage-enterprise-expansion-behind-domain-lab.md)
- [Task and software-key authority decision](../specs/decisions/0018-use-local-task-and-software-key-authority.md)
- [Enterprise open-work register](../specs/open-issues.md)
