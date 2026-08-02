# Enterprise access-control expansion

Status: Accepted. This specification is the durable roadmap contract for the
expansion into scheduled tasks and task folders, certificate private keys, SMB
shares, and Active Directory objects. It defines the entry gates, work
packages, and boundaries every family must satisfy. The per-family
specifications define the behavior that shipped, and specification 0005 maps
every roadmap task to its evidence.

Acceptance approves the contract, not a claim of complete implementation. A
work package closes either through executable evidence or through an accepted
decision record that defers it.

Specifications 0009 through 0017 accept the behavior delivered against this
roadmap: SMB-share and Active Directory DACL management, local Task Scheduler
DACL management, bounded share-only effective access, private-key inspection
and fail-closed mutation, schema-version-2 portability and desired state for
every enterprise family, and multi-controller directory behavior. `SMB-6` is
deferred by ADR 0017, `AD-7` by ADR 0022, and the Certificate Application
Programming Interface half of the private-key package by ADR 0024.

## Purpose

Extend `WindowsAccessControl` from local operating-system objects into the
persistent authorization surfaces used to deploy Windows workloads and
delegate enterprise resources. The expansion should let administrators use the
same pipeline, identity, mutation, backup, effective-access, safety, and DSC
concepts without pretending that the four domains share one rights model or
one trust boundary.

This specification extends the roadmap established by specification 0006. It
does not change the implemented behavior of the filesystem, registry-key,
service/SCM, or pinned-process families. Active Directory moves from excluded
for that release to planned for a future release; the current release remains
local-only.

## Planned object families

| Family | Initial targets | Persistence | Distinct boundary |
| --- | --- | ---: | --- |
| Task Scheduler | Registered tasks and task folders | Yes | Task Scheduler COM API, folder hierarchy, task-service safety |
| Certificate private key | CAPI and CNG software-backed user or machine keys selected through certificates or provider identity | Yes | Provider/container addressing, key-store scope, non-exportability |
| SMB share | Named shares on an explicit server | Yes | Share DACL versus backing NTFS DACL, server identity, network authorization |
| Active Directory | Objects in an explicitly selected domain partition and disposable organizational unit | Yes | LDAP security, schema GUIDs, object-specific ACEs, replication |

Each family receives object-specific commands, rights types, target
normalization, output types, and DSC resources where desired-state convergence
is defensible. Shared private infrastructure may be reused only after the
adapter proves that it preserves native descriptor fidelity.

## Product outcomes

The expansion supports two coherent administrative workflows.

### Windows workload identity security

Administrators can grant a workload identity the task, private-key, file,
registry, and service permissions it requires without exporting key material
or replacing unrelated ACEs.

### Enterprise resource authorization

Administrators can inspect and manage a share ACL separately from its backing
NTFS ACL, delegate access to Active Directory objects through typed
object-specific rules, and obtain bounded effective-access results whose local,
domain, and remote assumptions are explicit.

## Compatibility and design principles

- Existing public commands, output types, backup records, and DSC resources
  remain compatible unless a separately approved migration says otherwise.
- PowerShell 7 and Windows PowerShell 5.1 on supported Windows versions remain
  required execution environments.
- Runtime code uses in-box managed APIs and narrowly scoped Windows interop; an
  optional Windows role or feature is a declared prerequisite, not a bundled
  dependency.
- Public surfaces remain object-specific. Shared internals do not erase typed
  rights, inheritance, addressing, or failure semantics.
- Remote authority is explicit. No command infers a server, domain controller,
  credential, or authentication mechanism from ambient state when that choice
  can change the target.
- Every remote control channel provides mutual authentication, integrity, and
  confidentiality. LDAP requires signing and sealing; simple bind and channel
  downgrade are rejected. SMB requires signing and encryption. PowerShell
  remoting, when selected, requires an encrypted transport and rejects Basic
  authentication and plaintext HTTP. Kerberos is preferred; NTLM fallback is
  prohibited by default and requires a separately accepted exception contract.
- Remote calls authenticate directly to the final target. CredSSP and
  unconstrained delegation are prohibited. A justified multi-hop path requires
  a separately threat-modeled constrained-delegation or explicit per-hop
  credential contract before implementation.
- Mutators prevalidate target identity, rights, and all account inputs before
  the first write, honor `ShouldProcess`, and preserve unrelated descriptor
  sections and ACEs.
- The least-privilege contract applies to the token evaluated on the target.
  Remote SACL operations state how `SeSecurityPrivilege` is obtained by a
  delegated identity, never claim a missing privilege, and remain unsupported
  when the family cannot provide that behavior without broad administration.
- Backup and restore remain data-only, integrity-protected, section-scoped,
  and fully validated before the first write.
- Domain-lab tests mutate only disposable resources and prove cleanup or
  rollback after success and failure.

## Task Scheduler work package

The Task Scheduler adapter covers registered tasks and task folders as
different target kinds. Canonical identity includes the explicit computer,
task-folder path, and task name where applicable. Folder inheritance and task
creation side effects must be observed from the Task Scheduler API rather than
inferred from files under the operating-system task directory.

The adapter must preserve the Task Scheduler service's required access. Tests
must never make the service unable to read a task or folder. Built-in
operating-system tasks and folders under `\Microsoft\` are excluded from the
first increment and rejected by public target validation. A disposable task
folder is the only writable mutation and rollback boundary.

| ID | Task | Exit evidence |
| --- | --- | --- |
| TASK-1 | Probe task and folder descriptor query/set behavior in both PowerShell editions | Captured binary/SDDL round trip and section behavior |
| TASK-2 | Define canonical local and remote target identity, secure channel, rights, inheritance, system-tree rejection, and service-required ACE policy | Accepted domain contract plus downgrade and adversarial cases |
| TASK-3 | Implement task/folder normalization and the COM lifetime boundary | Unit tests prove release on success and failure |
| TASK-4 | Implement descriptor plus access/audit rule query and explicit mutation semantics | Focused unit and disposable live tests |
| TASK-5 | Extend unified backup/restore under the ENT-5 schema decision and add same-target serialization | Round-trip, tamper, duplicate, and concurrent-write tests |
| TASK-6 | Add exact-descriptor and exact-rule DSC resources where convergence is safe | MOF compilation and live convergence |
| TASK-7 | Add local and domain-lab acceptance, help, formatting, and migration notes | Cross-edition green gate and cleanup proof |

## Certificate private-key work package

A certificate is a selector for a private-key object, not the object whose
permissions are changed. Canonical identity must bind store location, provider
kind, provider name, key container or unique name, and machine/user scope
without exporting key material. CAPI and CNG receive separate adapters behind
one capability model when their behavior can be represented honestly.

The initial scope covers software-backed keys whose provider exposes a mutable
security descriptor. Hardware, smart-card, TPM, and remote providers are
reported as unsupported capabilities until live probes prove safe behavior.
Disposable self-signed software keys provide the baseline lab fixture and do
not require a certification authority. Enrollment and CA-specific behavior are
a later capability unless the provider matrix explicitly admits them.

Before mutation, the adapter detects known bindings to critical live services
such as domain-controller LDAPS, Remote Desktop Services, HTTP.sys, or IIS. The
first increment rejects such keys; a later contract may permit them only with
high-impact confirmation and tested service-specific recovery.

| ID | Task | Exit evidence |
| --- | --- | --- |
| KEY-1 | Build a CAPI/CNG/provider capability matrix for both PowerShell editions | Repeatable probes with provider, store, and key metadata |
| KEY-2 | Define certificate and provider selectors plus stable canonical key identity | Collision, renewal, missing-key, and ambiguous-selector tests |
| KEY-3 | Implement key-handle lifetime and descriptor query/set adapters without private-key export | Resource cleanup and secret-scanning evidence |
| KEY-4 | Implement typed access/audit rule query and explicit mutation semantics for supported providers | Unit and disposable-key live tests |
| KEY-5 | Extend backup/restore under the ENT-5 schema decision without storing certificate or private-key material | Descriptor-only schema and signed round-trip tests |
| KEY-6 | Add DSC resources only for stable software-key identities | Convergence, renewal, disappearance, and provider-rejection tests |
| KEY-7 | Detect critical service bindings and document unsupported providers and recovery procedures for a denied key | Binding rejection, cross-edition acceptance, and cleanup proof |
| KEY-8 | Complete an independent cryptographic-boundary review | No unresolved Blocker or Major findings |

## SMB share work package

An SMB share descriptor and the backing filesystem descriptor are independent
authorization layers. Commands must never present a share-only calculation as
the effective access to a file. Canonical share identity includes the explicit
server identity and share name; backing paths remain separate NTFS targets.

Administrative and special shares, including `ADMIN$`, drive shares, `IPC$`,
and `print$`, plus clustered shares, continuously available shares, DFS
namespaces, and cloud-backed shares are excluded from the first increment
unless a later probe adds an explicit target contract.

| ID | Task | Exit evidence |
| --- | --- | --- |
| SMB-1 | Probe local and remote share descriptor APIs, section support, rights mapping, and server-name normalization | Cross-edition capability matrix |
| SMB-2 | Threat-model authentication, Kerberos delegation, channel downgrade, server spoofing, credential handling, and rollback | Failed downgrade tests and independent security review with no Blocker or Major findings |
| SMB-3 | Implement canonical target resolution and typed share descriptor/rule commands | Unit and disposable-share live tests |
| SMB-4 | Extend unified backup/restore under the ENT-5 schema decision and target locking with server-qualified identity | Remote round-trip, duplicate, tamper, and partial-failure tests |
| SMB-5 | Implement a bounded share-effective-access result that states its token and server context | Requested-rights tests without NTFS claims |
| SMB-6 | Deferred by ADR 0017; reconsider only under a separately accepted server-side token and remote authorization contract | No combined-access claim in the current roadmap |
| SMB-7 | Add exact-descriptor/rule DSC resources, help, formatting, and cleanup automation | Cross-edition domain-lab convergence |

`SMB-1` through `SMB-5` and `SMB-7` are delivered. Specification 0009 owns the
command contract, specification 0011 owns the bounded share-only effective
access, and specification 0013 owns the server-qualified canonical identity,
schema-version-2 portability, and the two share DSC resources. `SMB-6` remains
deferred by ADR 0017.

## Active Directory work package

Active Directory is not treated as a generic file-like ACL. The adapter must
preserve and expose object-specific ACE GUIDs, inherited-object GUIDs, extended
rights, validated writes, property sets, child-object rights, and directory
inheritance. Schema and extended-rights names are resolved against the selected
forest and retained with their GUIDs.

Initial writes are limited to objects inside a disposable organizational unit
in the domain partition. Domain-root, `AdminSDHolder`, configuration-partition,
schema-partition, system-container, Group Policy object, Domain Controllers OU,
and dynamically protected principal mutation are excluded until separately
specified and protected by dedicated recovery tests.

| ID | Task | Exit evidence |
| --- | --- | --- |
| AD-1 | Probe directory API availability in both PowerShell editions and define server/DC selection, LDAP signing/sealing, authentication, referral, timeout, and consistency behavior | Cross-edition capability matrix, accepted remote-security contract, and failed downgrade tests |
| AD-2 | Implement schema, property-set, extended-right, and object-class GUID resolution with caching | Known-schema and unknown-GUID tests |
| AD-3 | Define canonical identity using forest/domain authority plus immutable object identity while preserving the current distinguished name | Rename, move, deletion, and DC-switch tests |
| AD-4 | Implement descriptor and typed object-specific access/audit rule queries | Disposable-OU read tests with inheritance provenance |
| AD-5 | Implement add, set, exact removal, rights removal, account purge, and clear semantics without flattening object ACEs | Native descriptor comparison and unrelated-ACE preservation |
| AD-6 | Implement inheritance, owner/group, backup/restore under the ENT-5 schema decision, and concurrency behavior | Multi-DC round-trip and replication-aware tests |
| AD-7 | Define bounded effective access or explicitly defer it when Authz cannot model directory semantics defensibly | Documented capability decision and evidence |
| AD-8 | Add object-specific DSC resources, help, formatting, and cleanup automation | Cross-edition live convergence inside the test OU |
| AD-9 | Complete an independent security review focused on delegation, privilege escalation, and directory lockout | No unresolved Blocker or Major findings |

`AD-1`, `AD-2`, `AD-5`, and `AD-9` are delivered. `AD-4` is delivered for DACL
descriptors and access rules, including inheritance provenance and resolved
schema, property-set, validated-write, and extended-right names; audit-rule
queries remain outside the accepted SACL boundary. `AD-5` covers add, set, exact
removal, rights removal, account purge, and clear. ADR 0021 amended the `AD-1`
server-selection contract to
allow a discovered and pinned domain controller. `AD-6` is delivered for
schema-version-2 backup and restore, for the existing write-boundary
concurrency check, and for replication convergence; directory inheritance and
owner/group mutation stay outside the accepted boundary. `AD-7` is
closed as an explicit evidence-based deferral in ADR 0022. `AD-8` is delivered
by the two directory DSC resources in specification 0013. Specification 0016
records the multi-controller identity, replication, and pinned-controller
outage behavior and closed the replication work.

## Cross-cutting foundation tasks

| ID | Task | Exit evidence |
| --- | --- | --- |
| ENT-1 | Inventory the supplied domain lab and record operating systems, roles, PowerShell editions, domains, trusts, certificate providers, and reset mechanism | Versioned lab inventory with no secrets |
| ENT-2 | Create disposable identities, groups, task folders, shares, keys, and an organizational unit plus a break-glass recovery account | Idempotent setup and teardown proof |
| ENT-3 | Threat-model private data, credentials, remote content, outbound channels, Kerberos delegation, remote-token privileges, and destructive recovery for every family | Reviewed threat model plus a per-family, per-section matrix proving ordinary operations use a delegated non-Domain-Admin identity |
| ENT-4 | Decide explicit remote target, secure-channel, direct authentication, and credential semantics without weakening the existing local command contracts | Accepted ADR plus compatibility, downgrade-rejection, and no-CredSSP tests |
| ENT-5 | Decide whether new target metadata is backward-compatible with backup schema version 1 or requires schema version 2, including the replay and record-omission limits from specification 0004 | Migration, downgrade, freshness, completeness, and rollback contract |
| ENT-6 | Extend descriptor capability discovery, object-family dispatch, metrics, error taxonomy, and canonical target locks | Shared contract tests across old and new families |
| ENT-7 | Add a domain-lab test profile with heartbeat, cleanup ledger, retained evidence, exact skip reasons, and runtime secret retrieval from a user-controlled secret store or interactive credential broker | Repeatable unattended run, no secret-bearing environment variables, and leak-free teardown |
| ENT-8 | Run final cross-edition, privilege-gated, static, package, security, and independent-review gates | Production-readiness evidence for each shipped family |

`ENT-6` through `ENT-8` are delivered for the currently shipped enterprise
families. SMB, AD, and Task Scheduler use shared bounded dispatch, canonical
deduplication, metrics, and target-lock contracts. The unattended test-harness
runner executes five fixed live suites, emits suite heartbeats, records exact
sanitized skip reasons, rejects zero-pass or skipped suites, fails on an unready
cleanup ledger, and writes atomic sanitized evidence. The completed `ENT-8`
gate covers cross-edition, privilege, static, package, cleanup, security, and
independent-review evidence. Every later release candidate must rerun that gate;
its completion does not claim any deferred successor package.

## Domain-lab entry gate

No production implementation begins until the lab inventory proves the target
boundary. The intended evidence topology is:

- two writable domain controllers in one disposable domain when replication or
  DC failover is in scope; one controller leaves those tests blocked
- one domain-joined member server hosting disposable SMB shares, scheduled
  tasks, and software-backed certificate keys
- one domain-joined client or management host for caller-context and
  cross-machine tests
- dedicated test users, nested groups, service identities, denied identities,
  and a recovery identity that is not modified by tests
- snapshot, rebuild, or equivalent reset capability for every mutable machine
- an optional certification authority or second domain/forest only when a work
  package explicitly requires that topology
- a non-production forest with no trust relationship to and no routable path
  from any production directory; ENT-1 records this isolation explicitly
- teardown authority through the untouched recovery identity or machine rebuild
  so a test-written deny ACE cannot prevent cleanup

Credentials, private keys, recovery material, and domain secrets remain outside
the repository, logs, metrics, retained CI evidence, and tool output. Server,
domain, distinguished-name, share, and key-container identifiers may appear in
transient operator-facing output when needed to identify a target, but retained
evidence uses symbolic roles or redacted values. Lab configuration files may
contain symbolic role names and secret-store references, never secret values.

## Sequencing

1. Complete `ENT-1` through `ENT-5` and accept the security/remote contracts.
2. Complete `ENT-6` and `ENT-7` before releasing the first enterprise family.
3. Implement Task Scheduler as the lowest-risk persistent adapter.
4. Implement software-backed CAPI and CNG key adapters.
5. Implement SMB share management and share-only effective access.
6. Implement Active Directory query behavior before any directory mutation.
7. Add Active Directory mutation and replication-aware convergence.
8. Keep combined SMB, NTFS, and domain-context effective access deferred under
  ADR 0017 unless a later accepted decision introduces server-side evidence.
9. Run `ENT-8` for each enterprise release candidate.

Each core family remains independently releasable. Combined SMB, NTFS, and
domain-context effective access is a later dependent increment rather than a
condition for the SMB management release. A later package cannot be used to
waive a failed gate in an earlier package.

## Requirement identifiers

The `ENT-*`, `TASK-*`, `KEY-*`, `SMB-*`, and `AD-*` identifiers are durable
roadmap task identifiers, not functional or non-functional requirements.
Specification 0002 carries the stable `FR-*` and `NFR-*` identifiers for the
behavior delivered against this roadmap, and specification 0005 maps every
requirement and every roadmap task to executable evidence.

## Verification and completion

Every shipped family requires:

- test-first unit coverage for target normalization, rights, mutation
  semantics, identity validation, descriptor preservation, and failure paths
- live tests against disposable targets in both supported PowerShell editions
- exact proof of `WhatIf`, confirmation, pass-through, privilege restoration,
  native resource cleanup, and same-target serialization
- backup/restore tamper, duplicate, schema, partial-failure, and rollback tests
- DSC compilation and live convergence where a DSC resource is supported
- cleanup evidence showing no leaked tasks, keys, shares, directory objects,
  accounts, groups, sessions, handles, or credentials
- independent review for every remote, credential, cryptographic, and directory
  security boundary

## Acceptance conditions

Acceptance required the lab inventory, the API probes, the remote security
contract, the backup-schema decision, the per-family public API contracts, and
stable requirement identifiers. Each is satisfied by a durable artifact rather
than by a completed run.

| Condition | Satisfied by |
| --- | --- |
| Lab inventory | `docs/domain-lab-inventory.md`, verified topology, isolation, reset capability, and `ENT-1` through `ENT-7` foundation |
| API probes | The `TASK-1`, `KEY-1`, `SMB-1`, and `AD-1` capability evidence traced in specification 0005 |
| Remote security contract | ADR 0015, ADR 0018, and ADR 0021 |
| Backup-schema decision | ADR 0016 as extended by ADR 0023, realized by specifications 0013, 0014, and 0017 |
| Per-family public API contracts | Specifications 0009, 0010, 0011, 0012, 0013, 0014, 0015, 0016, and 0017, plus specification 0003 |
| Stable requirement identifiers | `FR-18` through `FR-27` and `NFR-11` through `NFR-20` in specification 0002 |
| Roadmap traceability | The roadmap task traceability tables in specification 0005 |

## Deferred candidates

Mandatory integrity labels, HTTP.sys URL reservations, Remote Desktop Services
listeners, named pipes, PowerShell/WinRM endpoints, WMI namespaces, printers,
event-log channels, MSMQ queues, device ACLs, COM/AppID permissions, and local
account-right assignment remain outside this specification. Each requires a
separate scope decision before implementation. The exclusions for window
stations/desktops, named synchronization objects, JEA/session endpoints, and
other candidates in specification 0006 and ADR 0011 remain unchanged.

## Resolved questions

The questions this specification opened are answered by the accepted contracts
below. Reopening one requires a new decision record.

1. The supplied lab is recorded in `docs/domain-lab-inventory.md`: three
   forests, five domains, five writable domain controllers, a replication
   partner pair, an enterprise root certification authority, five member
   servers, and full reproduction from the deployment script.
2. SMB, Task Scheduler, and private-key operations run locally on the target
   under ADR 0015 and ADR 0018. Active Directory uses direct Kerberos LDAP with
   signing and sealing under ADR 0015 and ADR 0021. CredSSP, unconstrained
   delegation, and per-hop credential chains stay prohibited.
3. Yes. One explicitly selected domain partition is the boundary, and
   specification 0016 keeps read-only domain controllers, inter-site
   replication scheduling, and other partitions outside the contract.
4. Microsoft Software Key Storage Provider is the only supported provider.
   ADR 0024 rejects every Certificate Application Programming Interface
   provider at the boundary, and hardware, smart-card, and remote providers
   stay unsupported.
5. Yes. ADR 0016 requires schema version 2 for enterprise targets, ADR 0023
   extends it to Task Scheduler, and specification 0017 extends it to the
   private-key family.
6. Every enterprise family receives both an exact-descriptor and a rule-presence
   resource, defined by specifications 0013, 0014, and 0017.
7. None beyond the bounded local SID-derived share-only result of
   specification 0011. ADR 0017 defers combined and remote effective access,
   and ADR 0022 defers directory effective access on measured evidence.

## See also

- [WindowsAccessControl expansion](0006-windows-access-control-expansion.md)
- [Security and persistence](0004-security-and-persistence.md)
- [Open issues](open-issues.md)
- [ADR 0011](decisions/0011-limit-release-to-local-object-families.md)
- [ADR 0014](decisions/0014-stage-enterprise-expansion-behind-domain-lab.md)
