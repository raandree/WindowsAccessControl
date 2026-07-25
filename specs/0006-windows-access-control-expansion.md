# Design Concept: WindowsAccessControl

> Status: ACCEPTED
> Interview conducted: 2026-07-25
> Override log: The user requested one consolidated grill round and no later
> questions. Fifty questions covered all twelve Grill-Me categories, and the
> user selected `SIGNED OFF: proceed autonomously`. Conflicts are resolved in
> this document using the latest or most restrictive signed answer.

## Purpose

Rename the unpublished `NTFSPermission` module to `WindowsAccessControl` and
extend its pipeline-first permission management from NTFS files and directories
to registry keys, services, the Service Control Manager (SCM), and live process
objects. The module gives interactive administrators, automation authors, DSC
operators, and security auditors one consistent model for Windows security
descriptors without requiring callers to manipulate native pointers or .NET
access-control classes.

Completion means the selected object families, class-based DSC resources,
documentation, live privileged tests, cross-edition build, package, and
independent review are green. The result is a production-complete `0.x` feature
release rather than a research-only prototype.

## Scope

### Current object families

| Object family | Targets | Persistent | Descriptor capabilities | Inheritance |
| --- | --- | ---: | --- | --- |
| File system | Local NTFS files and directories | Yes | Owner, group, DACL, SACL | Filesystem hierarchy |
| Registry | Local keys in standard hives and 32/64-bit views | Yes | Owner, group, DACL, SACL | Registry-key hierarchy |
| Service | Local named services, driver services, per-user services, and SCM | Yes | Owner, group, DACL, SACL | Not supported |
| Process | Local PID, `Process` object, module output, or caller-owned handle | No | Owner, group, DACL, SACL | Not supported |

Registry values are not independent targets. Windows secures value query and
mutation through rights on the containing key, including `KEY_QUERY_VALUE` and
`KEY_SET_VALUE`.

The public surface uses object-specific commands over a shared private binary
security-descriptor engine. Existing NTFS command concepts remain domain
specific. Cross-domain capabilities use `Windows` nouns, including identity,
privilege, backup, restore, effective access, and metrics.

All supported object families provide, where Windows supports the operation:

- access and audit rule construction, query, add, replace, exact removal,
  rights subtraction, account purge, and explicit-rule clear
- owner, primary group, and section-scoped security-descriptor query or mutation
- versioned unified backup and restore
- effective-access evaluation where Authz produces a defensible result
- pipeline input, `WhatIf`, `Confirm`, and opt-in `PassThru`

Filesystem and registry-key commands additionally provide access and audit
inheritance management. Service and process commands reject inheritance
operations through the capability model rather than silently doing nothing.

### Additional object-type decision

Microsoft documents files, registry keys, services, printers, shares, kernel
objects, processes, window objects, directory-service objects, and WMI objects
as securable Windows object types. The release decision is:

| Candidate | Decision | Reason |
| --- | --- | --- |
| Service Control Manager | Current scope | Persistent service-family descriptor and high administrative value |
| Scheduled tasks | Future | Persistent descriptor and DSC fit, but Task Scheduler COM semantics need a separate adapter |
| Printers | Future | Persistent descriptor; safe write testing needs a disposable print queue and port |
| WMI namespaces | Future | Persistent and hierarchical, but a bad write can lock out management infrastructure |
| SMB shares | Future | Persistent share ACL, but strong in-box cmdlets already exist |
| Event-log channels | Future | Persistent SDDL surface, but custom-channel test setup is a separate concern |
| Certificate private keys | Future | Valuable, but CAPI/CNG addressing differs across PowerShell editions |
| Named kernel synchronization objects | Excluded | Securable but ephemeral and unsuitable for desired-state convergence |
| Window stations and desktops | Excluded | Session-scoped, locally ambiguous names, and high interactive-session risk |
| COM/AppID | Excluded | Niche binary registry descriptors with a high activation-security blast radius |
| JEA/session endpoints | Excluded | Existing platform surface and adjacent to the remote-management non-goal |
| Active Directory objects | Excluded | Explicit signed non-goal for this release |

Primary research anchors are the Microsoft
[`SE_OBJECT_TYPE`](https://learn.microsoft.com/en-us/windows/win32/api/accctrl/ne-accctrl-se_object_type),
[securable objects](https://learn.microsoft.com/en-us/windows/win32/secauthz/securable-objects),
[registry security](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights),
[service security](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights),
and [process security](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
documentation.

## Non-goals

- POSIX ACLs and non-Windows runtime behavior beyond a clear import failure
- cloud IAM, Group Policy authoring, Central Access Policy management, or
  operating-system audit-policy configuration
- Active Directory ACLs in this release
- native remote APIs, remote registry/service targets, or computer discovery
- a graphical interface
- registry-value ACLs, because values have no independent security descriptor
- persistent desired state for a process after that process instance exits
- implicit ownership seizure as a fallback after an authorization failure
- exposing internal helper classes as a caller API

The user selected remote registry and service targets during domain questions,
but later selected local-only management and native remote APIs as an explicit
non-goal. The later, more restrictive answer controls this release. Explicit
credentials are therefore limited to opt-in local impersonation; they do not
activate a remote API surface.

## Stakeholders

Primary users are interactive Windows administrators, automation authors, DSC
operators, and security auditors. The repository owner is the default
maintainer, publisher, issue owner, and approver for future breaking changes.
There are no known external consumers and `NTFSPermission` has not been
published, so a hard package rename is permitted.

The build runs on PowerShell 7. The installed module supports Windows
PowerShell 5.1 and current PowerShell 7 on Windows. Release evidence must cover
Windows 11, Windows Server 2025, the Windows LCM, and a DSC v3 compatibility
assessment.

## Inputs

Identity-valued parameters accept:

- account-name and SID strings
- `NTAccount`, `SecurityIdentifier`, and other `IdentityReference` objects
- module identity and rule output through `SID`, `Account`, and
  `IdentityReference` properties; account parameters retain the compatibility
  aliases `ID` and `IdentityReference`

Identity conversion follows the safe portions of NTFSSecurity's
`IdentityReference2` design: normalize equality and deduplication by SID,
translate account names eagerly, preserve valid orphaned SIDs, and return the
account name when resolvable or SID text otherwise. Callers use cmdlets and
public enums directly; they do not construct public module classes.

Target-valued parameters accept canonical strings, native provider/process
objects, relevant module output, and explicit raw handles. A caller-owned raw
handle is never closed by the module. Module-opened handles are always closed in
`finally` or a safe-handle boundary.

Registry keys accept provider paths and canonical native names. A `RegistryView`
enum selects default, 32-bit, or 64-bit views. Service input uses service names,
not display names; SCM is an explicit parameter set. Process input uses PID or a
`System.Diagnostics.Process` instance. Name-based multi-process selection is not
the default.

State-changing commands prevalidate all identities, rights, target forms, and
backup records before the first write for each target. Cross-target batches are
not transactional; each target is its own persistence boundary.

## Outputs

Commands emit structured objects with versioned type and property contracts,
not public module classes. Every domain rule object includes:

- object family and canonical target identity
- account name, SID, resolution state, and identity reference
- typed domain rights plus normalized unsigned access mask
- access qualifier or audit flags
- explicit/inherited state and inheritance flags where supported
- the native rule or security descriptor for advanced inspection

The module exposes public flags enums for service rights, SCM rights, process
rights, registry view, descriptor sections, rule mutation mode, and DSC ensure
semantics. Default formatting is domain-specific and does not change pipeline
objects.

Backup uses one schema-versioned JSON envelope across all object families. Each
record includes object family, canonical target identity, instance identity
where needed, selected sections, SDDL, and integrity metadata. A SHA-256 digest
is supported, with optional X.509 signature verification when a signing
certificate is supplied. JSON is data and is never evaluated.

In-process metrics are exposed as structured snapshots: operation count,
success/failure count, target count, and elapsed duration by command and object
family. SDDL is not included in metrics.

## Failure modes

- Invalid global input or a malformed backup terminates before mutation.
- Missing targets, access denial, protected processes, exited processes, and
  other per-target failures produce structured nonterminating errors so other
  independent targets can continue.
- A process is opened once with the minimum rights, its creation identity is
  checked, and all work uses that handle. Exit or PID reuse fails closed.
- A missing required privilege produces an error naming the privilege and the
  operation. The module never claims it enabled a privilege absent from the
  token.
- DSC `Set()` throws on any failed write or disappeared target. A later
  consistency pass reconverges from observed state; the resource does not hide
  partial failure.
- Backup restore validates every record and integrity proof before writing.
  Runtime I/O failure can still leave earlier independent targets changed and
  is reported with the completed-target set.
- Parallel workers aggregate errors without suppressing error records or
  weakening assertions.

## Edge cases

- Empty target and identity collections are rejected.
- Duplicate target aliases and identities are deduplicated by canonical target
  identity and SID before dispatch.
- Unicode paths, key names, service names, and account names use Unicode native
  APIs.
- Registry paths account for provider prefixes, canonical hive aliases, and
  WOW64 view selection. Registry values remain key-level rights only.
- Service names are case-insensitive and distinct from display names. Per-user
  service instance names and driver services use the same named-service API.
- Process ID `0`, protected processes, and inaccessible system processes fail
  with actionable errors. A process descriptor is never treated as persistent
  after process exit.
- Null DACLs, absent SACLs, unknown ACE types, mandatory labels, and resource
  attribute ACEs are preserved unless the selected exact-descriptor operation
  explicitly owns that section.
- Canonical ACE order is reported and preserved. The module does not silently
  reorder an ACL unless an explicit exact-descriptor resource owns it.
- Filesystem reparse targets and path replacement retain the documented
  time-of-check/time-of-use risk; privileged callers must use trusted parents.
- Same-target concurrent writes are serialized. Different canonical targets
  can run concurrently.

## Security

The module uses in-box managed APIs plus narrowly scoped Unicode Win32 interop.
Named registry and service targets use `GetNamedSecurityInfoW` and
`SetNamedSecurityInfoW`; process and caller-owned handles use `GetSecurityInfo`
and `SetSecurityInfo`. The engine copies returned self-relative descriptors and
releases every native buffer or handle.

Commands automatically enable required privileges only when the current token
already contains them. The privilege scope is reference-counted across parallel
workers and restores the original enabled state in `finally`. Typical scopes
include `SeSecurityPrivilege` for SACL access, `SeRestorePrivilege` for
arbitrary owner or restore operations, `SeTakeOwnershipPrivilege` for explicit
take-ownership operations, and `SeDebugPrivilege` only when a process operation
requires it. Read operations do not retain broader authority after completion.
This decision supersedes ADR 0007's explicit-only production behavior.

`PSCredential` input is opt-in local impersonation. Secrets are never logged,
serialized into backup documents, or passed through tool output. The module
redacts SDDL from verbose output; debug output may identify native API, section
flags, target metadata, and error codes but not full descriptors by default.

Mutators use `ShouldProcess`. Destructive exact-descriptor, clear, restore,
owner, and broad purge operations use high confirmation impact. Ordinary
mutators do not snapshot automatically; callers and DSC workflows use explicit
backup when rollback is required.

Live tests mutate only disposable scratch resources: temporary NTFS trees,
HKCU registry keys, temporary services, and controlled child processes. Tests
snapshot state, restore privileges, clean up in `finally`, and fail if a test
resource leaks.

## Performance

The supported operating point is approximately 10,000 targets per command and
hundreds of ACEs per descriptor. Target arrays use bounded parallelism by
default, with `ThrottleLimit` defaulting to the smaller of eight and the logical
processor count. `ThrottleLimit 1` provides deterministic sequential execution.

Identity translation and target normalization are cached within one invocation.
Each target descriptor is loaded once and persisted once per selected mutation.
Workers stream completed objects and structured errors without retaining native
buffers. Representative batch benchmarks must show no material regression from
the current NTFS implementation; correctness and section preservation remain
hard gates.

## Observability

Commands provide structured error identifiers, verbose decision traces, and
redacted debug-level native details. `Get-WindowsAccessControlMetric` returns
in-process counters and durations by command and object family. No Windows event
log or ETW provider is introduced in this release.

Live and CI evidence retains NUnit XML, build/analyzer logs, operating-system
and PowerShell inventory, privilege inventory, DSC results, benchmark summary,
and scratch-resource cleanup proof. A reviewer can determine within 30 seconds
whether each object family, DSC resource, edition, and privilege gate passed.

## Rollback

The package rename is hard because the old package is unpublished and has no
known consumers. The existing module GUID is preserved so Gallery identity and
project lineage follow the rename; package metadata and source paths use
`WindowsAccessControl`. A migration map records every renamed cross-domain
command and output type.

If external use is discovered before release, generate a separately tested
`NTFSPermission` compatibility package that imports `WindowsAccessControl` and
provides deprecated aliases. Do not ship a speculative shim without evidence.

Ordinary ACL writes are reversible through explicit unified backup and restore.
Exact restore is section-scoped. Process rollback is possible only while the
same pinned process instance exists. There is no remote rollback surface.

## Open questions

No question blocks implementation. The following are intentionally deferred
and must receive separate specifications before implementation:

- native remote registry, service, printer, WMI, task, or event-log management
- scheduled-task, printer, WMI namespace, SMB-share, event-log-channel, and
  certificate-private-key adapters
- Active Directory ACLs
- persistent policy that reapplies permissions to future process instances
- heuristic inherited-ACE provenance or remote effective-access context

## Sign-off

- [x] User has read the consolidated interview choices end to end.
- [x] User accepts every section or delegated conflict resolution to the agent.
- [x] User selected `SIGNED OFF: proceed autonomously` on 2026-07-25.
