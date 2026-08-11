---
status: current
last-verified: 2026-08-04
owner: active-agent
source: repository evidence
---

# System patterns

Normative architecture decisions live under
[specs/decisions/](../specs/decisions/README.md). The entries below are routing
summaries only; accepted ADRs control when wording differs.

## Architecture

Public commands handle pipeline binding, path parameter sets, `ShouldProcess`,
and output. Private functions resolve paths and identities, map inheritance
semantics, load and persist only required security descriptor sections, and
convert native rules into stable PowerShell objects. Pure descriptor mutation
is separated from filesystem persistence so most behavior is unit-testable
without elevation.

## Fail-closed gate patterns

These generalize beyond the private-key family and were established by the
specification 0015 reviews.

- A gate input that cannot be read must throw. An enumeration that cannot tell
    completion from failure silently truncates its own input, which turns a
    refusal into a permit.
- A refusal that is global needs its input set wide enough that only a genuine
    fault reaches it. Narrowing the search to a fixed list converts unrelated
    stale state into a machine-wide denial of the whole command family.
- Over-matching is the safe direction for a detector and under-matching is not.
    Prefer a pattern that yields a false refusal to one that can yield no
    detection at all, and record the trade rather than tightening by reflex.
- A command that matches exactly must say when it matched nothing. A revocation
    that removed nothing and reported success is worse than one that failed.
- A predicate that decides a security outcome must not depend on a caller gate
    for its correctness, even when every current caller applies that gate.
- A read-only probe settles a disputed claim faster than an argument. Two review
    findings in this family were refuted by measuring the platform instead.
- Delete the parameter rather than trust the caller. The private-key write
    boundary stopped taking a certificate at all, so a restore and a
    desired-state resource cannot reach it with a weaker binding check. A gate
    that cannot be addressed incorrectly does not need a reviewer to confirm
    that every caller addressed it correctly.
- A replay path inherits every gate of the direct path or it is a bypass. A
    portability restore adds no parameter, no exemption, and no override switch;
    it composes the same write command an operator would run.
- Prove a refusal with a test, not with an argument that it cannot happen. Each
    fail-closed write gate has a restore-level refusal test, because a gate that
    is only reachable in theory is a gate nobody notices going inert.
- A lookup that narrows a grant must throw when it resolves nothing. ADMF's
    `Convert-AdcSchemaGuid` silently drops a name it cannot map, so a misspelled
    `ObjectType` collapses to the empty GUID and an entry meant for one property
    becomes an entry for every property. Any name-to-GUID input added here fails
    closed instead.
- An argument transformation attribute does not run on a parameter that also
    declares its type. PowerShell adds `ArgumentTypeConverterAttribute` for the
    declared type and that converter runs first, so a transform written to widen
    what the type accepts never sees the value. Either the attribute owns the
    whole conversion and the type declaration goes, or the attribute is
    decoration. Prove such an attribute with a test that binds the value the
    declared type would reject, not with a test that the attribute is present.
- A refusal that is correct can still be a gap. Refusing to expand a forest-wide
    alias without the root domain SID was right, and it also made the command
    useless for whole classes on any child domain controller, which is an
    ordinary topology. A fail-closed branch needs a reachable path to the value
    it is closed on; here that path is the global catalog port of the same
    pinned server. Reach for the second source before accepting the refusal.
- A single lab is not a topology. Two separate forests cannot exercise a
    root-versus-child difference at all, and the branch that mattered most only
    ran once the suite pointed at a child domain. Check that the fixture can
    reach the branch before reading a green run as evidence for it.

## Acceptance lab

The domain acceptance lab derives from the AutomatedLab sample scenario
`Multi-AD Forest with Trusts.ps1`. Every addition on top of that baseline must
name the suite that fails without it, and a machine no suite reaches is recorded
as reserved rather than described as required.
[tests/Lab/README.md](../tests/Lab/README.md) holds that delta and is the
operator entry point.

## Coverage measurement

Coverage is measured where the code runs, not where the test harness runs. A
suite that drives the module through a session against another machine records
nothing on the harness side, so the acceptance runner publishes the measurable
locations once, each such suite arms them in the remote runspace, and the hit
counts return in publication order and are added to the harness-side counts.
One JaCoCo document is rendered from the harness-side locations so its package,
class, and source-file names match the document the repository build produces
for the same module version. Before any merge, a document that measures a
source file or a line the reference document does not is refused, because such
a merge produces a union of disjoint sets and moves the reported percentage
without measuring anything new.

A threshold is asserted over what the running profile can execute, never over
what some other environment could execute. Normative record:
[ADR 0027](../specs/decisions/0027-assert-coverage-over-executable-scope.md).
The generalizable parts:

- A gate that only one environment can meet is two verdicts, not one. Assert the
    same rule everywhere and let the reported numbers differ with the evidence.
- Evidence that cannot be verified is absent evidence, not a defect. A stale
    document is reported and ignored rather than merged or turned into a red
    build nobody can fix.
- A declaration that removes code from a gate needs a check derived from
    measurement, not a sentence in a decision record. Here the rule is that the
    local profile must execute nothing of a declared file, and the build proves
    it against the locally measured document on every run.
- Declare exact paths rather than globs when the list decides what is asserted.
    `-like` is case-insensitive and a glob silently absorbs files added later.
- The `-f` format operator binds tighter than `+`, so a concatenated format
    string leaves the first placeholders unformatted unless the concatenation is
    parenthesized. Force an error branch to run rather than reading it.

## Decisions

### Decision 1: Use the canonical Memory Bank base

- Choice: Keep durable project context in .memory-bank.
- Rationale: Preserve evidence-backed context across sessions.

### Decision 2: Use only in-box runtime APIs

Normative record: [ADR 0002](../specs/decisions/0002-use-only-in-box-runtime-security-apis.md).

- Choice: Build on `Get-Acl`, `Set-Acl`, and
    `System.Security.AccessControl`, with narrowly scoped Windows interop only
    where no managed API exists.
- Rationale: Support both PowerShell editions without inheriting archived
    AlphaFS or ProcessPrivileges dependencies.

### Decision 3: Keep destructive ACL semantics explicit

Normative record: [ADR 0004](../specs/decisions/0004-expose-explicit-acl-mutation-semantics.md).

- Choice: Map add, set, exact removal, rights subtraction, and account purge to
    distinct parameter sets; do not expose whole-DACL reset as a routine rule
    operation.
- Rationale: The underlying .NET methods differ materially and accidental
    reset can remove every unrelated ACE.

### Decision 4: Preserve descriptor sections

Normative record: [ADR 0003](../specs/decisions/0003-persist-only-selected-descriptor-sections.md).

- Choice: Read and persist only the descriptor sections required by each
    operation.
- Rationale: Microsoft recommends matching loaded and persisted sections, and
    this prevents a DACL operation from clobbering a SACL, owner, or group.

### Decision 5: Use versioned, validated JSON backups

Normative record: [ADR 0005](../specs/decisions/0005-use-versioned-validated-json-backups.md).

- Choice: Store path, item type, selected section mask, and SDDL under schema
    version 1; validate and prepare every record before the first restore write.
- Rationale: Keep backup content non-executable, section-scoped, and resistant
    to malformed later records causing partial application.

### Decision 6: Keep destructive modes separately testable

Normative record: [ADR 0004](../specs/decisions/0004-expose-explicit-acl-mutation-semantics.md).

- Choice: Model exact removal, rights subtraction, and account-wide purge as
    explicit modes, with `WhatIf`, high confirmation impact, and regression tests
    for each access and audit path.
- Rationale: The native APIs have different semantics and account-wide purge
    does not require a rights mask.

### Decision 7: Batch only after identity prevalidation

Normative record: [ADR 0006](../specs/decisions/0006-prevalidate-and-deduplicate-identities.md).

- Choice: Resolve and deduplicate all account inputs by SID before changing a
    descriptor, then persist once per target and emit one result per unique SID.
- Rationale: Invalid identities fail before mutation, duplicate aliases cannot
    misrepresent persisted ACEs, and batch operations avoid repeated writes.

### Decision 8: Make privilege gaps executable and explicit

Normative record: [ADR 0007](../specs/decisions/0007-keep-privilege-changes-explicit.md).

- Choice: Enumerate current-token privileges without enabling them, and keep
    privileged acceptance scenarios discovered but skipped with exact reasons
    when required privileges are absent.
- Rationale: Missing privilege evidence must not look like a passing SACL or
    arbitrary-owner live test, and read operations must not broaden token state.

### Decision 9: Keep specifications authoritative and help beside code

Normative record: [ADR 0001](../specs/decisions/0001-document-api-contract-in-specs-and-help.md).

- Choice: Numbered specifications own requirements and holistic API/security
    contracts; comment-based help owns exhaustive per-command detail; the
    README owns the overview and command catalog; the usage guide owns
    task-oriented cross-command workflows.
- Rationale: Each user question has one documentation layer without duplicating
    parameter reference that belongs next to implementation.

### Decision 10: Persist ACL protection with the selected ACL

- Choice: When changing file-system DACL or SACL protection, persist the
    selected ACL pointer and its protected or unprotected native control flag
    together through `SetNamedSecurityInfoW`.
- Rationale: PowerShell 7 can persist ACE content through
    `FileSystemAclExtensions.SetAccessControl` while dropping an unprotected
    SACL control flag; passing only a native protection flag is rejected.

### Decision 11: Scope required privileges to operations

Normative record: [ADR 0008](../specs/decisions/0008-use-scoped-automatic-privilege-enablement.md).

- Choice: Reference-count required privilege scopes and restore original token
    state after the final worker exits.
- Rationale: Commands and DSC remain composable without import-time authority
    broadening.

### Decision 12: Rename to WindowsAccessControl

Normative record: [ADR 0009](../specs/decisions/0009-rename-module-to-windows-access-control.md).

- Choice: Hard-rename the unpublished package and cross-domain contracts while
    retaining NTFS in filesystem-specific command nouns.
- Rationale: The package name must describe all current object families.

### Decision 13: Share one binary descriptor engine

Normative record: [ADR 0010](../specs/decisions/0010-use-shared-binary-security-descriptor-engine.md).

- Choice: Use named Unicode APIs for registry/services and handle APIs for
    processes over self-relative binary descriptors.
- Rationale: This preserves section and ACE fidelity across both PowerShell
    editions without a runtime dependency.

### Decision 14: Keep the release local and testable

Normative record: [ADR 0011](../specs/decisions/0011-limit-release-to-local-object-families.md).

- Choice: Ship local file system, registry key, service/SCM, and live process
    targets; defer or exclude other securable object types explicitly.
- Rationale: Remote trust and ephemeral object lifetimes require separate
    contracts.

### Decision 15: Use object-specific public and DSC surfaces

Normative record: [ADR 0012](../specs/decisions/0012-use-object-specific-commands-and-dsc-resources.md).

- Choice: Export object-specific commands, typed object contracts, public
    enums, and exact/rule class-based DSC resources per family.
- Rationale: Rights and capabilities remain discoverable while internals stay
    shared.

### Decision 16: Bound parallel target execution

Normative record: [ADR 0013](../specs/decisions/0013-use-bounded-parallel-target-execution.md).

- Choice: Prevalidate and deduplicate before bounded parallel dispatch;
    serialize aliases of one canonical target. Import an isolated module into
    each worker runspace, keep recursion state thread-local, retain metrics in
    the parent module, and share the reference-counted lock registry across
    module instances in the hosting application domain.
- Rationale: Enterprise-size batches need throughput without lost updates or
    unbounded native resource use. A single `PSModuleInfo` cannot be entered
    concurrently, while module-local lock stores cannot coordinate independent
    imports.

### Decision 17: Normalize and verify registry targets before native calls

Normative record: [ADR 0011](../specs/decisions/0011-limit-release-to-local-object-families.md).

- Choice: Normalize provider/native hive aliases into one named-object target,
    select registry view through `SE_REGISTRY_*`, and reject remote paths or
    remote/unverifiable `RegistryKey` objects before using their names.
- Rationale: Remote `RegistryKey.Name` values look local; accepting them could
    redirect an intended remote mutation to the same path on the local host.

### Decision 18: Keep ACL masks and objects explicit across editions

- Choice: Assign `RawAcl` instances in direct branches so PowerShell does not
    enumerate them into ACEs, and perform .NET `AceFlags`, `AuditFlags`, and
    `ControlFlags` bitwise operations through integer masks before casting at
    API boundaries.
- Rationale: PowerShell 7 tolerates enum coercion that Windows PowerShell 5.1
    rejects, while expression output can silently unwrap an enumerable ACL.

### Decision 19: Skip semantically identical named-descriptor writes

- Choice: Compare selected-section SDDL under the same privilege scope before
    native persistence; return an absent SACL unchanged for matchless clear or
    remove operations.
- Rationale: Idempotent operations must not require an unnecessary privileged
    write or turn an absent SACL into an empty present SACL.

### Decision 20: Address the SCM through a scoped native handle

Normative record: [ADR 0010](../specs/decisions/0010-use-shared-binary-security-descriptor-engine.md).

- Choice: Open the local SCM with `OpenSCManagerW` using only `READ_CONTROL`,
    `WRITE_DAC`, `WRITE_OWNER`, and/or `ACCESS_SYSTEM_SECURITY` required by the
    selected operation; use the shared `GetSecurityInfo`/`SetSecurityInfo`
    engine and close with `CloseServiceHandle` in `finally`.
- Rationale: The SCM is not a named service and cannot be addressed through
    `GetNamedSecurityInfoW`, while the handle engine preserves the same binary
    descriptor and section-scoped persistence model.

### Decision 21: Keep service and SCM rights distinct

- Choice: Use one service command family with explicit `Service` and
    `ServiceControlManager` parameter sets; bind `WindowsServiceRights` for
    named services and `WindowsServiceControlManagerRights` for the SCM.
- Rationale: One public noun keeps workflows discoverable while parameter-set
    typing prevents applying rights from the wrong Windows object contract.

### Decision 22: Pin one live process handle per PID operation

Normative records: [ADR 0010](../specs/decisions/0010-use-shared-binary-security-descriptor-engine.md)
and [ADR 0011](../specs/decisions/0011-limit-release-to-local-object-families.md).

- Choice: Normalize PID, `Process`, and module output to a positive PID plus
    creation `FILETIME`; verify both when opening one operation-scoped handle,
    then perform the complete read, comparison, mutation, and write through that
    handle. Treat caller handles as borrowed and never close them.
- Rationale: A PID can be reused between separate opens. Pinning and operating
    on one verified handle closes that race while preserving caller ownership.

### Decision 23: Retry process access without broadening token authority

Normative record: [ADR 0008](../specs/decisions/0008-use-scoped-automatic-privilege-enablement.md).

- Choice: Retry a denied PID handle open with `SeDebugPrivilege` only when the
    first failure is access denied and the current token already contains the
    privilege. Restore its exact initial state after the retry scope.
- Rationale: Protected processes may require debug authority, but unrelated
    errors and caller-owned handles must not trigger privilege escalation.

### Decision 24: Use one integrity-protected descriptor envelope

Normative records: [ADR 0003](../specs/decisions/0003-persist-only-selected-descriptor-sections.md)
and [ADR 0005](../specs/decisions/0005-use-versioned-validated-json-backups.md).

- Choice: Normalize object-specific descriptor output into one schema-versioned
    record carrying family, canonical target, instance metadata, native section
    mask, SDDL, and a deterministic SHA-256 digest. Optionally sign each digest
    with an explicitly supplied RSA X.509 certificate.
- Rationale: One non-executable format preserves section fidelity across both
    PowerShell editions while keeping target-specific validation and persistence
    inside existing adapters.

### Decision 25: Validate and prepare the complete restore before writing

- Choice: Verify every schema field, digest, optional signature, selected
    section, canonical target, duplicate, and live process identity, then prepare
    every target before entering the persistence loop.
- Rationale: A malformed or tampered later record must not mutate an earlier
    independent target. Runtime write failures remain nontransactional and are
    recoverable by rerunning the validated backup.

### Decision 26: Make absence and backup replacement explicit

- Choice: Encode a selected absent SACL as `S:NO_ACCESS_CONTROL`, reject omitted
    selected ACLs and null DACLs, and write completed envelopes through atomic
    same-directory move or replacement after `ShouldProcess` approval.
- Rationale: Absence must not be confused with an empty ACL, and interrupted
    backup writes must not destroy the prior recovery artifact.

### Decision 27: Keep aggregate backup writes singular

Normative records: [ADR 0005](../specs/decisions/0005-use-versioned-validated-json-backups.md)
and [ADR 0013](../specs/decisions/0013-use-bounded-parallel-target-execution.md).

- Choice: For NTFS aggregate backup, normalize the complete target set and read
    descriptors through bounded workers, then call the unified writer exactly
    once only after every read succeeds.
- Rationale: Descriptor reads benefit from concurrency, but recursively writing
    one envelope per target would break atomicity and overwrite semantics.

### Decision 28: Make exact DSC identity object-specific

Normative record: [ADR 0012](../specs/decisions/0012-use-object-specific-commands-and-dsc-resources.md).

- Choice: Export separate exact selected-section resources for NTFS, registry
    key, named service, SCM, and pinned process targets. Include registry view
    and process creation `FILETIME` in composite identity and use a prefixed
    reason class.
- Rationale: Target identity and rights semantics differ by family. Process
    reuse and registry view must fail closed rather than converge the wrong
    object.

### Decision 29: Normalize only system-derived ACL flags in DSC

- Choice: Compare canonical selected-section SDDL after clearing only DACL/SACL
    `AUTO_INHERITED` flags on cloned descriptors. Preserve protection flags,
    selected ACL presence, and every ACE exactly.
- Rationale: Windows can add auto-inherited flags after persistence, causing an
    endless DSC loop, while ignoring protection or ACE differences would weaken
    desired-state ownership.

### Decision 30: Give rule-presence DSC exact ACE identity

Normative record: [ADR 0012](../specs/decisions/0012-use-object-specific-commands-and-dsc-resources.md).

- Choice: Identify a managed access rule by canonical target, SID, unsigned
    rights mask, allow/deny qualifier, explicit origin, and inheritance scope
    where supported. `Absent` removes every duplicate exact native ACE.
- Rationale: Presence resources must preserve partial rights, inherited ACEs,
    opposite qualifiers/scopes, and unrelated identities rather than behaving
    like account purge or descriptor replacement.

### Decision 31: Normalize NTFS rule masks through .NET

- Choice: Construct the desired `FileSystemAccessRule` before comparison so
    allowed rights include .NET's automatic `Synchronize` bit while denied
    rights retain their requested mask.
- Rationale: Comparing the raw requested mask to the materialized ACE causes
    permanent drift for allowed NTFS rules.

### Decision 32: Scope explicit credentials to local impersonation

Normative record: [ADR 0011](../specs/decisions/0011-limit-release-to-local-object-families.md).

- Choice: Expose one `Invoke-WindowsAccessControl` script-block scope, acquire
    an interactive local token with `LogonUserW`, and execute through
    `WindowsIdentity.RunImpersonated` in both supported PowerShell editions.
- Rationale: One explicit scope composes with every object-specific command
    without duplicating credentials or introducing remote target semantics.
    Direct `SecureString` marshaling, zeroing, and safe-handle disposal bound
    password and token lifetime to the operation.

### Decision 33: Use breakpoint coverage across PowerShell editions

- Choice: Keep Pester `CodeCoverage.UseBreakpoints` enabled for the module test
    gate in both supported PowerShell editions.
- Rationale: Pester 5.7.1 marks profiler-tracer coverage as experimental. On
    Windows PowerShell 5.1 it corrupts class-based DSC construction after
    Desktop LCM acceptance, while breakpoint coverage preserves the same tests
    and clears the coverage threshold in both editions.

### Decision 34: Align native ACE metadata with managed rule enumeration

- Choice: When a Windows API returns metadata for every native DACL ACE but the
    public contract uses .NET access rules, parse the same binary descriptor and
    filter metadata to `CommonAce` allow/deny entries before positional pairing.
- Rationale: `.GetAccessRules()` omits object and other nonstandard ACEs. Zipping
    its output directly to a full native ACE array can shift provenance or make
    valid enterprise ACLs fail enumeration.

### Decision 35: Gate enterprise expansion on a disposable domain lab

Normative record: [ADR 0014](../specs/decisions/0014-stage-enterprise-expansion-behind-domain-lab.md).

- Choice: Plan Task Scheduler, certificate private-key, SMB-share, and Active
    Directory adapters as separate work packages, but block implementation on
    lab inventory, disposable setup/teardown, API probes, threat models, remote
    contracts, and rollback evidence. Require an isolated non-production forest,
    protected remote channels, direct authentication, and explicit target-token
    privilege behavior; prohibit CredSSP and unconstrained delegation.
- Rationale: Provider, server, credential, LDAP, replication, and lockout
    behavior cannot be proven by mocks or inherited from the local object
    families. ADR 0011 remains the current-release boundary.

### Decision 36: Build once and test the same artifact in GitHub Actions

- Choice: Check out full history, calculate the module version with the pinned
    GitVersion tool, build one Sampler output artifact on Windows, and test that
    artifact in separate PowerShell 7 and Windows PowerShell 5.1 jobs. Keep
    workflow permissions read-only and retain test reports as artifacts.
- Rationale: One immutable build output keeps both supported editions aligned,
    full history preserves semantic versioning, and least-privilege automation
    is sufficient for continuous integration without release credentials.

### Decision 37: Version symbolic lab evidence, not infrastructure identity

- Choice: Store domain-lab evidence by symbolic role and capability while
    keeping machine/domain mappings, addresses, credentials, secret-store
    references, and recovery material outside the repository. Treat successful
    explicit Kerberos connectivity as capability evidence, not as approval of
    a server baseline that still permits prohibited downgrade paths.
- Rationale: Repeatable evidence does not require identifying the lab, and one
    secure client choice cannot prove that weaker server authentication or
    transport settings are unavailable.

### Decision 38: Mark, compensate, and explicitly delete lab keys
- Choice: Give every disposable lab resource an exact identity and ownership
    marker, refuse unmarked collisions, compensate member-first then domain on
    partial setup failure, and keep the untouched RID-500 identity outside the
    fixture. Use a deterministic software CNG provider/container and call
    `CngKey.Delete` before removing its selector certificate.
- Rationale: Idempotent names alone do not establish ownership, recursive
    teardown can otherwise delete foreign objects, and deleting a certificate
    from the Windows store does not delete its persisted CNG private key.

### Decision 39: Address SMB shares through local provider authority

Normative record: [ADR 0015](../specs/decisions/0015-use-local-smb-and-signed-sealed-ldap.md).

- Choice: Resolve ordinary, non-special shares through the local SMB provider,
    reject wildcard and nonlocal topology, and persist only the DACL through
    `SE_LMSHARE`. Capture and restore the share description around native
    descriptor writes.
- Rationale: The provider owns local share identity and topology, while a raw
    `SE_LMSHARE` write can clear description metadata that is outside the
    selected security descriptor section.

### Decision 40: Bind Active Directory operations to strict LDAP authority

Normative record: [ADR 0015](../specs/decisions/0015-use-local-smb-and-signed-sealed-ldap.md).

- Choice: Connect directly to an explicit FQDN writable domain controller with
    LDAP v3, Kerberos authentication, signing, sealing, referrals disabled, and
    bounded timeouts. Use DACL-only LDAP controls and prevalidate the complete
    write batch against allowed-base, immutable-GUID, excluded-partition, and
    protected-target rules before dispatch. Decision 58 later allowed the
    domain-controller name to be discovered and pinned instead of supplied.
- Rationale: `Negotiate` can fall back to NTLM, referrals can change authority,
    and per-worker validation can allow an earlier independent target to mutate
    before a later invalid target is discovered.

### Decision 41: Require schema version 2 for enterprise targets

Normative record: [ADR 0016](../specs/decisions/0016-require-schema-v2-for-enterprise-targets.md).

- Choice: Keep schema version 1 limited to its canonical local target families;
    require schema version 2 before SMB-share or Active Directory records enter
    unified backup and restore.
- Rationale: Extending schema version 1 would weaken its established authority
    and target-identity guarantees for records that require server, share, base
    DN, and immutable directory identity metadata.

### Decision 42: Verify Task Scheduler DACLs semantically

- Choice: Compare persisted Task Scheduler DACLs by protection state and exact
    ACE identity while tolerating only service-derived ACE order and
    `DACL_AUTO_INHERITED` changes. Preserve every Local System ACE and release
    COM objects in reverse acquisition order.
- Rationale: The Task Scheduler service canonicalizes descriptors after a
    write. Raw SDDL equality rejects valid persistence, while broader
    normalization could hide a rights or protection change.

### Decision 43: Keep caller callbacks in one runspace

- Choice: Execute `Edit-NTFSItemSecurityDescriptor` callbacks sequentially,
    with one read and at most one selected-section write per target. Keep
    callback output suppressed and reject edits to unloaded sections.
- Rationale: A caller-owned script block is not safe to invoke concurrently
    across worker runspaces. Deterministic sequential execution preserves the
    bounded editing contract without sharing mutable callback state.

### Decision 44: Make unattended suite success explicit

- Choice: Require every domain-lab suite to report `Passed`, discover and pass
    at least one test, report zero skips, and leave both lab boundaries ready.
    Write sanitized evidence atomically and preserve a primary suite failure
    when cleanup or evidence finalization also fails.
- Rationale: Pester can report a passed container with zero useful tests, and a
    finalization error can otherwise mask the failure that changed system
    state.

### Decision 45: Separate CNG inspection from mutation

- Choice: Limit the first certificate-private-key increment to DACL inspection
    of an exact persisted RSA key in Microsoft Software Key Storage Provider.
    Cross-check certificate, provider, and key identity; hash the canonical
    target; retain caller certificate lifetime; and never export key material.
- Rationale: Safe CNG writes require critical-binding detection, provider
    implementation checks, service-ACE preservation, rollback, and separate
    cryptographic review. Read authority can be proven without assuming those
    mutation guarantees.

### Decision 46: Fail closed on an unloaded descriptor section

- Choice: Reject a descriptor-bound mutation whose required section was not
    loaded, rather than widening the descriptor's `Sections` to cover it.
- Rationale: Widening makes the persist step write a section the descriptor
    never read, replacing a live ACL with an empty one. The gate protects
    against forgetting to load a section; `Sections` stays caller-writable, so
    it is not a defense against deliberate tampering by the trusted caller.

### Decision 47: Keep a descriptor projection consistent with its native object

- Choice: Refresh a descriptor's SDDL, owner, group, protection, and canonical
    projection in place after every in-memory mutation, and create a missing
    projection member instead of throwing.
- Rationale: Backup and inspection read the projection, not the native object,
    so a stale projection silently produces pre-edit output. Creating a missing
    member keeps a caller-supplied object from failing after its target was
    already written.

### Decision 48: Never let a post-write step throw

- Choice: Compile native types and validate native preconditions before the ACL
    write, and skip an ACL-protection request whose ACL is absent while
    reporting the skip through the verbose stream.
- Rationale: A throw after `SetAccessControl` commits leaves a caller believing
    nothing was applied while the change is live. `SetFileSystemAclProtection`
    rejects an absent ACL, and NTFS items routinely have no SACL.

### Decision 49: Default to the typed parameter set for descriptor input

- Choice: Where a command exposes both an untyped `[object[]]$Path` and a
    `[PSTypeName(...)]` descriptor parameter on the pipeline, make the
    descriptor set the default.
- Rationale: Both match a `pscustomobject` without coercion, and the binder
    breaks the tie with the default set. With `Path` as the default, a piped
    descriptor is stringified into a path and fails in target resolution. This
    was verified empirically, not assumed.

### Decision 50: Name rights after the operation, per object type

- Choice: Give Task Scheduler two enums. `WindowsTaskFolderRights` names
    directory operations (`ListTasks`, `CreateTask`, `CreateSubfolder`,
    `Traverse`); `WindowsScheduledTaskRights` names file operations
    (`ReadTaskDefinition`, `WriteTaskDefinition`, `RunTask`). Neither exposes
    `FileSystemRights` or `ACCESS_SYSTEM_SECURITY`.
- Rationale: Task Scheduler descriptors live on the file-backed task store, so
    the masks are file rights, but the same bit means different things on a
    folder and a task: `0x2` creates a task on a folder and updates the
    definition on a task. One shared enum would have understated a folder grant.
    Microsoft documents the mapping in "Security Contexts for Tasks".

### Decision 51: Evaluate the whole service token before a Task Scheduler write

- Choice: Reject a candidate DACL that newly denies read, write, or run access
    to any identity in the Task Scheduler service token, using the live
    LocalSystem token group set captured for the `Schedule` service plus
    `NT SERVICE\ALL SERVICES`. Do not re-evaluate a deny ACE that the target
    already carries; warn about it instead, and warn when a new deny removes
    `WRITE_DAC` or `WRITE_OWNER`.
- Rationale: Preserving the literal SYSTEM ACEs is not sufficient; a deny ACE
    for Everyone, Users, or Administrators locks the service out just as
    effectively. Ignoring pre-existing deny ACEs keeps an affected target
    manageable and recoverable, and the warnings keep both conditions visible.
    The SID list is best effort: another SKU or build can carry more groups.

### Decision 52: Reject ACE types the Task Scheduler store re-revisions

- Choice: Reject object and compound ACEs in a Task Scheduler candidate DACL.
- Rationale: The store accepts them but normalizes the ACL revision from 2 to
    4, so exact-persistence verification fails and rolls the write back with a
    misleading error. Those ACE types also carry no Task Scheduler meaning.
    Verified empirically against a disposable task folder.

### Decision 53: Make inheritance scope part of ACE identity when adding

- Choice: Let a caller opt `Invoke-WindowsAclRuleMutation` into
    `-MatchAceFlags`, so an `Add` treats a differing `AppliesTo` as a distinct
    ACE rather than a duplicate. The Task Scheduler folder and registry-key
    families opt in.
- Rationale: The default exact match compares only qualifier, SID, and access
    mask, so re-adding an existing account and rights combination with a new
    inheritance scope silently wrote nothing and returned nothing through
    `PassThru`. The switch is opt-in so `Set` and `Clear` semantics for the
    other families are unchanged.

### Decision 54: Re-read and compare before a staged descriptor write

- Choice: Pass the descriptor read at staging time to
    `Set-WindowsTaskSchedulerSecurityDescriptor` and reject the write when the
    target's DACL no longer matches it. Verify the rollback descriptor too, and
    report an indeterminate state when it cannot be confirmed.
- Rationale: The write boundary already re-reads the target for its safety
    gates, but previously wrote the stale candidate anyway, so a concurrent
    change was silently clobbered. The two rule-removal commands do not take
    the canonical target lock, so this check is what protects them.

### Decision 55: Emit batched worker output outside the dispatcher's catch

Normative record: [ADR 0013](../specs/decisions/0013-use-bounded-parallel-target-execution.md).

- Choice: Keep every pipeline write out of the batch dispatcher's per-target
    `try`/`catch`. The sequential path collects worker output into a list; the
    parallel path reuses the collection `EndInvoke` already materialized. Both
    emit through `$PSCmdlet.WriteObject($item, $false)` after the target's lock
    is released, then write that target's error record.
- Rationale: PowerShell surfaces a downstream command's terminating error in
    the upstream frame at the moment output is written. With the write inside
    the dispatcher's `catch`, that error was indistinguishable from a worker
    failure — a probe confirmed identical exception type, fully qualified error
    ID, activity, and invocation info — and was downgraded to a non-terminating
    error, so a piped fail-closed rejection did not stop the caller. Moving the
    write out also runs it after the worker's `finally` cleared the thread-local
    batch-worker flag, so a downstream mutator dispatches and locks its own
    targets instead of silently taking the inline branch.

### Decision 56: Degrade registry provenance instead of losing the rules

- Choice: Resolve registry `InheritedFrom` only with `SE_REGISTRY_KEY`, enforce
    that object type in the native entry point as well as the PowerShell gate,
    and report a null source with a non-terminating error when the ancestor
    lookup fails or its row count does not match the ACL. The filesystem path
    keeps terminating the target.
- Rationale: A live probe showed Windows rejects the WOW64 registry-view object
    types with `ERROR_INVALID_PARAMETER`, while passing `SE_REGISTRY_KEY` for
    those targets succeeds and returns a confident ancestor from the wrong
    view. A registry ancestor chain also commonly crosses keys the caller
    cannot read, and the walk happens after the descriptor is already in hand,
    so terminating the target would trade a working read-only inspection
    command for an optional column. Null is the already-defined "source
    unknown" state, so degrading introduces no new output contract.
    Normative record: [ADR 0019](../specs/decisions/0019-report-null-registry-provenance-for-wow64-views.md).

### Decision 57: Enrich directory rules over the bound connection

Normative record: [ADR 0020](../specs/decisions/0020-enrich-directory-rules-over-the-bound-connection.md).

- Choice: Resolve inherited-ACE provenance by walking the ancestor chain, and
    resolve object GUIDs to schema and control-access names, over the same
    signed and sealed connection that returned the descriptor. Match the nearest
    ancestor holding an equivalent explicit inheritable ACE, stop at a protected
    DACL or an unreadable ancestor, and degrade to a null value on failure.
- Rationale: `GetInheritanceSourceW` supports directory objects but locates its
    own domain controller and takes no credential, so it would mix a second
    authority into one result. This is the one family where provenance is
    inferred rather than reported by Windows.

### Decision 58: Discover and pin one domain controller

Normative record: [ADR 0021](../specs/decisions/0021-discover-and-pin-a-domain-controller.md).

- Choice: Make `Server` optional, locate one writable domain controller in the
    computer's domain when it is omitted, validate the discovered name with the
    explicit-name rules, and resolve it once per invocation before target
    prevalidation so every target and batch worker uses the same replica.
- Rationale: The requirement is one identified consistency point per command,
    not a hand-typed name. Supersedes only the explicit-server element of
    ADR 0015 and of Decision 40.

### Decision 59: Scope a directory rule mutation by both object GUIDs

- Choice: Let `Set`, rights removal, account purge, and clear match an explicit
    ACE on account, qualifier, `ObjectType`, and `InheritedObjectType`. An ACE
    scoped to a different GUID pair is preserved.
- Rationale: Active Directory ACEs carry object-specific meaning. Matching on
    account and qualifier alone would collapse a property-set or extended-right
    delegation into whatever common ACE the caller happened to request, silently
    widening or narrowing rights the caller never named.

### Decision 60: Expand a stored generic bit before subtracting rights

- Choice: In directory rights removal, expand a stored `GENERIC_ALL`,
    `GENERIC_WRITE`, `GENERIC_READ`, or `GENERIC_EXECUTE` bit into the specific
    rights the AD generic mapping confers, then subtract.
- Rationale: Active Directory stores generic bits verbatim and maps them at
    access-check time. Subtracting `WriteDacl` from a raw `0x10000000` mask left
    the bit set, so the command reported success while full control survived,
    and the manageability gate then confirmed the object as manageable through
    that very ACE. Verified by regression test.

### Decision 61: Refuse a directory DACL that leaves nobody able to manage it

- Choice: Every directory rule mutator rejects a candidate DACL in which no
    principal holds `WriteDacl` or `WriteOwner` on the object itself. A denied,
    inherit-only, or object-scoped grant does not count. The check warns instead
    of failing when the object was already unmanageable, and
    `Set-ADObjectSecurityDescriptor` is the explicit escape hatch.
- Rationale: `Clear` and account purge are the first operations here that can
    strip every explicit grant at once. The gate is a lockout guard for the
    common case, not a proof of recoverability: it performs no group expansion
    and does not verify that the surviving grantee still resolves.

### Decision 62: Compare against the staging read before a directory write

- Choice: Directory rule mutators pass the descriptor they staged from to the
    write boundary, which re-reads the target and refuses to persist when the
    DACL changed in between. The raw descriptor setter keeps last-writer-wins.
- Rationale: The boundary already re-read the target for its other gates but
    wrote the stale candidate anyway, so a concurrent change was silently
    reverted. This mirrors Decision 54 for the Task Scheduler family.

### Decision 63: Disclose a deny removal before the operator commits

- Choice: Count removed deny ACEs from the raw ACL delta before `ShouldProcess`,
    fold that count into the operation description, and warn again after a
    successful write. Project full rule objects only for `PassThru`.
- Rationale: `All` and `Clear` remove deny rules too, which increases effective
    access. A warning inside the `ShouldProcess` block is invisible under
    `-WhatIf` and arrives after a confirmation prompt is answered. Working from
    the raw ACEs also avoids a SID-translation round trip per ACE just to decide
    whether to print anything.

### Decision 64: Pin the backup record version to the object family

Normative record: [ADR 0016](../specs/decisions/0016-require-schema-v2-for-enterprise-targets.md).

- Choice: Make the record version a property of the object family, not of the
    caller. The five local families are version 1; SMB share and Active
    Directory are version 2. Reject a record whose family and version disagree
    in both directions, and set the envelope schema version to the highest
    record version present.
- Rationale: A caller-chosen version would let an enterprise record be replayed
    as a local target, or a local record claim server authority it never
    carried. Version 1 also keeps its original hashed field set, so extending
    the digest for version 2 cannot invalidate an existing local backup.

### Decision 65: Qualify an SMB canonical target with its owning computer

- Choice: Replace `SmbShare:Local:<SHARE>` with `SmbShare:<SERVER>:<SHARE>`,
    report `Server` on share targets, and refuse to restore a share record on a
    different computer.
- Rationale: The lock registry is process-wide, so `Local` was sufficient for
    serialization but not for portability. A record has to name the machine that
    produced it, or a restore could silently apply one server's share DACL to a
    same-named share elsewhere. ADR 0015 still keeps every SMB command local.

### Decision 66: Match a restored directory object by GUID, not by server

- Choice: Bind one explicit or discovered writable domain controller for a whole
    restore, and verify a directory record against the object's immutable
    `objectGUID` and recorded domain naming context rather than its canonical
    target.
- Rationale: The canonical target embeds the domain controller that produced the
    backup. Any writable domain controller may legitimately serve the restore,
    so server equality would reject a valid restore while GUID plus domain still
    prevents replay into another directory.

### Decision 67: Keep directory credentials out of desired state

Normative record: [ADR 0012](../specs/decisions/0012-use-object-specific-commands-and-dsc-resources.md).

- Choice: Give the SMB share and Active Directory DSC resources no credential
    property, require `AllowedBaseDistinguishedName` on every directory write,
    restrict `Sections` to `Access`, and accept an optional `ObjectGuid` that
    fails closed when a distinguished name resolves to a different object.
- Rationale: The Local Configuration Manager already binds LDAP as the node
    identity, so a credential property would only add plaintext-MOF risk. The
    allowed base makes a configuration state its own destructive boundary, and a
    distinguished name can be reused after a delete and recreate.

### Decision 68: Defer directory effective access on measured evidence

Normative record: [ADR 0022](../specs/decisions/0022-defer-active-directory-effective-access.md).

- Choice: Ship no Active Directory effective-access command, and never present a
    locally constructed Authz context or a `tokenGroups` reconstruction as a
    directory access decision.
- Rationale: Live probes measured 8 directory-computed group SIDs against 16 in
    the same principal's real logon token, 22 confidential attributes that need
    `CONTROL_ACCESS` beyond `READ_PROPERTY`, 15 property sets, 6 validated
    writes, and a domain-wide `dSHeuristics` list-object switch. The domain
    controller exposes an authoritative answer only for the bound caller.

### Decision 69: Qualify a Task Scheduler target with its owning computer

Normative record: [ADR 0023](../specs/decisions/0023-qualify-task-scheduler-identity-by-computer.md).

- Choice: Replace `TaskFolder:Local:<PATH>` with `TaskFolder:<COMPUTER>:<PATH>`,
    do the same for `ScheduledTask`, join a task path and leaf with exactly one
    separator, report `Server` on the target, and encode both families as
    schema-version-2 records that reuse `Server` and store the absolute task
    path in `Target`.
- Rationale: `Local` names no machine, so a portability record could be replayed
    against another task store. Reusing `Server` and `Target` binds the record
    to its computer without adding a hashed field, so every existing version-1
    and version-2 backup keeps validating. ADR 0018 still keeps every Task
    Scheduler command local.

### Decision 70: Compare a Task Scheduler desired state semantically

Normative records: [ADR 0012](../specs/decisions/0012-use-object-specific-commands-and-dsc-resources.md)
and Decision 42.

- Choice: Compare a Task Scheduler DSC descriptor by protection state,
    auto-inherit-required state, ACL revision, and the duplicate-sensitive ACE
    multiset instead of canonical SDDL equality, and require `AllowedRootPath`
    on every Task Scheduler resource before a write.
- Rationale: The Task Scheduler service canonicalizes ACE order after a write,
    so exact SDDL equality would report drift on every consistency run. The
    allowed root path makes a configuration state its own containment boundary
    the way the directory resources state theirs. The multiset is ordered with
    an ordinal comparer, and the sorted identities are emitted element by
    element: a leading `,` would stop PowerShell unrolling the array and turn the
    pairwise string comparison into an array comparison that always reports
    drift.

### Decision 71: Gate a suite on the Pester run result, not its failure count

- Choice: Treat a Pester suite as passing only when `Result` is `Passed`; never
    infer success from `FailedCount` alone.
- Rationale: A `BeforeAll` or `AfterAll` failure is recorded as a failed
    container, not a failed test, so a suite whose rollback verification throws
    reports `FailedCount` 0 while `Result` is `Failed`. The domain-lab
    acceptance runner and the detached suite runner both gate on `Result`,
    which is what makes a green lab run evidence that the fixture DACLs were
    restored. Verified on 2026-07-31 with a throwaway suite whose `AfterAll`
    throws.


### Decision 72: Key the private-key binding gate on the key, not the certificate

- Choice: Refuse a private-key DACL write when any HTTP.sys, WinRM HTTPS,
    Remote Desktop, or LDAPS binding uses the same private key, and decide
    sameness by comparing subject public keys rather than thumbprints.
- Rationale: The canonical write target is the key, while a binding names a
    certificate, and the relation is many-to-one. A renewal with key reuse
    (`certreq -renew` without `-newkey`, auto-enrollment configured to reuse the
    key, or an IIS renew) produces a second certificate over the same container
    while the binding still names the old thumbprint. A thumbprint comparison
    passes and the live TLS or LDAPS key is rewritten. Two certificates share a
    private key exactly when they carry the same public key, and that comparison
    needs no key handle, so it also works for a bound certificate whose private
    key cannot be opened. A bound thumbprint that resolves to no stored
    certificate throws, because its key cannot be compared.

### Decision 73: Refuse a new deny ACE and any non-plain ACE on a private key

- Choice: Reject a candidate private-key DACL that adds a deny ACE the stored
    DACL does not already contain, and reject any ACE whose type is not plain
    `AccessAllowed` or `AccessDenied`. `Add-CertificatePrivateKeyAccessRule`
    therefore exposes no `AccessControlType`.
- Rationale: A per-account preservation gate cannot see either bypass, and both
    were proven against the built module. A deny ACE naming `WD` or `AU` denies
    SYSTEM and Administrators through group membership while the literal-SID
    grant check still passes. A callback ACE parses with an `AccessAllowed`
    qualifier and satisfies a required grant, yet grants nothing when its
    condition evaluates false. Enumerating every group that could contain a
    recovery identity is not decidable, so the class is removed instead of
    filtered. Removing a deny ACE that already exists stays supported, because
    that direction can only widen access.

### Decision 74: Compare a private-key ACE by type and payload, not by qualifier

- Choice: Build the ACE comparison key from the security identifier, ACE type,
    generic-expanded mask, ACE flags, a digest of any conditional payload, and
    any object ACE scope, and give a custom ACE a key over its exact bytes.
- Rationale: `AceQualifier` maps `AccessAllowedCallback` onto `AccessAllowed`,
    so a qualifier-based key equated a conditional DACL with its plain
    equivalent. That defect made three things unsound at once: reasserting the
    plain DACL over a conditional one was a silent no-op, write verification
    accepted a stored DACL of a different ACE type, and rollback verification
    accepted a restored DACL of a different ACE type.

### Decision 75: Tag the GitHub release before the Gallery publish

- Choice: The `publish` workflow runs `Publish_Release_To_GitHub` first and
    `Publish_Module_To_Gallery` second, and the pipeline fails before either
    when the `GitHubToken` or the `GalleryApiToken` secret is missing. The job
    runs only on the upstream repository, only for the default branch or a
    stable `v*` tag, and is never cancelled by a newer run.
- Rationale: Both Sampler release tasks skip themselves on an empty token, so a
    missing `GitHubToken` alone would still ship a version to the Gallery
    without the `v*` tag GitVersion anchors the next pre-release number on. The
    following build would then recompute an already-published version and the
    Gallery would reject it with HTTP 409. Failing on the missing secret, and
    creating the tag before the package leaves, keeps the two in step.

### Decision 76: Complete argument values from a class in the module

- Choice: Argument completion is a PowerShell class in `source/Classes` that
    implements `System.Management.Automation.IArgumentCompleter`, carries its own
    data, and is named in an `[ArgumentCompleter([Type])]` attribute. A completer
    never calls a command that compiles interop or touches a target.
- Rationale: A probe in both editions showed the class form completing from a
    script module in Windows PowerShell 5.1 and PowerShell 7, and the module
    resolves the type itself, so nothing has to be exported or registered in the
    caller's session. Completion answers a keystroke: `Add-Type` in
    `Initialize-WindowsAccessControlNativeType` would put a compile behind the
    Tab key, and typed text is escaped as a literal so an unbalanced bracket
    cannot throw a wildcard error mid-keystroke.

### Decision 77: Build an NTFS rule through a mask-range helper

- Choice: `New-NTFSFileSystemRule` builds every NTFS access and audit rule. It
    uses the public `FileSystemAccessRule` or `FileSystemAuditRule` constructor
    for a mask the enum can name and the `AccessRuleFactory` or
    `AuditRuleFactory` overload for one it cannot. `-AccessRights` carries
    `WindowsAccessRightsTransformAttribute`, a class-based argument
    transformation over `Enum::ToObject`, so a raw mask binds while the enum
    type and its name validation stay.
- Rationale: The public constructors throw for any mask outside `FullControl`,
    which is exactly the `GENERIC_*` case the predecessor module could report
    and never remove. The factory takes the mask verbatim, and confining the
    factory to out-of-range masks preserves the framework's `Synchronize`
    normalization for every existing call. Reference a class attribute by its
    full class name: the engine's implicit `Attribute` suffix search does not
    reach a PowerShell class type.

### Decision 78: Refuse a path that does not name one canonical target

- Choice: `Resolve-NTFSPath` refuses a Win32 device-namespace path (`\\?\`,
    `\\.\`) and a bare drive specification such as `C:`, each with its own
    terminating error naming the replacement. A universal naming convention path
    stays supported.
- Rationale: Both resolved to something other than what the caller wrote. The
    device namespace bypasses normalization, so the resolved name is not a
    canonical target key for batch serialization, backup records, or desired
    state, and a misbinding is reported to have destroyed a system. `C:` resolves
    to the current location of that drive, so a command meant for a volume
    silently addressed a directory inside it. See ADR 0029.

### Decision 79: Address the object the caller named, per object family

- Choice: A file system junction, symbolic link, and volume mount point are
    addressed as themselves; a registry symbolic link is followed to its target.
    No command walks a directory tree, so a target set is the supplied targets
    plus one level of wildcard expansion.
- Rationale: Measured in both editions, a file system link carries its own
    descriptor and `Get-Acl`, `Set-Acl`, `icacls`, and `icacls /L` all agree; the
    registry has no managed API that opens a link without following it. Not
    expanding a target set is what makes a reparse-point cycle unreachable. See
    ADR 0030, ADR 0031, and ADR 0032.
