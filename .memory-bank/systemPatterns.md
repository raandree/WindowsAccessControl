---
status: current
last-verified: 2026-07-27
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
    contracts; comment-based help owns exhaustive per-command detail.
- Rationale: The design remains reviewable without duplicating parameter
    reference that belongs next to implementation.

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
