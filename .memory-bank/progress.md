---
status: current
last-verified: 2026-07-29
owner: active-agent
source: repository evidence
---

# Progress

## Current status

The local NTFS, registry, service/SCM, process, SMB-share, Task Scheduler, and
bounded Active Directory command families are complete for their accepted
increments. Bounded execution, canonical write serialization, metrics, exact
DSC resources for the original five families, unattended domain-lab evidence,
and read-only CNG private-key inspection are independently reviewed. OI-11 and
ENT-8 are closed for the currently shipped enterprise families.

## Recent milestones

- Canonical Memory Bank base initialized.
- 2026-07-25: Implemented 27 pipeline-first NTFS permission commands on Sampler.
- 2026-07-25: Passed 228 tests on PowerShell 7 and Windows PowerShell 5.1 with
    84.41 percent coverage and an enforced 80 percent gate.
- 2026-07-25: Resolved every independent review Blocker, Major, and Minor
    finding; focused re-review returned APPROVE.
- 2026-07-25: Created the green local feature commit; no remote push was
    requested or performed.
- 2026-07-25: Audited all exports and recorded 50 direct behavior
    specifications across 28 commands.
- 2026-07-25: Scanned NTFSSecurity and adopted multi-account additions,
    explicit-rule cleanup while enabling inheritance, and token privilege
    inventory without adopting AlphaFS or implicit privilege escalation.
- 2026-07-25: Added six privilege-gated live acceptance specifications for
    SACL workflows and arbitrary-owner assignment.
- 2026-07-25: Passed final Unit and Integration behavior suites in PowerShell 7
    and Windows PowerShell 5.1 with 67 passed, zero failed, and six explicit
    privilege skips per edition.
- 2026-07-25: Built and inspected `NTFSPermission.0.1.0.nupkg`; final AST,
    analyzer, manifest, format, changelog, and Memory Bank gates passed.
- 2026-07-25: Prepared the approved, green follow-up as a local feature commit;
    no remote push was requested or performed.
- 2026-07-25: Migrated the test-count matrix into a Vivarium-style normative
    `specs/` tree with numbered contracts, stable requirement IDs, MADR records,
    open issues, and Pester conformance enforcement.
- 2026-07-25: Passed the complete QA folder with 181 tests. Eight specification
    checks enforce structure, status, requirement identity, traceability,
    exports, local links, curated format views, and ADR indexing.
- 2026-07-25: Closed the privileged NTFS release gate with seven live
    acceptance scenarios, zero failures, and zero skips; added SACL-only copy
    preservation evidence and fixed PowerShell 7 SACL protection persistence.
- 2026-07-25: Accepted the signed `WindowsAccessControl` expansion design and
    six governing ADRs after a 50-question consolidated Grill-Me interview,
    primary Microsoft-source research, and a successful three-family API probe.
- 2026-07-25: Hard-renamed the unpublished package to
    `WindowsAccessControl`, preserved its GUID, fixed elevated-owner test
    assumptions, and passed 259 tests in each supported PowerShell edition with
    86.72 percent PowerShell 7 coverage.
- 2026-07-25: Implemented and hardened the shared named/handle descriptor
    engine, process identity pinning, NTFSSecurity-style SID conversion,
    cross-edition rights enums, and scoped automatic privileges; passed 277
    PowerShell 7 tests at 87.4 percent coverage and 15 focused 5.1 tests.
- 2026-07-25: Added 15 local registry-key commands for descriptor, access,
    audit, and inheritance workflows with explicit registry views, curated
    formatting, local-only target validation, and section-scoped persistence.
- 2026-07-25: Passed 399 PowerShell 7 tests at 86.13 percent coverage and a
    31-test Windows PowerShell 5.1 registry/contract gate with zero failures or
    skips; verified scratch cleanup and privilege restoration.
- 2026-07-25: Added 12 local service/SCM commands for selected descriptors and
    typed access/audit rule CRUD, including explicit SCM targeting and
    cross-edition `ServiceController` pipeline support.
- 2026-07-25: Passed 497 PowerShell 7 tests at 85.02 percent coverage and 25
    Windows PowerShell 5.1 service/contract tests with zero failures or skips;
    verified no `WacTest*` service leaks and restored privilege state.
- 2026-07-26: Added 12 pinned live-process commands for selected descriptors
    and typed access/audit rule CRUD over PID, `Process`, module-output, and
    caller-owned handle targets.
- 2026-07-26: Passed 596 PowerShell 7 tests at 84.21 percent coverage and 26
    Windows PowerShell 5.1 process/contract tests with zero failures or skips;
    verified exact privilege-state restoration and zero controlled-child leaks.
- 2026-07-26: Completed independent process security review with no Blocker or
    Major findings and an explicit APPROVE verdict.
- 2026-07-26: Added unified descriptor backup and restore across filesystem,
    registry, service/SCM, and pinned process targets with deterministic SHA-256
    records and optional RSA X.509 signing and verification.
- 2026-07-26: Hardened portability with all-record prevalidation, atomic backup
    replacement, explicit absent-SACL encoding, historical NTFS compatibility,
    duplicate-target rejection, and adversarial signature/downgrade coverage.
- 2026-07-26: Passed 629 PowerShell 7 tests at 85.39 percent coverage and 76
    focused Windows PowerShell 5.1 tests with zero failures or skips; verified 69
    exports, exact privilege restoration, and zero scratch-resource leaks.
- 2026-07-26: Completed independent portability security re-review with no
    Blocker or Major findings and an explicit APPROVE verdict.
- 2026-07-26: Added bounded target-array execution across filesystem, registry,
    service/SCM, and pinned process commands with canonical deduplication,
    isolated worker modules, and application-domain same-target locks.
- 2026-07-26: Added redacted aggregate metrics as the 70th export and bounded
    aggregate NTFS backup reads followed by one atomic envelope write.
- 2026-07-26: Added deterministic dispatcher, live NTFS mutation/`WhatIf`,
    cross-module lock, cross-edition single-target, and parallel error-stream
    regression coverage plus a repeatable NTFS throughput benchmark.
- 2026-07-26: Passed 670 PowerShell 7 tests at 86.35 percent coverage and 37
    focused Windows PowerShell 5.1 tests with zero failures or skips; static,
    parse, encoding, and whitespace gates are clean.
- 2026-07-26: Completed two independent concurrency reviews with no Blocker or
    Major findings and explicit APPROVE verdicts.
- 2026-07-26: Added five class-based exact selected-section DSC resources for
    NTFS, registry keys, named services, SCM, and pinned processes with
    prefixed reasons and object-specific composite keys.
- 2026-07-26: Added fail-closed selected-section validation, canonical
    comparison that excludes only system-derived auto-inherited flags, combined
    DACL/SACL protection coverage, and explicit absent-SACL convergence.
- 2026-07-26: Passed 716 PowerShell 7 tests at 86.69 percent coverage, 31
    focused Windows PowerShell 5.1 exact-resource tests, and two Desktop LCM
    compile/invoke tests with zero failures or skips.
- 2026-07-26: Completed independent exact-resource review and re-review with no
    remaining Blocker, Major, or Minor findings and an explicit APPROVE verdict.
- 2026-07-26: Added five class-based exact access-rule presence DSC resources
    with typed composite keys, SID-normalized matching, `Present`/`Absent`
    convergence, duplicate exact-ACE cleanup, and unsigned rights handling.
- 2026-07-26: Added five-family live convergence with unrelated-rule
    preservation and SCM/process rollback; Desktop LCM now compiles all ten
    resources and invokes NTFS descriptor and rule resources.
- 2026-07-26: Passed 766 PowerShell 7 tests at 87.59 percent coverage, 35
    focused Windows PowerShell 5.1 rule-resource tests, and three Desktop LCM
    tests with zero failures or skips.
- 2026-07-26: Completed independent rule-resource review and re-review with no
    remaining Blocker, Major, or Minor findings and an explicit APPROVE verdict.
- 2026-07-26: Added explicit local-only credential impersonation with secure
    password marshaling, managed identity restoration, and safe-token cleanup.
- 2026-07-26: Passed argument, nested-scope, exception, and invalid-credential
    impersonation acceptance in both PowerShell editions with zero failures or
    skips.
- 2026-07-26: Constrained the NTFS and registry DSC `AppliesTo` key properties
    with a `ValidateSet` matching the cmdlet surface and added a contract test
    that keeps them in sync; `Get-DscResource -Syntax` now advertises the
    allowed values. Full PowerShell 7 gate passed 781 tests at 87.47 percent
    coverage, with the only failures in an untracked pre-rename stale test file.
- 2026-07-26: Extended the NTFS `AppliesTo` vocabulary with the three
    inherit-only single-level values (`SubfoldersAndFilesOnlyOneLevel`,
    `SubfoldersOnlyOneLevel`, `FilesOnlyOneLevel`) across both converters, the
    eight NTFS cmdlets, and the DSC resource, matching full NTFSSecurity
    `ApplyTo` coverage. Added a converter round-trip test. Full PowerShell 7
    gate passed 797 tests at 88.06 percent coverage, with the only failures in
    the untracked pre-rename stale test file.
- 2026-07-26: Removed the two untracked pre-rename stale files
    (`Initialize-NTFSNativeType.ps1`, `Elevated-NTFSPermission.Tests.ps1`) with
    explicit approval. The full PowerShell 7 gate is now fully green at 797
    passed, 0 failed, 0 skipped, 88.06 percent coverage.
- 2026-07-26: Closed the release with 779 PowerShell 7 tests at 87.53 percent
    coverage and a 450-test Windows PowerShell 5.1 QA/impersonation gate, all
    with zero failures or skips.
- 2026-07-26: Built and inspected
    `WindowsAccessControl.0.2.0-windows.nupkg`; verified 71 functions, ten DSC
    resources, eight expected archive entries, and no source/test or
    secret-like artifacts.
- 2026-07-26: Completed independent impersonation security review and
    re-review with no Blocker or Major findings and explicit APPROVE verdicts.
- 2026-07-26: Reproduced six Windows PowerShell 5.1 exact-descriptor DSC
    failures under Pester's experimental profiler-tracer coverage, restored
    breakpoint coverage, and passed 770 Desktop tests at 87.79 percent coverage
    plus 797 PowerShell 7 tests at 88.19 percent coverage with zero failures or
    skips.
- 2026-07-27: Closed OI-3 by adding `InheritedFrom` to NTFS access-rule output
    through `GetInheritanceSourceW`, including original-ancestor resolution,
    native allocation cleanup, managed/native ACE alignment, and explicit-only
    fast-path behavior.
- 2026-07-27: Passed eight focused tests in both PowerShell editions, eight
    specification QA tests, and a privilege-compatible Sampler gate with 714
    passing tests, zero failures, and one skip. Independent re-review returned
    APPROVE with no Blocker or Major findings.
- 2026-07-27: Added a Draft design contract for OI-5 in-memory descriptor
    mutation (`specs/0007`), indexed it in the specification README, linked it
    from the OI-5 register, and recorded that the live-process family is
    excluded because ADR 0022 pins one handle per operation. Specification
    conformance passed eight tests.
- 2026-07-27: Passed the complete elevated cross-edition release gate at 803
    tests, 0 failed, 0 skipped, and 88.21 percent coverage over the 80 percent
    threshold, with every previously-skipped privileged SACL, service, owner,
    and elevated-acceptance scenario executed. Fast-forwarded `main` to the
    OI-3 and OI-5 commits locally; no remote push was performed.
- 2026-07-28: Added Draft specification 0008 for domain-lab-gated Task
    Scheduler, certificate private-key, SMB-share, and Active Directory access
    control; indexed ADR 0014 and open issues OI-6 through OI-10. Specification
    conformance passed eight tests.
- 2026-07-28: Delivered OI-5 phase 1: `Set-NTFSItemSecurityDescriptor` persists
    an edited filesystem descriptor with one write, and `Add-NTFSAccessRule`
    stages an access rule on a `SecurityDescriptor` object in memory without
    writing. Resolved the five OI-5 design questions in `specs/0007`. Focused
    unit, live round-trip, and `WhatIf` tests pass; analyzer clean.
- 2026-07-28: Replaced the Azure Pipelines definition with a read-only GitHub
    Actions workflow that builds one full-history Sampler artifact and tests it
    on Windows with PowerShell 7 and Windows PowerShell 5.1. Updated GitVersion
    branch rules from `master` to `main`.
- 2026-07-28: Added a task-oriented usage guide covering common NTFS,
    registry, service/SCM, process, backup/restore, diagnostics, batching,
    impersonation, remote-session, and DSC workflows. Verified 41 PowerShell
    examples and complete help/catalog coverage for all 72 packaged commands.
    The generated package exports `Set-NTFSItemSecurityDescriptor`, but the
    static source manifest export list still omits it.
- 2026-07-28: Began `ENT-1` with a secret-free domain-lab inventory covering
    one writable domain controller, one member server, one management host,
    supported PowerShell editions, role capabilities, and unresolved safety
    and transport gates.
- 2026-07-28: Passed read-only `AD-1` baseline probes in PowerShell 7.6.3 and
    Windows PowerShell 5.1 using explicit writable-domain-controller selection,
    Negotiate authentication, LDAP signing and sealing, RootDSE discovery, and
    binary domain-descriptor parsing. No directory object was modified.
- 2026-07-28: Implemented the `ENT-2` test-only domain-lab harness with marked,
    idempotent OU, identity, group, SMB-share, task-folder, and software CNG-key
    fixtures plus read-only status, `ShouldProcess`, recovery verification, and
    compensating cleanup.
- 2026-07-28: Passed five focused unit tests and four explicit live lifecycle
    tests. Setup creates no resources on its second pass and repairs either a
    missing key or a missing selector; teardown removes every fixture, deletes
    the CNG private key, reports already absent on its second pass, and restores
    a final ready fixture set.
- 2026-07-28: Reproduced and fixed certificate-only CNG key leakage, removed
    three attributable orphan keys from the red cycles, and preserved the final
    deterministic key. Cross-edition parsing and focused PSScriptAnalyzer are
    clean.
- 2026-07-28: The complete Sampler profile passed 818 tests at 88.01 percent
    coverage and failed three pre-existing local-impersonation scenarios because
    the domain-controller test host denies interactive logon to the disposable
    ordinary accounts. The harness tests, QA, and all other tests passed.
- 2026-07-28: Complete repository QA passed 449 tests with zero failures or
    skips. Independent destructive-boundary review and final certificate-path
    re-review returned APPROVE with no unresolved Blocker or Major findings.
- 2026-07-28: Accepted specification 0009 and ADRs 0015/0016, then added five
    local SMB-share and five explicit-domain-controller Active Directory DACL
    commands. The source and generated manifests now export 82 functions.
- 2026-07-28: Passed delegated live acceptance for all four SMB scenarios and
    all five Active Directory scenarios in both supported PowerShell editions.
    Independent security re-review returned APPROVE with no unresolved Blocker
    or Major findings.
- 2026-07-28: Passed complete repository QA at 509 tests and the configured
    Sampler profile at 900 of 903 tests with 81.44 percent coverage. The three
    failures are the existing domain-controller interactive-logon policy cases;
    every enterprise test passed. Built and inspected the eight-entry local
    package with 82 exports and no source, test, lab-identity, or key artifacts.
- 2026-07-28: Closed OI-4 by rejecting UNC effective-access targets and
    deferring remote or combined SMB-plus-NTFS claims under ADR 0017.
- 2026-07-28: Accepted and implemented Task Scheduler folder/task DACL get/set,
    SMB share-only effective access, bounded NTFS callback editing, and
    read-only Microsoft Software KSP RSA-key descriptor inspection.
- 2026-07-28: Added the strict unattended five-suite domain-lab runner. The live
    profile passed 18 tests with five ready cleanup checks and no failures or
    skips; final domain and member readiness is clean.
- 2026-07-28: Closed OI-11/ENT-8. Final Core runs 992 of 995 tests successfully
    at 80.4561 percent coverage; final Desktop runs 965 of 968 successfully at
    80.0226 percent. The only failures are three exact domain-controller
    interactive-logon policy cases, and the same four-test file passes 4 of 4
    on the domain member in both editions.
- 2026-07-28: Built and inspected the eight-entry 89-export package. Both
    editions import all 89 commands; archive hygiene is clean; package SHA-256
    is `A702E507470676DF4784C2B9442D16DC036DB230552E438B0C8CAFA724312F67`.
- 2026-07-29: Closed OI-21 by adding `SecurityDescriptor` parameter sets to the
    remaining NTFS access, audit, owner, and inheritance mutators, and closed
    OI-13 by extending the same model to the registry-key family with
    `Edit-RegistryKeySecurityDescriptor` as the 90th export. Added opt-in
    `RequireUnchanged` optimistic concurrency over a read-time SHA-256
    `ConcurrencyToken`.
- 2026-07-29: Replaced the latent section-widening path in `Add-NTFSAccessRule`
    with a fail-closed unloaded-section gate, and stopped requesting NTFS ACL
    protection for an absent ACL so an `Access, Audit` persist on a SACL-less
    item can no longer fail after the DACL was written.
- 2026-07-29: Made `SecurityDescriptor` the default parameter set on nine
    registry commands after proving empirically that a piped descriptor
    otherwise binds to the untyped `Path` and fails in path resolution.
- 2026-07-29: Passed the full Sampler profile at 1084 of 1087 tests and 80.91
    percent coverage with zero skips. The only failures are the pre-existing
    domain-controller interactive-logon policy cases. Static analysis over
    source and tests is clean.
- 2026-07-29: Completed independent security review and focused re-review. Two
    Major findings (post-commit protection failure, stale NTFS descriptor
    projection) were fixed; the re-review returned APPROVE and the remaining
    Minor and Nit findings were closed.
- 2026-07-29: Closed OI-19 by adding six typed Task Scheduler access-rule
    commands as exports 91 through 96, backed by separate
    `WindowsTaskFolderRights` and `WindowsScheduledTaskRights` models and a
    seven-value folder `AppliesTo` scope. The rights model, ACL-revision
    behavior, and service-token group set were established by live probes, not
    assumed.
- 2026-07-29: Added three fail-closed Task Scheduler write gates: reject a
    candidate that newly denies the service token, reject object and compound
    ACEs that the store re-revisions from ACL revision 2 to 4, and reject a
    staged write whose target changed after the read. Rollback is now verified.
- 2026-07-29: Independent security review returned REQUEST CHANGES with three
    Major findings; all three were fixed (flags-blind duplicate suppression,
    one shared rights enum that understated a folder grant, missing optimistic
    concurrency). Every Minor and Nit finding was closed except the registry
    parity gap, recorded as OI-25. The focused re-review returned APPROVE.
- 2026-07-29: Traced two intermittently failing in-memory descriptor editing
    tests to `Invoke-WindowsAccessControlBatch` downgrading a downstream
    terminating error to a non-terminating one on its sequential path. Two
    source-stash bisects reproduce the failure on unmodified `HEAD` source, so
    the defect predates this increment; it is recorded as OI-26.
- 2026-07-29: Closed OI-26 by buffering each target's worker output and
    emitting it after the dispatcher's `try`/`catch` on both the sequential and
    parallel paths, after a probe proved a downstream terminating error is
    indistinguishable from a worker failure by exception type, error ID,
    activity, or invocation info. Added sequential and parallel propagation
    regression tests; both previously failing integration tests pass again.
- 2026-07-29: Added native `InheritedFrom` provenance to registry-key access
    rules. `GetFileSystemAccessRuleInheritanceSources` was refactored into a
    shared native helper with a registry entry point that uses `SE_REGISTRY_KEY`
    and the registry generic mapping. A live probe proved Windows rejects the
    WOW64 registry-view object types with `ERROR_INVALID_PARAMETER`, so those
    views report a null source instead of an ancestor resolved against the
    wrong view. Recorded as ADR 0019.
- 2026-07-29: Independent security review of the registry provenance change
    returned APPROVE WITH COMMENTS with one Major finding. Every Major and Minor
    finding was fixed: provenance now degrades to null with a non-terminating
    error instead of discarding a successful descriptor read, the native entry
    point rejects unsupported object types, and the hive translator fails closed
    on an unrecognized native form.
- 2026-07-29: Added `InheritedFrom`, `ObjectTypeName`, and
    `InheritedObjectTypeName` to Active Directory access rules and made `Server`
    optional on the four directory commands that take it. A live probe proved
    `GetInheritanceSourceW` supports `SE_DS_OBJECT` but rejects a
    server-qualified name and locates its own domain controller, so provenance
    is inferred by walking the ancestor chain over the bound connection. The
    inference agrees with that native oracle on all 26 inherited ACEs of the lab
    user. Recorded as ADR 0020 and ADR 0021.
- 2026-07-29: Independent security review of the directory enrichment returned
    APPROVE WITH COMMENTS with no Blocker and one Major finding. Discovery ran
    once per pipeline item instead of once per invocation and now memoizes the
    pinned name; the ancestor walk stops at a protected DACL, requires candidate
    propagation flags to be consistent with the observed inherited ACE, and no
    longer caches an identity-dependent unresolved GUID. Windows PowerShell
    resolves parameter type attributes before a function body runs, so the
    directory assembly is now loaded at module import.

## Stable capabilities

- Access and audit rule construction, query, mutation, filtering, and clearing.
- Owner, inheritance, identity, privilege, and Authz effective-access workflows.
- Structured token privilege inventory and deduplicated multi-account additions.
- Optional explicit-rule removal while enabling access or audit inheritance.
- Selected-section descriptor copy and versioned JSON backup or restore.
- Reproducible Sampler build plus a two-edition GitHub Actions test matrix.
- Normative numbered specifications with requirement-to-test traceability and
    immutable accepted ADRs.
- Local registry-key descriptor, access-rule, audit-rule, and inheritance
    workflows across the default, 32-bit, and 64-bit registry views.
- Local named-service and explicit Service Control Manager descriptor and
    typed rule workflows without inheritance semantics.
- Pinned live-process descriptor and typed rule workflows with PID-reuse
    protection and caller-owned handle support.
- Unified schema-versioned descriptor backup and restore with section-scoped
    cross-family dispatch, SHA-256 integrity, optional X.509 authenticity, and
    atomic file replacement.
- Bounded target-array execution with canonical deduplication, process-wide
    same-target write serialization, deterministic sequential mode, and
    redacted in-process metrics.
- Exact selected-section DSC resources for every current target family,
    including Desktop MOF compilation and SYSTEM LCM invocation evidence.
- Exact access-rule presence DSC resources for every current target family,
    including duplicate cleanup, live rollback, and SYSTEM LCM invocation.
- Native inherited NTFS access-rule provenance without heuristic parent-ACL
    comparison.
- Local SMB-share DACL mutation and bounded share-only SID-derived effective
    access with explicit backing-NTFS exclusion.
- Signed/sealed Active Directory DACL mutation against an explicit or
    discovered and pinned domain controller, with complete-batch prevalidation,
    immutable object identity, inferred inherited-ACE provenance, and resolved
    schema and control-access GUID names.
- Local Task Scheduler folder and registered-task DACL descriptor get/set plus
    typed access-rule query, add, and exact removal with object-specific rights,
    folder inheritance scope, containment, service-token lockout rejection,
    object-ACE rejection, staged-write concurrency rejection, semantic
    verification, and verified rollback.
- Bounded NTFS callback editing with deterministic sequential callbacks and one
    read/at-most-one-write per target.
- Read-only DACL inspection of exact persisted RSA CNG keys without private-key
    export.
- Strict unattended domain-lab acceptance with fixed ordering, redacted atomic
    evidence, no-skip/nonzero gates, and cleanup readiness after every suite.
- Detached descriptor editing across the filesystem and registry-key families
    with fail-closed unloaded-section rejection, in-place projection refresh,
    bounded editing scopes, and opt-in optimistic concurrency.

## Open work

- OI-14, OI-16, and OI-17 add SMB/AD portability, desired state, broader
    mutation, and an AD effective-access decision.
- OI-18 requires a second writable domain controller for replication and
    failover evidence.
- OI-20 adds Task Scheduler portability and desired state.
- OI-22 through OI-24 add fail-closed CNG mutation, separate CAPI support, and
    private-key portability/desired state after their security gates.
- OI-25 extends inheritance-sensitive duplicate detection to the registry-key
    family.
- Remote publication remains user-controlled.
