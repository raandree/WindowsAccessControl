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
and fail-closed CNG private-key mutation are independently reviewed. OI-11,
ENT-8, OI-18, OI-22, and OI-23 are closed. The 80 percent coverage gate is
currently unmet at 78.61 percent; ADR 0025 keeps the threshold and tracks the
measurement fix as OI-27.

## Recent milestones

- 2026-08-01: Closed OI-22 after the full review convention. One feature review
    and three fix rounds, each with its own scoped re-review, ended at APPROVE
    WITH MINOR FINDINGS with no Blocker and no Major; the remaining Minor and
    Nit findings were fixed too. The rounds found a dead LDAPS gate on every
    domain controller, a machine-wide write denial from one unresolvable bound
    thumbprint, a revocation that reported success without revoking, a
    preservation gate that refused an exact reassert, and a native enumeration
    that could not tell completion from failure. Two review claims were refuted
    with read-only probes and one finding was parked with a written ruling.
    Evidence: 1242 unit and QA tests passing against a 1220 baseline, a clean
    analyzer run over every changed file, and the six-suite lab acceptance green.
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
- 2026-07-30: Closed OI-25 by opting `Add-RegistryKeyAccessRule` and
    `Add-RegistryKeyAuditRule` into inheritance-scope-sensitive duplicate
    detection on both the descriptor-staging and path-write paths. `Set` and
    `Clear` stay scope-blind; specification 0003 records the asymmetry as
    deliberate.
- 2026-07-30: Closed OI-16 by adding `Set-ADObjectAccessRule`,
    `Clear-ADObjectAccessRule`, and `Exact`/`Rights`/`All` removal modes on a
    distinguished-name parameter set for `Remove-ADObjectAccessRule`. Every mode
    matches on account, qualifier, and both object GUIDs, so an object ACE is
    never flattened into a common ACE.
- 2026-07-30: Added a fail-closed manageability gate that rejects a candidate
    DACL granting no principal `WriteDacl` or `WriteOwner` on the object itself,
    and a write-boundary staleness check that rejects a staged descriptor whose
    target changed after the read. `Set-ADObjectSecurityDescriptor` remains the
    explicit escape hatch and keeps last-writer-wins.
- 2026-07-30: Rights removal expands a stored native `GENERIC_*` bit into the
    rights it confers before subtracting, after a review proved that subtracting
    from the raw bit silently retained the grant while the gate then reported the
    object as manageable through that very ACE.
- 2026-07-30: Two independent security reviews ran. The first returned REQUEST
    CHANGES with four Major findings (deny purge discarding a bound
    `AccessControlType`, generic-bit subtraction, lost update, and a piped rule
    binding to the destructive parameter set); all four plus every Minor and Nit
    were fixed. The re-review returned APPROVE WITH COMMENTS and its six
    follow-up Minor/Nit findings were fixed too.
- 2026-07-30: A destructive lab test locked the shared `OU=Targets` fixture out
    of its own restore path by writing a protected DACL through the raw setter.
    The OU was repaired by re-enabling inheritance and restoring the nine default
    `organizationalUnit` explicit ACEs from its parent, and both gate tests now
    use a disposable child OU that always retains an admin grant.
- 2026-07-30: Final PowerShell 7 gate passed 1236 of 1239 tests with zero skips;
    the only failures are the pre-existing domain-controller interactive-logon
    policy cases. The live domain lab passed 10 of 10 Active Directory scenarios
    and was left clean with no leaked organizational units.
- 2026-07-30: Closed OI-14 and OI-17 with specification 0013. SMB share
    canonical targets and write-lock keys are now qualified by the owning
    computer (`SmbShare:<SERVER>:<SHARE>`), and both enterprise families entered
    unified backup and restore as schema-version-2 records that bind server
    authority plus immutable share or directory identity. Record version is a
    property of the object family, so a family/version mismatch is rejected in
    both directions and the pinned version-1 digest keeps existing local backups
    valid.
- 2026-07-30: Added `Server`, `AllowedBaseDistinguishedName`, `Credential`, and
    `TimeoutSeconds` to `Restore-WindowsSecurityDescriptor`. An SMB record
    restores only on the computer it names; a directory record is resolved for
    write during preparation and restored through one pinned writable domain
    controller matched by `objectGUID` and domain naming context.
- 2026-07-30: Added four class-based DSC resources for SMB share and Active
    Directory descriptors and access rules. Directory resources require an
    allowed organizational unit, manage the access section only, take no
    credential, pin one domain controller per `Set()`, and re-assert an optional
    `ObjectGuid` before the write.
- 2026-07-30: Closed AD-7 with ADR 0022 after read-only probes measured the gap:
    8 directory-computed group SIDs against 16 in the same principal's live logon
    token, 22 confidential attributes, 15 property sets, 6 validated writes, and
    a domain-wide `dSHeuristics` list-object switch. The domain controller
    exposes an authoritative answer only for the bound caller.
- 2026-07-30: Independent security review returned three Major findings
    (directory deduplication keyed on the server-qualified canonical target, an
    unprevalidated directory write boundary, and an object-GUID pin enforced only
    in `Get()`). All three plus every Minor were fixed and covered by new
    regression tests.
- 2026-07-30: Final non-lab gate passed 1268 of 1271 tests with zero skips; the
    only failures remain the domain-controller interactive-logon policy cases.
    The unattended domain-lab profile passed all five suites at 29 of 29 tests
    with zero skips and both boundaries ready.
- 2026-07-30: Closed the cross-edition gate for the increment. A focused Windows
    PowerShell 5.1 run passed 103 of 103 tests with zero skips over the
    portability, DSC contract, DSC adapter, and SMB target suites, so the new
    `[guid]::TryParse` reference calls, enum casts, and class-based resources
    hold on Desktop. The built artifact carries 98 exports, 14 DSC resources,
    five files, and no test, source, or secret-like content.
- 2026-07-30: `build.ps1 -Tasks pack` cannot complete in this checkout.
    `Microsoft.PowerShell.PSResourceGet` fails to load `NuGet.Packaging`
    6.7.0.127, and that assembly is genuinely absent from the restored module in
    `output/RequiredModules`. The module build itself succeeds; this is a
    dependency-restore gap in the environment, not a product defect, and it
    predates this increment.
- 2026-07-30: Closed OI-20 with specification 0014 and ADR 0023. Task Scheduler
    canonical targets and write-lock keys are now qualified by the owning
    computer (`TaskFolder:<COMPUTER>:<PATH>`), and both families entered unified
    backup and restore as schema-version-2 records. The records reuse the
    existing hashed `Server` field and store the absolute task path in `Target`,
    so no hashed field was added and every existing version-1 and version-2
    backup still validates.
- 2026-07-30: Added `AllowedRootPath` to `Restore-WindowsSecurityDescriptor`. A
    task record restores only on the computer it names, every target is resolved
    for write during preparation, and the write passes through the public
    setters and their specification 0010 gates.
- 2026-07-30: Added four class-based DSC resources for task folder and
    registered-task descriptors and access rules. They manage the access section
    only, require `AllowedRootPath`, and compare DACLs by protection state and
    ACE multiset because the Task Scheduler service canonicalizes ACE order after
    a write.
- 2026-07-30: Independent security review returned APPROVE WITH COMMENTS with no
    Blocker and three Major findings: specification 0014 claimed a staleness gate
    the descriptor write path does not have, ADR 0023 asserted a root-folder task
    form the path normalizer makes unreachable, and the ACE-order limitation was
    documented on the cmdlets but not on the new resources. All three plus every
    Minor were fixed, including ordinal path comparison, rejection of a
    whitespace-only task name, an explicit rejection of a registered-task record
    that names the root folder, and ordinal ACE-multiset ordering.
- 2026-07-30: A focused Windows PowerShell 5.1 run passed 149 of 149 tests with
    zero skips over the portability, DSC contract, DSC adapter, and Task
    Scheduler suites. Static analysis over source and tests is clean apart from
    pre-existing warnings in the Sampler-provided `tests/QA/module.tests.ps1`.
- 2026-07-30: The gate run after the review fixes caught a self-inflicted
    regression. Adopting ordinal ACE-multiset ordering in
    `Test-WindowsTaskSchedulerDaclEquivalent` ended the sorting script block with
    `, $identities`, which stopped PowerShell unrolling the array, so
    `@(& $block ...)` produced one element wrapping the whole array and the
    pairwise comparison compared two arrays instead of two strings. Every
    equivalent DACL then reported drift. Removing the comma restored
    element-by-element output and kept the ordinal sort; the pre-existing
    reordered-ACE test is what caught it.
- 2026-07-30: Final gate passed 1309 of 1312 tests with zero skips. The only
    failures remain the three domain-controller interactive-logon policy cases.
    A focused Windows PowerShell 5.1 run passed 161 of 161 tests with zero skips.
- 2026-07-30: Measured the coverage gate. The configured profile reports 79.61
    percent against an 80 percent threshold. The shortfall is pre-existing: the
    new Task Scheduler code measures about 97 percent covered and excluding it
    lowers the total to 79.29 percent, while the largest uncovered regions are
    Active Directory and SMB paths that only execute on the domain lab.
- 2026-07-31: Ran the domain-lab acceptance against the OI-20 increment for the
    first time. Five suites and 32 tests passed with zero failures, zero skips,
    and an independent readiness check after every suite. The two previously
    unexecuted Task Scheduler Describes passed on the first attempt, so no
    source change was required and nothing contradicted specification 0014 or
    ADR 0023.
- 2026-07-31: Closed the one gap the acceptance did not cover. The suite never
    called a descriptor resource `Set`, so the endless-correction case was
    unproven. A new live test drifts both Task Scheduler descriptor resources,
    converges each in one `Set`, and asserts no drift on two further
    consistency passes. `Test-WindowsTaskSchedulerDscSddl` was also confirmed
    against the live eight-ACE inherited folder DACL with a fully reversed ACE
    order.
- 2026-07-31: Verified that a green lab run really proves rollback. A throwing
    `AfterAll` yields `Result` `Failed` with `FailedCount` 0, and both the
    acceptance runner and the detached suite runner gate on `Result`. The final
    live folder DACL was byte-identical to the pre-run capture, with zero leaked
    tasks, subfolders, shares, organizational units, or keys.

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
- Active Directory add, set, exact removal, rights removal, account purge, and
    clear that preserve object-ACE scope, expand stored generic bits before
    subtracting, disclose removed deny rules, reject a staged write whose target
    changed, and refuse a DACL that would leave the object unmanageable.
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

- 2026-08-01: Moved the project to a Hyper-V host that is not domain joined and
    proved the enterprise suites cannot be driven from it. The host binds LDAP
    with Negotiate but not Kerberos, and the module pins Kerberos deliberately,
    so the suites run inside the lab through AutomatedLab credential delegation
    rather than weakening the bind.
- 2026-08-01: Ran the complete existing acceptance unchanged against an interim
    single-domain-controller lab on the first attempt: five suites, 32 tests,
    zero failures and zero skips. The harness is topology-portable.
- 2026-08-01: Replaced the lab with a reproducible definition in
    `tests/Lab/Deploy-WindowsAccessControlLab.ps1`: three forests, two child
    domains, a second writable domain controller in the fixture domain, an
    enterprise root certification authority, four member servers, and
    PowerShell 7 plus Pester 5 on every machine. Three failed attempts taught
    the script to remove a predecessor lab, its orphaned virtual switch, and
    stale host-file entries; an orphaned switch keeps the host adapter on the
    retired subnet and strands every new machine.
- 2026-08-01: Closed OI-22 with specification 0015. Live probes established the
    rights model instead of assuming it: the software provider stores a
    candidate ACE with the matching generic bit added, so every comparison
    expands generic bits first, and `NCryptGetProperty('Impl Type')` reports
    `0x22` for the software provider against `0x0B` for the smart card provider.
- 2026-08-01: An independent cryptographic review returned REQUEST CHANGES with
    one Blocker and six Major findings, and all were fixed and verified live.
    The Blocker was a routine bypass rather than an exotic one: the binding gate
    compared certificate thumbprints while the write target is the key, so a
    certificate renewed with key reuse defeated it. Detection now resolves every
    bound thumbprint to a stored certificate and compares subject public keys.
- 2026-08-01: Collapsed two Major findings into one rule after proving both
    against the built module. A deny ACE naming a containing group and a
    conditional allow ACE each satisfy a per-account grant check while locking
    the key, so a new deny ACE and any non-plain ACE type are now refused and
    `Add-CertificatePrivateKeyAccessRule` exposes no deny surface. `RequireUnchanged`
    compared two reads taken inside the same write lock and was replaced by a
    caller-supplied `ConcurrencyToken`.
- 2026-08-01: Closed OI-23 as a decision. ADR 0024 records a cross-edition probe
    showing both PowerShell editions route a legacy CSP key through the CNG
    legacy bridge and return `RSACng`, so the separate managed CAPI object the
    issue assumed is never returned; the bridge still reports the CAPI provider
    name and cannot serve a descriptor at all. The rejection boundary is tested;
    the implementation half is withdrawn.
- 2026-08-01: Added a live Active Directory replication suite covering
    domain-controller switch, convergence between two writable replicas,
    identity across rename and move, rejection of a restore whose distinguished
    name was reused by a different object, and a failing read of a deleted
    object.
- 2026-08-01: Closed OI-18 with specification 0016 after the rebuilt lab came up
    with two writable domain controllers in the fixture domain. The live suite
    passed 7 of 7 on its first run: controller pinning, convergence in both
    directions between the two replicas, identity across a rename and a move,
    rejection of a restore whose distinguished name was reused, a failing read of
    a deleted object, and a pinned-controller outage.
- 2026-08-01: The outage test stops the partner's directory service and proves
    the module fails a pinned read and a pinned write with an LDAP-unavailable
    error rather than redirecting to the surviving controller. It restarts every
    dependent service it stopped, and the suite `AfterAll` fails when the partner
    does not serve the directory again.
- 2026-08-01: The first full acceptance run failed one assertion, and the module
    was right. The live Remote Desktop assertion assumed the bound certificate
    lives in the `Remote Desktop` store, but on the member server the bound
    certificate is in `My` and the `Remote Desktop` store holds a different one.
    The assertion was replaced by a deterministic HTTP.sys binding cycle that
    proves detection, refusal, release, and a permitted write afterwards, which
    also exercises the branch that covers Internet Information Services and
    WinRM HTTPS.
- 2026-08-01: The complete six-suite acceptance passed 40 of 40 tests with zero
    skips, six ready cleanup checks, both controllers serving afterwards, and no
    leaked organizational unit or HTTP.sys binding.
- 2026-08-02: Recorded the lab baseline. The AutomatedLab sample scenario
    `Multi-AD Forest with Trusts.ps1` supplies the domain, machine-name, and
    trust shape but is not sufficient on its own, and the gap was established
    against the suites rather than assumed. Without the enterprise root
    certification authority the private-key directory-service binding assertion
    fails, because a domain controller only holds a server-authentication
    certificate when a certification authority is in the forest. Without the
    second writable domain controller the replication suite throws in
    `BeforeAll`. Without PowerShell 7 and Pester 5 no suite is discovered at all.
    `tests/Lab/README.md` now carries the baseline, the delta, the machine map,
    and the operator workflow.
- 2026-08-02: Corrected two stale claims found while writing that guide. The
    deployment script pointed at `WindowsAccessControl.LabHost.psm1`, which does
    not exist, and the inventory credited a lab web server with the HTTP.sys
    binding evidence that actually comes from a disposable `netsh http` binding
    on the fixture member server. `F1DC2`, `F1AFile2`, the second child domain,
    and the second and third forests are reserved: no suite reaches them today.

## Open work

- OI-14 and OI-17 add SMB/AD portability, desired state, and an AD
    effective-access decision.
- OI-18 is complete. Specification 0016 records the multi-controller contract
    and the live suite passes 7 of 7 against two writable domain controllers.
- OI-20 is complete and carries live domain-lab evidence.
- OI-22 is complete: specification 0015 ships fail-closed CNG mutation and one
    independent cryptographic review closed with every Blocker and Major fixed.
- OI-23 is closed by decision. ADR 0024 records the cross-edition probe that
    disproved its premise and withdraws the implementation half.
- OI-24 is unblocked and not started. Its three binding design constraints are
    recorded in the open-issues register.
- The 80 percent coverage gate still needs a decision.
- Remote publication remains user-controlled.
