---
status: current
last-verified: 2026-07-27
owner: active-agent
source: repository evidence
---

# Progress

## Current status

The NTFS, registry, service/SCM, and pinned live-process command families are
complete with unified cross-domain portability, bounded execution, canonical
write serialization, metrics, and exact-descriptor DSC resources. They are
independently approved and green on both supported PowerShell editions. All ten
signed DSC resources are complete. OI-3 is closed with native inherited
access-rule provenance.

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

## Stable capabilities

- Access and audit rule construction, query, mutation, filtering, and clearing.
- Owner, inheritance, identity, privilege, and Authz effective-access workflows.
- Structured token privilege inventory and deduplicated multi-account additions.
- Optional explicit-rule removal while enabling access or audit inheritance.
- Selected-section descriptor copy and versioned JSON backup or restore.
- Reproducible Sampler build plus a two-edition Azure Pipelines test matrix.
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

## Open work

- Complete and validate the uncommitted OI-5 phase-one implementation.
- Inventory and prepare the supplied domain lab under ENT-1 and ENT-2.
- Resolve the remote-security, credential, backup-schema, and effective-access
    contracts before implementing OI-7 through OI-10.
- Remote publication remains user-controlled.
