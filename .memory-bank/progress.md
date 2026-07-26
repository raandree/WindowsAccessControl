---
status: current
last-verified: 2026-07-26
owner: active-agent
source: repository evidence
---

# Progress

## Current status

The NTFS, registry, service/SCM, and pinned live-process command families are
complete, independently approved, and green on both supported PowerShell
editions. Cross-domain portability, bounded execution, and DSC remain open.

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

## Open work

- Add unified cross-domain descriptor backup and restore with optional
    integrity protection.
- Add bounded target execution, same-target serialization, and metrics.
- Decide and implement optional local credential impersonation if retained.
- Add class-based DSC exact-descriptor and rule-presence resources for every
    current object family.
- Remote publication remains user-controlled.
