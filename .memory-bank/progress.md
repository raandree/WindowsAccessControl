---
status: current
last-verified: 2026-07-25
owner: active-agent
source: repository evidence
---

# Progress

## Current status

The 0.1.0 follow-up is complete, independently approved, packaged, and green on
both supported PowerShell editions within the available token privileges.

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

## Stable capabilities

- Access and audit rule construction, query, mutation, filtering, and clearing.
- Owner, inheritance, identity, privilege, and Authz effective-access workflows.
- Structured token privilege inventory and deduplicated multi-account additions.
- Optional explicit-rule removal while enabling access or audit inheritance.
- Selected-section descriptor copy and versioned JSON backup or restore.
- Reproducible Sampler build plus a two-edition Azure Pipelines test matrix.
- Normative numbered specifications with requirement-to-test traceability and
    immutable accepted ADRs.

## Open work

- Execute the six elevated acceptance specifications before release when the
    required token privileges are available.
- Remote publication remains user-controlled.
