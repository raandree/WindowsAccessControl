---
status: current
last-verified: 2026-07-29
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

Registry-key access rules now report native inherited-ACE provenance through
`InheritedFrom`, matching the NTFS family. The shared native inheritance-source
helper serves both families, the WOW64 registry views fail closed to a null
source, and a provenance lookup failure degrades the column instead of
discarding a successful descriptor read.

## Evidence

- A live probe established the constraints rather than assuming them:
    `GetInheritanceSourceW` succeeds with `SE_REGISTRY_KEY` and returns native
    hive names, but fails with `ERROR_INVALID_PARAMETER` for
    `SE_REGISTRY_WOW64_32KEY` and `SE_REGISTRY_WOW64_64KEY`, even though
    `GetNamedSecurityInfoW` accepts both for the same key.
- ADR 0019 records the fail-closed view decision and the degrade-on-failure
    decision; specifications 0003, 0004, and 0005 record the expanded contract
    and evidence.
- Independent security review returned APPROVE WITH COMMENTS with no Blocker
    and one Major finding. All Major and Minor findings were fixed.
- A pristine `main` worktree established the environment baseline for the full
    Sampler suite: 1081 passed, 50 failed, every failure elevation dependent.
- The focused registry, NTFS, QA, and mutator-safety set passes 68 of 68
    non-elevation tests, including 25 new provenance tests.

## Next step

Review or push the local commits only on explicit request. Ten focused issues
remain: OI-14, OI-16 through OI-18, OI-20, and OI-22 through OI-25, plus the
elevation-dependent failures that predate this work. OI-18 remains externally
blocked until a second writable domain controller exists; do not repurpose the
member server that hosts SMB, Task Scheduler, and software-key fixtures.
