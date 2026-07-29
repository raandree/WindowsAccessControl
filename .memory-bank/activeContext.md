---
status: current
last-verified: 2026-07-29
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

OI-19 is closed on `ai/descriptor-editing-expansion`. Task Scheduler now
exposes typed access-rule commands for folders and registered tasks, backed by
two object-specific rights enums, folder inheritance scope, and three new
fail-closed write gates. Remote push and publication remain under explicit
user control.

## Evidence

- Specification 0010 is accepted for the typed-rule slice; specifications 0003
    and 0005 record the expanded surface and traceability. The module exports
    96 functions.
- The rights model, ACL-revision behavior, and the service-token group set were
    all established by live probes against a disposable task folder, not
    assumed. Task Scheduler stores object ACEs but re-revisions the ACL from 2
    to 4, so those ACE types are now rejected.
- Independent security review returned REQUEST CHANGES with three Major
    findings. All three were fixed: the flags-blind duplicate suppression that
    silently discarded an inheritance-scope change, one shared rights enum that
    understated a task-folder grant, and the missing optimistic-concurrency
    check on the staged read-then-write window.
- Every Minor and Nit finding was closed except the registry parity gap, which
    is recorded as OI-25.
- Live domain-lab acceptance passes 5 of 5 against the disposable task folder
    on the member server, with the fixture restored afterwards.
- The full Sampler profile reached 1148 passed, 3 failed, 0 skipped at 81.17
    percent coverage. Later runs additionally surface two pre-existing
    in-memory descriptor editing failures; two source-stash bisects reproduce
    them on unmodified `HEAD`, and the root cause is recorded as OI-26.
- The three impersonation failures remain the pre-existing domain-controller
    interactive-logon policy cases; they fail identically on `main`.

## Next step

Review or push the local commits only on explicit request. Ten focused issues
remain: OI-14, OI-16 through OI-18, OI-20, and OI-22 through OI-26. OI-18
remains externally blocked until a second writable domain controller exists; do
not repurpose the member server that hosts SMB, Task Scheduler, and
software-key fixtures.
