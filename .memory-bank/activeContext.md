---
status: current
last-verified: 2026-07-30
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

OI-20 is closed. The Task Scheduler folder and registered-task families now have
computer-qualified canonical identity, schema-version-2 descriptor portability,
and four object-specific DSC resources, matching the SMB share and Active
Directory contract accepted in specification 0013.

## Evidence

- `Resolve-WindowsTaskSchedulerTarget` emits `Server` and
    `TaskFolder:<COMPUTER>:<PATH>` / `ScheduledTask:<COMPUTER>:<PATH>`, so the
    canonical write lock, metrics, and portability records all name the machine.
- Both families enter unified backup as record version 2 without adding a hashed
    field: `Server` already existed and `Target` carries the absolute task path,
    so the canonical target is exactly `<family>:<SERVER>:<TARGET>` and every
    existing version-1 and version-2 backup still validates.
- `Restore-WindowsSecurityDescriptor` gained `AllowedRootPath`. A task record
    restores only on the computer it names, every target is resolved for write
    during preparation, and the write passes through the public setters and
    their specification 0010 gates.
- Four DSC resources ship. They manage the access section only, require
    `AllowedRootPath`, and compare DACLs semantically because the Task Scheduler
    service canonicalizes ACE order after a write.
- One independent security review returned APPROVE WITH COMMENTS with no
    Blocker and three Major findings: a specification claim of a staleness gate
    the descriptor write path does not have, an unreachable root-folder code
    path asserted by the new ADR, and an undocumented ACE-order limitation on
    the new resources. All three plus every Minor were fixed.
- Coverage is 79.61 percent against an 80 percent gate. The shortfall is
    pre-existing: the new code measures about 97 percent covered, and excluding
    it lowers the measured total to 79.29 percent. The largest uncovered regions
    are Active Directory and SMB paths that only execute on the domain lab.
- The gate run after the review fixes caught a self-inflicted regression in the
    ordinal ACE-multiset ordering: a `,` before the returned array stopped
    PowerShell unrolling it, so equivalent DACLs reported drift. Removing the
    comma fixed it. Final gate: 1309 of 1312 tests with zero skips, the only
    failures being the three domain-controller interactive-logon policy cases.
    Windows PowerShell 5.1: 161 of 161 with zero skips.

## Next step

Review or push the local changes only on explicit request. Four focused issues
remain: OI-18 and OI-22 through OI-24. OI-18 remains externally blocked until a
second writable domain controller exists. The 80 percent coverage gate needs a
separate decision: either domain-lab coverage merging or an explicit threshold
change.
