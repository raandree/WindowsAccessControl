---
status: current
last-verified: 2026-07-31
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

OI-20 is closed and now carries live domain-lab evidence. The Task Scheduler
folder and registered-task families have computer-qualified canonical identity,
schema-version-2 descriptor portability, and four object-specific DSC resources,
matching the SMB share and Active Directory contract accepted in specification
0013.

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
- 2026-07-31: The domain-lab acceptance ran for the first time against the OI-20
    increment and passed on the first attempt. Five suites, 32 tests, zero
    failures and zero skips, with an independent readiness check after each
    suite. No source change was required.
- The two previously unexecuted Task Scheduler Describes passed against a live
    task store: schema version 2, record versions `2, 2`, families `TaskFolder`
    then `ScheduledTask`, `Server` equal to the uppercase member-server name,
    the folder canonical target `TaskFolder:<COMPUTER>:<UPPER PATH>`, exact
    restore of the original SDDL, an unbounded restore rejected by a message
    naming `AllowedRootPath`, and rule and descriptor convergence.
- The acceptance did not prove the property the increment was most exposed to,
    so one live test was added: a drifted descriptor converges in one `Set` and
    then reports no drift on two further consistency passes, for both the folder
    and registered-task descriptor resources. This is the endless-correction
    case that a wrong `Test-WindowsTaskSchedulerDscSddl` would produce, and the
    suite previously never called a descriptor resource `Set`.
- `Test-WindowsTaskSchedulerDscSddl` was also confirmed directly against the
    live eight-ACE inherited folder DACL: a fully reversed ACE order still
    compares equivalent, so the earlier array-unrolling regression is absent.
- A green lab run is trustworthy evidence of rollback because a throwing
    `AfterAll` produces `Result` `Failed` with `FailedCount` 0, and both runners
    gate on `Result`. This was verified with a throwaway suite rather than
    assumed.

## Next step

The OI-20 increment is on `main` at `b9a9f79` and already pushed. The live
evidence added on 2026-07-31 is a local, uncommitted change to the Task
Scheduler lab suite, specification 0014, and this Memory Bank; commit or push it
only on explicit request. Four focused issues remain: OI-18 and OI-22 through
OI-24. OI-18 remains externally blocked until a second writable domain
controller exists. The 80 percent coverage gate needs a separate decision:
either domain-lab coverage merging or an explicit threshold change.
