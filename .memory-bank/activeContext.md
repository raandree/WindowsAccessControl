---
status: current
last-verified: 2026-08-02
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

Specification 0008 is accepted. It was the last `Draft` in the specification
index, and it had blocked itself: its own text required stable requirement
identifiers and a roadmap-to-evidence mapping that did not exist yet.

OI-23 remains listed only as a decision record: ADR 0024 withdrew the
implementation half, and it should be reopened only for a concrete
`CryptAcquireContext` plus `PP_KEYSET_SEC_DESCR` requirement.

## Specification 0008 acceptance

- The contract is accepted, not a claim of complete implementation. The
    specification now says so, and every work package closes either through
    executable evidence or through an accepted decision record that defers it.
    `SMB-6` is deferred by ADR 0017, `AD-7` by ADR 0022, and the CAPI half of
    the private-key package by ADR 0024.
- Specification 0002 gained `FR-24` through `FR-27` and `NFR-17` through
    `NFR-20`. Everything shipped after read-only private-key inspection had no
    stable identifier: fail-closed private-key mutation (0015), key-addressed
    portability and desired state (0017), schema-version-2 enterprise
    portability and the SMB and directory resources (0013), the Task Scheduler
    equivalents (0014), and immutable directory identity (0016). `FR-23` was
    left as written, because inspection is still supported; mutation is a new
    requirement rather than a rewrite of an accepted one.
- Specification 0005 gained a roadmap task traceability section: all 39
    `ENT-*`, `TASK-*`, `KEY-*`, `SMB-*`, and `AD-*` tasks with their state and
    the test file, decision record, or artifact that closes them.
- Two statements in 0008 were contradicted by 0016 and are gone: that
    replication evidence remained blocked, and that OI-18 tracked it. The QA
    suite asserts OI-18 is absent from the register, so the specification was
    pointing at an issue that could not exist.
- The seven open questions are answered in place from the contracts that
    resolved them rather than deleted.

## Acceptance evidence

- The QA specification suite passes 10 of 10, including the two checks that
    govern this change: requirement identifiers are unique, and every identifier
    in 0002 is traced in 0005.
- No prose line added to the four files exceeds 80 characters, and
    `Get-ChangelogData` still parses `CHANGELOG.md`.
- The public command evidence table in 0005 was deliberately not extended.
    Fifteen exported commands have no row, but the `Direct specs` count equals
    neither the `It`, the `Context`, nor the `Describe` count of the command's
    test file, so the column follows a curated rule from the original audit.
    Filling it under a different rule would corrupt the column. Each of the
    fifteen does have a dedicated test file.

## Two findings worth keeping

- The committed domain-lab document measures 4,720 lines the module built from
    `main` does not have. It was produced against an earlier built module, so the
    merged 90.34 percent verdict recorded when OI-27 closed does not currently
    exist. The identity guard caught it, which is the behavior that decided the
    document should be reported rather than depended on.
- The `-f` format operator binds tighter than `+`, so
    `'a {0}' + 'b {1}' -f $x, $y` silently leaves `{0}` unformatted. One such
    message shipped into the failure branch and was found by forcing the branch
    rather than by reading it.

## Environment notes

- The development host is the Hyper-V host and is a workgroup machine. The
    module pins Kerberos for its LDAP bind, so the enterprise suites run inside
    the lab through AutomatedLab credential delegation.
- `WindowsAccessControlLab` has 13 machines across three forests. After a host
    reboot the machines must be started before the acceptance runs, and the
    member fixture reports not ready for a short time while its services start.
- The full Sampler gate on this machine has one environmental failure,
    `Should reconverge all NTFS descriptor sections together`, which also fails
    on committed `4852a18` and on `7d1a9d4`. The certificate private-key unit
    tests are flaky here for the same reason: they exercise the live key storage
    provider.

## Next step

No specification is in `Draft` and no focused issue is open. Two candidates
remain, both operational rather than contractual.

1. Rerun the domain-lab coverage document so the merged whole-module number can
    be reported with lab evidence again.
2. Diagnose `Should reconverge all NTFS descriptor sections together`, which
    fails on this host across commits and is tolerated without a written ruling.

Every other candidate (SMB-6, AD-7, directory audit rules, directory
inheritance and owner/group mutation, CAPI) is a written deferral and needs a
new accepted scope decision before implementation.
