---
status: current
last-verified: 2026-08-02
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

OI-28 is closed. The 80 percent coverage threshold is now asserted over the
commands the running test profile can execute, so the hosted build and a host
that can run the domain lab apply the same rule instead of producing two
different verdicts. The threshold itself is unchanged and no test was added to
reach it.

OI-23 remains listed only as a decision record: ADR 0024 withdrew the
implementation half, and it should be reopened only for a concrete
`CryptAcquireContext` plus `PP_KEYSET_SEC_DESCR` requirement.

## OI-28 design

- The verdict is scoped rather than lowered. Every measured line of the built
    `.psm1` is attributed to the source file it was merged from through the
    `#Region '<path>'` and `#EndRegion '<path>'` comments ModuleBuilder writes.
    All 7,938 measured commands attribute to 254 source files with none left
    over, so the attribution is exact rather than approximate.
- Only fifteen source files leave the asserted scope, listed as exact paths in
    `build.yaml` under `CodeCoverage: DomainLabOnlySourcePath`. They are the
    Active Directory and SMB share files the local profile executes no command
    of at all. The SMB share family belongs there for the same reason the
    directory family does: `SmbSharePermissions.Live.Tests.ps1` resolves a
    domain user through the `ActiveDirectory` module and drives the module
    through a Kerberos session against the disposable member server.
- Two guards keep the declaration honest and both were proved live. A declared
    path that matches no source file fails the build. A declared file whose
    locally measured document reports an executed command fails the build with
    that file and its counts named. The second check reads the local document,
    not the merged one, because the merged one would accept anything the lab
    happens to cover.
- Everything else stays in scope by default: a line the source map cannot
    attribute, every source file added later, and the eight further files that
    also measure zero locally but belong to families a local profile can reach.
- The whole-module and domain-lab-only numbers are reported and neither is
    asserted, together with whether domain-lab evidence was merged into that run.
- A domain-lab document that cannot be read or cannot merge is now treated as
    absent with a warning instead of failing the build. It is still never merged.

## OI-28 evidence

- Asserted scope 83.16 percent, 6,379 of 7,671 commands, against 80.36 percent,
    6,379 of 7,938, over the whole module. The declared files contribute 0 of 267
    commands, so no measured local evidence left the gate.
- 16 build-helper unit tests and 10 QA specification tests pass, in PowerShell 7
    and in Windows PowerShell 5.1. Both new failure branches were driven live:
    the unmatched-path guard and the executed declaration guard.
- PSScriptAnalyzer over every changed file produces only the pre-existing
    `PSReviewUnusedParameter` category, which the committed task file already
    produced for the Invoke-Build parameter convention.
- One independent review returned REQUEST CHANGES with seven Major findings. All
    are resolved. The first declaration used family globs that removed 553
    executed commands and nine fully covered files from the gate, `-like` matched
    case-insensitively so a future `*-WindowsAdapter*` file would have left the
    scope silently, nothing detected over-declaration, the build printed an
    assertion that did not exist, and the ADR's stated anti-gaming safeguard was
    false. Exact paths plus the executed-declaration guard replace all of it.

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

No focused issue remains open, so the next candidates come from the
specifications rather than the register.

1. Promote specification 0008 from `Draft` to `Accepted`. Its own acceptance
    criteria are the last gap: specification 0002 needs stable identifiers for
    the behavior shipped after FR-23 and NFR-16, specification 0005 needs the
    roadmap-task mapping, and specification 0008 still calls replication
    evidence blocked and points at the closed OI-18. The existing QA test that
    traces every requirement to evidence verifies the result.
2. Rerun the domain-lab coverage document. The committed one measures a module
    that no longer exists, so the merged whole-module number cannot be reported.
3. Diagnose `Should reconverge all NTFS descriptor sections together`, which
    fails on this host across commits and is currently tolerated without a
    written ruling.

Every other candidate (SMB-6, AD-7, directory audit rules, directory
inheritance and owner/group mutation, CAPI) is a written deferral and needs a
new accepted scope decision before implementation.
