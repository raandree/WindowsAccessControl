---
status: current
last-verified: 2026-07-28
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

The currently shipped enterprise increments are complete on
`ai/resolve-open-issues`, and OI-11/ENT-8 is closed. The branch contains remote
effective-access deferral, bounded NTFS editing, SMB share-only effective
access, Task Scheduler DACL descriptors, an unattended domain-lab runner, and
read-only software-CNG private-key descriptor inspection. The disposable lab is
ready. Remote push and publication remain under explicit user control.

## Evidence

- Specifications 0007 and 0009 through 0012 are accepted for their bounded
    increments; ADRs 0015 through 0018 define local authority, schema, effective
    access, Task Scheduler, and software-key boundaries.
- Source, built, and packaged manifests export exactly 89 functions. The
    eight-entry `WindowsAccessControl.0.0.1.nupkg` imports 89 commands in both
    editions and has SHA-256
    `A702E507470676DF4784C2B9442D16DC036DB230552E438B0C8CAFA724312F67`.
- The package contains no source/test/specification tree, lab identifier, or
    PEM private-key marker; it declares no required modules.
- The final Core profile discovers 995 tests: 992 pass, three host-policy cases
    fail, zero skip, and merged-module coverage is 80.4561 percent.
- The final Desktop profile discovers 968 tests: 965 pass, the same three
    host-policy cases fail, zero skip, and coverage is 80.0226 percent.
- The exact four-test impersonation file passes 4 of 4 on the domain member in
    PowerShell 7.6.3 and Windows PowerShell 5.1. The member denies no required
    logon type, retains no staged directory, and retains no disposable users.
- Sampler's native coverage task passes at 80.46 percent in Core and 80.02
    percent in Desktop. The three management-host failures are exactly the
    successful-logon cases rejected by domain-controller policy; the invalid
    password fail-closed case passes there.
- The unattended five-suite profile passes 18 tests with five ready cleanup
    checks. A final status check reports both lab boundaries ready, all 10
    expected domain objects present, and the member share, task folder, and CNG
    certificate fixture ready.
- The changed PowerShell tests parse in both editions with zero PSScriptAnalyzer
    warnings or errors. Markdown diagnostics, whitespace, secret, and
    infrastructure-identity scans are clean.
- Independent security reviews for the shipped enterprise slices returned
    APPROVE with no unresolved Blocker or Major findings.

## Next step

Review or push the local commits only on explicit request. Eleven focused issues
remain: OI-13, OI-14, and OI-16 through OI-24. OI-18 remains externally blocked
until a second writable domain controller exists; do not repurpose the member
server that hosts SMB, Task Scheduler, and software-key fixtures.
