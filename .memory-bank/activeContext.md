---
status: current
last-verified: 2026-07-29
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

OI-21 and OI-13 are closed on `ai/descriptor-editing-expansion`. Detached
descriptor editing now covers every filesystem and registry-key mutator, adds
`Edit-RegistryKeySecurityDescriptor` as the 90th export, and adds an opt-in
`RequireUnchanged` optimistic-concurrency switch backed by a read-time
`ConcurrencyToken`. Remote push and publication remain under explicit user
control.

## Evidence

- Specification 0007 is accepted for both families; specifications 0003 and
    0005 record the expanded parameter sets and traceability.
- The full Sampler profile runs 1084 of 1087 tests successfully at 80.91 percent
    merged-module coverage, over the 80 percent gate, with zero skips.
- The only three failures are the pre-existing domain-controller
    interactive-logon policy cases in `WindowsImpersonation.Tests.ps1`; they fail
    identically on `main` and pass on the domain member.
- `Invoke-ScriptAnalyzer -Severity Warning, Error` over `source/Public`,
    `source/Private`, `tests/Unit`, and `tests/Integration` is clean. Every
    changed source file parses in both editions.
- Independent security review returned REQUEST CHANGES with two Major findings;
    both were fixed and the focused re-review returned APPROVE. The four
    remaining Minor and two Nit findings were also closed.
- A descriptor-bound mutation fails closed when its section was not loaded,
    which replaces a latent ACL-wipe path in `Add-NTFSAccessRule`.
- NTFS ACL protection is requested only for a present ACL, so persisting an
    `Access, Audit` descriptor on a SACL-less item no longer fails after the
    DACL was already written.

## Next step

Review or push the local commits only on explicit request. Nine focused issues
remain: OI-14, OI-16 through OI-20, and OI-22 through OI-24. OI-18 remains
externally blocked until a second writable domain controller exists; do not
repurpose the member server that hosts SMB, Task Scheduler, and software-key
fixtures.
