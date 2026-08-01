---
status: current
last-verified: 2026-08-01
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

The project moved to a Hyper-V host that is not domain joined, and the domain
lab was replaced with a purpose-built multi-forest environment. OI-22 shipped as
specification 0015 after an independent cryptographic review returned REQUEST
CHANGES and every Blocker and Major finding was fixed. OI-23 closed as a
decision rather than an implementation. OI-18 has a suite but is waiting for the
lab rebuild to finish.

## Environment change

- The development host is the Hyper-V host and is a workgroup machine. It sits
    on the lab virtual switch and drives the lab through AutomatedLab, which
    uses credential delegation, so a directory call inside a lab session holds a
    real ticket-granting ticket.
- The module pins Kerberos for its LDAP bind. A probe proved a workgroup host
    can bind with Negotiate but not Kerberos, so the enterprise suites must run
    inside the lab. Falling back to NTLM was rejected as a security regression.
- `tests/Lab/Deploy-WindowsAccessControlLab.ps1` now owns the lab: three
    forests, two child domains, a second writable domain controller in the
    fixture domain, an enterprise root certification authority, four member
    servers, plus PowerShell 7 and Pester 5 on every machine.
- The interim single-DC lab ran the complete existing acceptance unchanged on
    the first attempt: five suites, 32 tests, zero failures and zero skips. The
    harness is topology-portable.
- A lab teardown that fails partway leaves the virtual switch behind. The host
    adapter then keeps the retired subnet while the new lab picks the next free
    one, and every new machine is stranded with no route to the host. The
    deployment script now removes an orphaned switch, but only when no virtual
    machine is attached.

## OI-22 evidence

- Live probes established the rights model rather than assuming it. A fresh
    machine key carries
    `D:P(A;;0xd01f01ff;;;CO)(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)`, and the
    provider stores a candidate ACE with the matching generic bit added, so a
    requested `0x00120089` reads back as `0x80120089`. Every comparison expands
    generic bits before comparing.
- `NCryptGetProperty('Impl Type')` reports `0x22` for the software provider and
    `0x0B` for the smart card provider, so hardware rejection is confirmed
    against the provider itself rather than trusting the name.
- One independent security review returned REQUEST CHANGES with one Blocker and
    six Major findings. All were fixed and verified live.
- The Blocker was real and non-adversarial: the binding gate compared the
    certificate thumbprint while the write target is the key, so a certificate
    renewed with key reuse would bypass it. Detection now enumerates every bound
    thumbprint, resolves it to a stored certificate, and compares subject public
    keys, which identifies the private key without opening a key handle.
- Two Major findings collapsed into one rule: a new deny ACE is refused outright
    and a non-plain ACE type is refused, because a deny naming a containing
    group and a conditional allow ACE both defeat any per-account grant check.
    `Add-CertificatePrivateKeyAccessRule` therefore has no `AccessControlType`.
- `RequireUnchanged` compared two reads taken inside the same write lock and
    proved nothing. It was replaced by a caller-supplied `ConcurrencyToken`,
    matching every other family.
- Three tool-level defects were found by tests rather than by inspection: an
    array argument flattening and shifting later positional arguments, an `if`
    without `else` contributing zero array elements and doing the same, and a
    lower-case local variable writing into a typed parameter that differed only
    by case. All three are recorded in `debugging-insights.md`.
- ModuleBuilder writes the merged module without parsing it, so a build can
    report success for a file that cannot be imported. Every build now parses
    the merged module explicitly.

## OI-23 outcome

ADR 0024 closes the CAPI question with a cross-edition probe instead of an
implementation. Both PowerShell editions route a legacy CSP key through the CNG
legacy bridge and return `RSACng`, so the separate managed CAPI object the issue
assumed is never returned. The bridge still reports the CAPI provider name, so
the existing allow-list already separates the two, and the bridged key cannot
serve a descriptor at all. The implementation half is withdrawn; the tested
rejection boundary remains.

## Next step

Finish the lab rebuild, run the six-suite acceptance including the new
replication suite, and decide the coverage gate from the current report. OI-24
is unblocked but not started; its three binding constraints are recorded in the
open-issues register so the next session starts from evidence.
