---
status: current
last-verified: 2026-08-01
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

OI-22 is closed. The fail-closed CNG private-key mutation of specification 0015
went through the repository's review convention in full: one feature review, then
three fix rounds each followed by its own scoped re-review. The third re-review
returned APPROVE WITH MINOR FINDINGS with no Blocker and no Major, and the
remaining Minor and Nit findings were fixed as well. The register entry and the
conformance test now record the issue as closed.

## OI-22 close-out

- The first re-review of the earlier fixes found one dead gate and three defects
    no unit test could have caught by construction. The `NTDS\My` store had been
    opened as a `StoreLocation::LocalMachine` name, which cannot address a service
    certificate store, so the LDAPS branch of the binding gate was inert on every
    domain controller. It is now opened natively under
    `CERT_SYSTEM_STORE_SERVICES` and proven against a real service store.
- A bound thumbprint that resolved to none of four hard-coded stores threw, which
    denied every private-key write on the machine. Resolution now searches every
    machine store that exists plus the `NTDS` service store, searches the stores a
    binding names first, and stops as soon as every thumbprint resolves.
- `Remove-CertificatePrivateKeyAccessRule` matched rights exactly and reported
    success when it matched nothing. It now names every account the request left
    unchanged, including when the same request matched another account.
- The service-preservation gate skipped inherit-only ACEs on the candidate side
    but not on the stored side, so it refused an exact reassert of a DACL that
    carried one.
- Two rounds argued about ACE ordering before the right rule emerged: allow ACEs
    are additive, so an allow-only reordering is already the requested state and
    is a no-op, while a reordering with a deny present is refused because order
    then decides the access check and the provider owns the stored order.
- Two review claims were refuted with read-only probes rather than argument. A
    completed service-store enumeration always reports `CRYPT_E_NOT_FOUND`,
    including for an empty store, and the services location opens an empty
    collection for a service name it does not know, so the test that was said
    never to reach the tightened check does reach it.
- One finding was parked with a written ruling. The HTTP.sys thumbprint match is
    deliberately shape-based and over-matches, because a label-and-value pattern
    would depend on a separator that is not stable across display languages, and
    a pattern that stops matching detects no binding at all, which is fail-open.

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

OI-22 is closed, so the two remaining focused issues are unblocked. OI-24 adds
private-key portability and desired state; its three binding constraints are
recorded in the open-issues register, and it must pass through the specification
0015 write boundary rather than around it. OI-27 merges domain-lab coverage into
the threshold gate so the 80 percent measurement reflects what the suites
actually exercise.
