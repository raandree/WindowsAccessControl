---
status: current
last-verified: 2026-08-02
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

OI-24 delivers KEY-5 and KEY-6: certificate private-key portability and desired
state. The implementation, specification 0017, ADR 0026, tests, and the review
loop are complete. One item is open: the six-suite domain-lab acceptance has not
produced live evidence yet, because the lab is contended.

The work lives in a separate worktree at `V:\Git\WindowsAccessControl-oi24` on
branch `ai/cng-private-key-mutation-and-multi-forest-lab`, so the OI-27 session
holding uncommitted changes in the main worktree stays untouched.

## OI-24 design

- The write boundary no longer accepts a certificate at all.
    `Set-WindowsCngKeySecurityDescriptor` lost its `Certificate` parameter, so a
    restore and a desired-state resource cannot reach it with a weaker binding
    check. The gate cannot be addressed incorrectly rather than merely being
    documented as correct.
- Every private-key command gained a `Key` parameter set selecting the key by
    CNG provider, persisted key name, and `Machine` or `User` scope. That path
    verifies the opened key is RSA and that its scope matches, because
    `CngKey.Open` would otherwise answer from the other key store.
- The critical-binding gate is keyed on the write target's own public key, read
    from the `CngKey` as a `BCRYPT_RSAKEY_BLOB`. It throws when the public key
    cannot be read, because a gate input that cannot be evaluated must not
    default to permit. `Test-CertificatePrivateKeyCriticalBinding` keeps the
    certificate-to-certificate comparison for a caller holding a certificate.
- Records are schema version 2 carrying `Server`, `ProviderName`, `KeyName`,
    `KeyScope`, and `CertificateThumbprint`. The thumbprint is evidence only and
    never a selector, because a renewal that reuses the key changes it. The four
    fields are hashed for this family alone, so every record written before this
    increment keeps validating.
- The foreign-computer check was hoisted out of per-record preparation into a
    whole-document pre-pass covering the SMB share, Task Scheduler, and
    private-key families, so a foreign record cannot be reached after an earlier
    record was already written.
- Restore adds no parameter and no override switch. It composes
    `Set-CertificatePrivateKeySecurityDescriptor` and passes
    `ExpectedCanonicalTarget`, reasserted against the handle the write holds, so
    a key deleted and recreated between preparation and write is refused.

## OI-24 evidence

- Unit and QA: 1306 passed, 0 failed, 0 skipped, against a 1242 baseline.
- Every specification 0015 gate a restore could bypass has a refusal test: an
    unsupported provider, a live critical binding, an added deny ACE, a
    conditional ACE, a dropped SYSTEM or Administrators grant, a removed service
    grant, and a protection-state change. Two restore-specific rejections cover a
    record replayed on another computer and a key whose identity changed.
- The merged module was parsed explicitly after the build, because ModuleBuilder
    does not parse what it writes.
- PSScriptAnalyzer over all 43 changed files produced no finding category absent
    from the committed baseline. `DscResourceInvalidKeyProperty` and
    `TypeNotFound` fire on the unchanged baseline file too, because a class file
    analyzed standalone cannot resolve the module's enum types.
- One independent `security-reviewer` review returned one Major and four Minor
    findings, all fixed. The scoped re-review of the fix diff returned APPROVE
    WITH MINOR FINDINGS with no Blocker and no Major; the three new Nits were
    cleared as well.

## Open item: live lab evidence

Four acceptance attempts failed for two unrelated environmental reasons, neither
a defect in the change.

- The host had rebooted, and the first attempt started while the lab machines
    had seven minutes of uptime. `Should repair a missing certificate whose
    managed CNG key remains` allows its repair job 30 seconds and calls
    `Stop-Job` on timeout, which left a certificate whose private key could not
    be read. `Remove-WindowsAccessControlDomainLab` cannot match such a
    certificate, so a later initialize created a second one beside it and every
    later run failed with `Multiple domain-lab certificates have the same managed
    identity`. A cleanup keyed on subject and friendly name alone restored the
    fixture to exactly one certificate.
- The OI-27 session drives the same `WindowsAccessControlLab` and the same
    `C:\WacRepo` payload directory. It wiped and re-copied that directory at
    08:18:30 while this session's run started at 08:18:40, so Pester found no
    test files. `C:\WacRepo` now holds the OI-27 tree, whose
    `CertificatePrivateKeyPermissions.Live.Tests.ps1` is 19,687 bytes against
    37,844 bytes here.

The user chose to wait for the OI-27 run to finish, then redeploy the full OI-24
payload without `-SkipPayload`. The lab is a shared resource and the two sessions
must be serialized on it.

## Superseded: OI-22 close-out

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

Run the domain-lab acceptance from `V:\Git\WindowsAccessControl-oi24` once the
OI-27 session releases the lab, confirm the four new live private-key cases, and
record the result. Both branches modify `CHANGELOG.md`, `specs/open-issues.md`,
and `tests/Lab/CertificatePrivateKeyPermissions.Live.Tests.ps1`, so merging them
will need a deliberate conflict resolution. OI-27 remains open for the coverage
measurement.
