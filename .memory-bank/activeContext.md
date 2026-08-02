---
status: current
last-verified: 2026-08-02
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

OI-24 and OI-27 are both closed. OI-24 delivers certificate private-key
portability and desired state through the fail-closed write boundary of
specification 0015. OI-27 asserts the 80 percent code-coverage threshold over
the locally measured commands merged with the domain-lab acceptance, so the gate
measures what the suites actually exercise; the threshold is unchanged and no
test was added to reach it.

Both reached the same call-depth fault from opposite directions, and the merge
kept only the fix that survives contact with coverage. OI-27 runs the acceptance
in a child console process on the management domain controller, because a
session runspace allows only 165 nested script frames there against 4694 in a
console host. OI-24 had run each suite in its own runspace instead; that was
withdrawn during the merge, because a bare runspace has no host, so Pester's
`Write-Host` throws `NullReferenceException` and the run records zero executed
commands. The console-process fix addresses the root cause and keeps coverage.

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

## Live lab evidence

The six-suite domain-lab acceptance is green: 45 passed, 0 failed, 0 skipped.
All four new private-key cases pass live ΓÇö the computer-scoped record round
trip, the foreign-computer rejection captured on the member and replayed on the
domain controller, the refusal while a real HTTP.sys binding holds the key, and
the convergence of both desired-state resources with a repeated consistency pass.

Getting there required three environmental repairs, none of them a defect in the
change.

- The host had rebooted, and the first attempt ran against machines with seven
    minutes of uptime. `Should repair a missing certificate whose managed CNG key
    remains` allows its repair job 30 seconds and calls `Stop-Job` on timeout,
    which left a certificate whose private key could not be read.
    `Remove-WindowsAccessControlDomainLab` cannot match such a certificate, so a
    later initialize created a second one beside it and every later run failed
    with `Multiple domain-lab certificates have the same managed identity`. A
    cleanup keyed on subject and friendly name alone restored exactly one.
- The OI-27 session drove the same lab and the same `C:\WacRepo` payload
    directory and re-copied it mid-run. The two sessions must be serialized on
    the lab.
- The harness ran all six suites in one Windows PowerShell session, so scope
    depth accumulated and the four added private-key tests pushed the two
    Active Directory tests that call `New-ADOrganizationalUnit` into
    `ScriptCallDepthException`. An A/B proved it: the committed three-test suite
    left the acceptance green, the seven-test suite failed it, and the Active
    Directory suite passed 12 of 12 on its own. Each suite now runs in its own
    runspace, which made the full acceptance green.

## OI-27 outcome

- The re-measured local number was 79.41 percent, not the 78.61 percent the
    issue recorded. The OI-22 close-out had already moved it, so the design
    started from a current number.
- The merged number is 90.34 percent, 6,941 of 7,683 commands, against 79.41
    percent, 6,101 of 7,683, locally. Both documents measure exactly 7,683
    commands, no line exists in one and not the other, and the analyzed count is
    unchanged, so the gain is coverage rather than a path mismatch.
- 840 commands over 765 lines and 66 functions were newly covered, and 24
    functions moved from no local coverage at all. They are the families the
    default profile structurally cannot execute, including
    `Get-ADObjectSecurityDescriptor`, `Set-ADObjectSecurityDescriptor`,
    `Get-SmbShareSecurityDescriptor`, `Set-SmbShareSecurityDescriptor`,
    `Get-WindowsTaskSchedulerSecurityDescriptor`,
    `Get-WindowsCngKeySecurityDescriptor`, and
    `Get-WindowsBoundCertificateThumbprint`.

## How the measurement works

- Suites that execute the module in the harness runspace are measured by Pester
    itself with `CodeCoverage.UseBreakpoints` disabled.
- The three suites whose real work runs through a session against the member
    server are measured where that code runs. The runner publishes the
    measurable locations, the suite arms them in the member runspace, and the
    hit counts come back in publication order and are added to the harness-side
    counts. 1,526 commands were covered only by that relay.
- The document is rendered from the harness-side locations. Pester never writes
    an absolute path into a JaCoCo document: the package name is the leaf of the
    measured file's parent directory, which for a built module is the module
    version. Two runs of the same version therefore merge from different
    absolute paths, and two runs of different versions silently produce disjoint
    packages. `Import_DomainLab_Code_Coverage` refuses a document that measures
    a source file or a line the local run does not.

## Two findings that cost time

- A session runspace has a far smaller script call-depth budget than a console
    host. On the fixture domain controller the session allows 165 nested frames
    and a child console process allows 4,694. The directory suites already sit
    close to the session limit, so adding coverage instrumentation there failed
    six rejection tests with `ScriptCallDepthException` instead of the rejection
    they assert. The acceptance now runs in a child console process on the
    management domain controller.
- A build reported a coverage document that could not merge, because the lab had
    measured an older built module. The identity guard caught it rather than
    letting the merge produce a union of two disjoint sets.

## Environment notes

- The development host is the Hyper-V host and is a workgroup machine. The
    module pins Kerberos for its LDAP bind, so the enterprise suites run inside
    the lab through AutomatedLab credential delegation.
- `WindowsAccessControlLab` has 13 machines across three forests. After a host
    reboot the machines must be started before the acceptance runs, and the
    member fixture reports not ready for a short time while its services start.
- The full Sampler gate on this machine has one environmental failure,
    `Should reconverge all NTFS descriptor sections together`, which also fails
    on committed `4852a18`. The certificate private-key unit tests are flaky here
    for the same reason: they exercise the live key storage provider.

## Next step

OI-23 is closed by decision, and OI-24 and OI-27 are delivered, so OI-28 is the
only remaining focused issue. It gives the hosted build a coverage verdict it
can stand behind, because the merged verdict currently depends on a domain lab
that the hosted build cannot run.
