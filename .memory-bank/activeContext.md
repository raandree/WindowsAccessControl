---
status: current
last-verified: 2026-08-02
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

OI-27 is closed. The 80 percent code-coverage threshold is now asserted over the
locally measured commands merged with the domain-lab acceptance, so the gate
measures what the suites actually exercise. The threshold is unchanged and no
test was added to reach it.

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

OI-23 is closed by decision and OI-24 is the only remaining focused issue. It
adds private-key portability and desired state, its three binding constraints
are recorded in the open-issues register, and it must pass through the
specification 0015 write boundary rather than around it.
