---
status: current
last-verified: 2026-08-04
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

The domain-lab coverage document is current again, so the merged whole-module
coverage number is measured evidence rather than a remembered figure. This was
the last operational candidate recorded after the publish pipeline closed.

## What changed

No repository file changed. The run refreshed the local, gitignored artifact
`tests/Lab/coverage/JaCoCo_coverage_DomainLab.xml`, which the build imports.

The stale document had been measured on 2026-08-02 against a module the current
`main` no longer produces: it covered a 6,916-command profile with line numbers
up to 26545, while the module built from `ce4eea0` has 27,413 lines.
`Assert-JaCoCoDocumentIdentity` therefore refused it, and the build fell back to
the empty "absent" document and reported the domain-lab-only files instead of
asserting them.

## Acceptance evidence

- All 13 `WindowsAccessControlLab` machines were Running; the host session was
    elevated on PowerShell 7.6.3; the working tree was clean at `ce4eea0`.
- `tests/Lab/Invoke-WindowsAccessControlLabAcceptance.ps1` is green: 6 suites,
    45 passed, 0 failed, 0 skipped, `Result = Passed`, 19:26:03Z to 19:41:48Z.
    Per suite: DomainLab 4, CertificatePrivateKey 7, TaskScheduler 8, SmbShare
    7, ADObjectPermissions 12, ADObjectReplication 7. Every suite reported
    `Ready = True` on both the domain and the member boundary.
- The new document measures 42.83 percent (3,403 of 7,945 commands), of which
    1,699 are member-only.
- `./build.ps1 -Tasks test` succeeds: 10 tasks, 0 errors, 0 warnings. Local
    Pester is 1,495 passed, 0 failed, 0 skipped, 0 inconclusive, 0 not run.
- `Import_DomainLab_Code_Coverage` accepted the document rather than falling
    back, and `Assert_Merged_Code_Coverage_Threshold` reports
    `Domain-lab evidence merged: yes`.
- Whole-module coverage is 90.48 percent (7,189 of 7,945 commands), reported.
    The asserted scope is 90.52 percent (6,950 of 7,678 commands the local test
    profile can execute) against the 80 percent threshold, per ADR 0025 and
    ADR 0027.

## Why no rebuild was inserted

The lab document and the local run must measure the identical merged `.psm1`,
or the identity guard refuses the merge. The built module at `0.0.1` already
matched `ce4eea0` (the last two commits touched only `build.yaml`, the workflow,
and documentation), and the `test` workflow does not rebuild, so both runs
measured the same file without a rebuild between them.

## Repository setup

The `publish` job needs two repository secrets under Settings > Secrets and
variables > Actions: `GitHubToken` and `GalleryApiToken`. Without both, the job
fails on its verification step rather than publishing a partial release. The
module manifest still has no `LicenseUri` and no `ProjectUri`; the Gallery
accepts the package without them but shows no links.

One detail was not reconciled: at the moment of confirmation
`git ls-remote --tags origin` listed no `v*` tag, and the repository is private
so the run could not be read from here. Confirm the tag, the GitHub release, and
the Gallery version agree on the next release.

## Environment notes

- The development host is the Hyper-V host and is a workgroup machine. The
    module pins Kerberos for its LDAP bind, so the enterprise suites run inside
    the lab through AutomatedLab credential delegation.
- `WindowsAccessControlLab` has 13 machines across three forests. After a host
    reboot the machines must be started before the acceptance runs, and the
    member fixture reports not ready for a short time while its services start.
- A standalone Pester run must prepend `output/module` and
    `output/RequiredModules` to `PSModulePath`. Without them, 36 DSC discovery
    and Sampler-dependent tests fail for a reason none of them caused.
- The certificate private-key unit tests remain flaky here because they
    exercise the live key storage provider.
- The committed domain-lab coverage document still measures a module the current
    `main` build does not produce, so the merged whole-module verdict is
    reported rather than asserted until the lab acceptance is rerun.

## Next step

No specification is in `Draft`, no focused issue is open, and no operational
candidate remains. Rerun the lab acceptance whenever a source change moves the
merged `.psm1`, because the identity guard then refuses the previous document
and the whole-module number silently degrades to reported-only.

Every other candidate (SMB-6, AD-7, directory audit rules, directory
inheritance and owner/group mutation, CAPI) is a written deferral and needs a
new accepted scope decision before implementation.
