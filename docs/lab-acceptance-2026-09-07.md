# Lab acceptance: 2026-09-07

Execution record for the [acceptance checklist](../tests/Lab/acceptance-checklist.md)
following the [test-gap audit](test-gap-audit-2026-09-06.md). All four lab
passes, the isolated DSC-engine gate, and both final local test and coverage
gates passed. This record is not release approval.

## Candidate and prerequisites

- Base commit: `5991673c276b0f957877a61fd77f7e94de7a9b7d` on
  `ai/test-gap-audit`, initially a clean worktree.
- The only executable change during acceptance is a test-fixture cleanup fix,
  protected by three new unit tests. Production source and package bytes did
  not change after the initial rebuild.
- Elevated Hyper-V host; AutomatedLab 5.61.704; thirteen existing VMs on the
  internal lab switch. No lab redeployment, removal, or checkpoint restoration.
- Checkpoint `wac-pre-5991673-884f8279` covers every existing VM and is retained.
- Both writable fixture controllers accepted signed and sealed Kerberos LDAP
  binds and rootDSE queries. AD readiness, RSAT, Pester 5.7.1, both PowerShell
  editions, WSMan, and the renewable schema-version-4 CNG template were checked.
- Local Core version: 7.6.5. Lab Core version: 7.6.3. Lab Desktop version:
  5.1.26100.32684. Isolated DSC ran on the prepared reserved member, not against
  the management controller's pre-existing module installations.

## Results

| Gate | Passed | Failed | Skipped | Cleanup |
| --- | ---: | ---: | ---: | --- |
| Built module, Desktop with coverage | 95 | 0 | 0 | Eight ready entries |
| Built module, Core | 95 | 0 | 0 | Eight ready entries |
| Installed package, Desktop | 95 | 0 | 0 | Eight ready entries |
| Installed package, Core | 95 | 0 | 0 | Eight ready entries |
| Isolated Desktop DSC engine | 5 | 0 | 0 | Owned installation and staging removed |
| Focused repaired replication suite | 12 | 0 | 0 | Both boundaries ready |
| New fixture regressions, each edition | 3 | 0 | 0 | Mocked directory boundary |
| Final local Core suite | 1,805 | 0 | 2 | Coverage gate passed |
| Final local Desktop suite | 1,760 | 0 | 2 | Coverage gate passed |

The four full passes exercised the same 95 cases, not 380 unique cases. Each
pass deployed a fresh payload and completed before the next started. The
sequence finished at 11:40:16 UTC with exit marker zero. All four reports say
`Passed`; each has eight suites and eight ready domain/member cleanup entries.
Both new escaped-DN and expected-GUID regressions passed in every pass.

The five DSC tests include both actual `Invoke-DscResource` cases. NUnit,
serialized Pester results, guest/host exit markers, and independent installation
cleanup checks agree. No test or assertion was weakened or skipped to pass.

Fresh local tests ran after lab evidence collection in separate processes.
Core asserted coverage is 91.16 percent, with 91.10 percent whole-module
coverage. Desktop asserted coverage is 90.41 percent, with 90.38 percent
whole-module coverage. The threshold remains 80 percent. Both editions imported
the successful lab document byte-for-byte and passed the coverage identity
check. The final gate completed at 12:08:04 UTC with exit marker zero.

The two local environment skips in each edition concern a mounted volume and
an unavailable SACL-read privilege. Each local build reported two intentional
mocked artifact-copy warnings, not failed lab evidence collection. Both test
workflows completed ten tasks with zero errors. The monitor was stopped after
the retained results and successful completion markers were verified.

## Failure found and repaired

The initial instrumented Desktop run passed all 95 test bodies but failed the
replication container in `AfterAll`. The new GUID-reuse case deleted both
objects by GUID while leaving the original DN registered for later cleanup.
The second deletion raised a terminating `ADIdentityNotFoundException` and
aborted cleanup of eight subsequent disposable OUs. The runner correctly
retained `Result = 'Failed'` and an unready domain boundary.

[The fix](../tests/Lab/ADObjectReplication.Live.Tests.ps1) releases the obsolete
registration only after successful original-GUID deletion. The replacement
keeps its exact-GUID `finally` cleanup.
[Three lifecycle regressions](../tests/Unit/Lab/ADObjectReplicationFixtureSafety.Tests.ps1)
cover success, original deletion failure, and replacement creation failure.
Two failed before the fix; all three pass in both editions afterward.
Static analysis of both changed scripts reports zero findings.

Before retrying, the eight leftover GUIDs, creation times, DACLs, and absence
of children were verified against captured evidence. Cleanup deleted only
those identities. Replicated cleanup restored the ten-object marked baseline
on the fixture domain. The focused live rerun then passed before the full
four-pass sequence restarted. Failed-run evidence remains separate and is not
used as the successful acceptance report or coverage source.

## Artifact identity and retention

The detached `pack` workflow completed 22 tasks with zero errors or warnings.
The local package version is `0.0.1`, the GitVersion fallback, not a release.
All 25 module files matched the package, including command help, format data,
and all 20 DSC help files. All 25 installed candidate files were also verified.

| Artifact | SHA-256 |
| --- | --- |
| Rebuilt package | `3D2A97578B142B3131283AF5D519302CE90DB9A6B036B867C0914A2B96505CA7` |
| Built and installed root module | `A70F3C1E5347C8196D5A9656F785C91B9008316E54778C0A3ED389D2DAEF019D` |
| Successful lab coverage | `13B030B0D910B639E1BBDF1FA5E948397786EBC3622E1B5F4897A30215EB20DF` |

Private host evidence is retained under administrator `%TEMP%` in
`wac-acceptance-5991673-884f827956f442e0974735805d7d0d0c`. It contains the
candidate, build logs, failed-run evidence, successful per-edition JSON and
guest consoles, DSC NUnit/Pester results, cleanup inventories, local results,
and the orchestration scripts. Share only the redacted acceptance reports;
raw logs and local diagnostics are not sanitized and must not be published.

## Final lab state and release limits

All thirteen VMs and checkpoints remain. Both fixture controllers answer
signed/sealed Kerberos LDAP, with zero leftover targets. The ten marked domain
objects and member fixtures are ready. Directory, DNS, KDC, ADWS, WinRM, and CA
services are running. No acceptance process or raw payload log remains.

The original `0.0.1` installation was preserved and restored with its four
original file hashes and directory ACL unchanged; `0.2.0` was not replaced.
DSC staging, focused-test staging, and preservation directories were removed
after evidence verification. The fresh lab payload and baseline fixtures remain
available. No merge into main, publication, or remote push was performed.

Independent security review remains recommended for the containment, immutable
identity, and exact-ACE changes. The redundant CNG post-write read still needs
targeted failure injection and resolution before stable-release approval.
The audit's native-failure, soak, unusual-ACE persistence, and topology limits
remain open; these passes do not establish atomic multi-controller writes.
