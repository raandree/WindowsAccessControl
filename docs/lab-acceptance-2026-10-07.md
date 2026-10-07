# Lab acceptance: 2026-10-07

Live domain-lab acceptance of the post-release candidate, `main` at `2ebb3a5`,
which the release workflow published as `v0.3.0-preview0002`. The run followed
the [acceptance checklist](../tests/Lab/acceptance-checklist.md). All four
full lab passes, the isolated Desktop DSC-engine gate, and both local test and
coverage gates passed. The lab-runner ownership refusals were also proven live.
This record is not release approval.

## Candidate and environment

- Commit: `2ebb3a54cb7b8411aeee5582b0daee5cb0ed112b` on `main`, the merge of
  pull request #5, with a clean worktree. Source, tests, and build inputs did
  not change during acceptance.
- Version: GitVersion 5.12.0, the official standalone Windows release run
  read-only, computed `0.3.0-preview0002`. The build received it through
  `$env:ModuleVersion`, as the [contributing guide](../CONTRIBUTING.md)
  describes, so the package is release-equivalent rather than the `0.0.1`
  development fallback.
- One detached `pack` built the module and the package: 22 tasks, zero errors,
  zero warnings. All 25 module files of the build, of the package, and of the
  `0.3.0-preview0002` package on the PowerShell Gallery are byte-identical, so
  these passes tested the bytes that users install.
- Lab: the existing isolated `WindowsAccessControlLab`, all thirteen VMs
  reused. No VM removal, redeployment, checkpoint restoration, or topology
  change was needed. AutomatedLab 5.61.704; lab Windows PowerShell
  5.1.26100.32684 and PowerShell 7.6.3; Pester 5.7.1 in both module roots;
  RSAT on every machine.
- Checkpoint `wac07-pre-2ebb3a5-b4de5d73` covers all thirteen VMs.
- Readiness was proven at the protocol level, not only by VM state, before
  the checkpoint, after it, and after each lab pass: WinRM on all thirteen
  machines; signed and sealed Kerberos LDAP rootDSE queries against both
  writable fixture controllers, each reporting `isSynchronized`; a
  ticket-granting ticket and `ldap` service tickets; ten marked baseline
  objects on both controllers with no leftover target; the member share, Task
  Scheduler folder, and lab key; and the published renewable CNG template.

## Payload and module ownership

The unmarked `C:\WacRepo` payload on `F1ADC1` predated the runner's ownership
marker, so the runner would have refused it. It was the payload of the
2026-09-07 `5991673` acceptance: 541 files, no junction or symbolic link,
built module SHA-256 `A70F3C1E…F019D`. An older unmarked `C:\WacLive` staging
directory from 2026-08-11 was also present. `F1ADC1` holds unmarked `0.0.1`
and `0.2.0` installations, and `F1DC1` an unmarked `0.0.1` installation. During
acceptance none of them was removed, marked, or changed: every pass used a
fresh, absent payload root, which the runner created and marked, and the
release-equivalent package version `0.3.0` did not collide with an existing
installation.

The two refusals from the lab-runner ownership change were proven against
run-owned decoys, so no pre-existing directory was put at risk:

- An unmarked decoy payload root was refused at the reset step with the
  documented message and resolution.
- An unmarked decoy `0.3.0` installation was refused at the install step,
  after the runner had created and marked a fresh payload root and its
  package staging directory.

Both decoys were byte-identical afterwards and carried no marker. The decoys
and the demonstration's own payload root were then removed.

## Lab results

| Gate | Passed | Failed | Skipped | Cleanup | Completed UTC |
| --- | ---: | ---: | ---: | --- | --- |
| Desktop DSC engine | 5 | 0 | 0 | Temporary installation removed | 14:26:09 |
| Built module, Desktop with coverage | 97 | 0 | 0 | Eight ready entries | 14:40:57 |
| Built module, Core | 97 | 0 | 0 | Eight ready entries | 14:49:06 |
| Installed package, Desktop | 97 | 0 | 0 | Eight ready entries | 15:03:49 |
| Installed package, Core | 97 | 0 | 0 | Eight ready entries | 15:11:58 |

These are four executions of the same 97 live cases, not 388 unique tests:
the 95 cases of 2026-09-07 plus the two Active Directory cases added after
them. Every full pass reported `Passed`, eight suites, zero skipped tests,
explicit native exit zero, and both domain and member readiness in all eight
cleanup entries. Per suite: domain lab 6, certificate private key 8, Task
Scheduler 8, SMB share 7, Active Directory object 16, schema default and
object type 35, foreign principal 5, and replication 12.

The DSC gate ran in an isolated Windows PowerShell 5.1 process on the reserved
member `F1AFile2`, staged with the exact built module. It includes both actual
`Invoke-DscResource` cases. It ran while the built pass used the shared
fixtures, which it does not touch, and it finished before the installed-package
pass. The installed-package pass installed the package at the `0.3.0` version
directory of the machine module path on `F1ADC1`; its 25 module files matched
the candidate and its marker was present.

## Changed behavior with live evidence

- Lab-runner ownership: both refusals above, plus marked creation of every
  payload root, package staging directory, and installed version directory.
- Active Directory: `Should evaluate a caller who cannot read the object
  security descriptor` and `Should report a missing directory object as not
  found` passed in all four passes, as did the earlier escaped-name and
  reused-GUID regressions.
- SMB share description: the live SMB case asserts that the share description
  is byte-identical after both the add and the exact remove, so the pre-write
  description read and the restore decision ran on a real share.
- Shared batching: the Active Directory, SMB share, and Task Scheduler
  commands that the live suites call dispatch through the refactored batching
  layer, so all four passes ran it. The certificate private-key commands do
  not use that layer.

Changed behavior that still has no live evidence, only unit tests:

- Repairing a Task Scheduler DACL that has no Local System ACE. The lab
  folder keeps a Local System rule, so the live suite never reaches that path.
- The SMB warning for a description edited during the DACL write, the restore
  of a description the write cleared, and the stop for a description that
  cannot be read before the write.
- The two recorded lab-runner follow-ups: member-server suites that delete
  `ModuleUnderTest` without an ownership check, and the unmarked root that
  `-SkipPayloadDeployment -ModuleSource Installed` creates.

## Artifact identity

| Artifact | SHA-256 |
| --- | --- |
| Tested root module | `8DCEC9CBFCF71359D253E536A7E30AF90DCE1B7D154E589DF571F58AA6B3F371` |
| Tested module manifest | `581F7E70ABEA58B3FB0B8D0A2C45FB79267207493CF9B215FAB285A3295F3785` |
| Tested package | `148C5558F205B11502FC0545C26BB4D44E64C06693FC6044AE05EF2D33B2860F` |
| PowerShell Gallery package | `3E122CC9BEA88C6C5D4B94492B1E91BB31F5BF445F35B61976B8472D0488CC03` |
| Fresh lab coverage | `BC34FE2BEFE59E39D5D79CDDF9D1278FE4F2149EBB1ABD4D222A77C9E917BA23` |

The two package files differ only in their packaging metadata; their module
files are identical. The new lab coverage measures 8,506 commands, of which
the domain-lab profile exercised 3,868 (45.47 percent); the harness reports
1,701 of them as reached only in the member-server runspace. It is not the
local or merged coverage percentage. The previous coverage document was
preserved before the run. The new one reached the configured coverage path
from the instrumented Desktop pass and matches the guest original
byte-for-byte.

## Local coverage gates

| Edition | Passed | Failed | Skipped | Asserted coverage | Whole-module coverage | Completed UTC |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Core 7.6.6 | 1,931 | 0 | 2 | 91.22% | 91.22% | 14:59:46 |
| Desktop 5.1.26100.33438 | 1,886 | 0 | 2 | 90.49% | 90.50% | 15:27:04 |

Both editions imported the fresh lab document and reported `Domain-lab
evidence merged: yes`; the 80 percent threshold and the asserted source scope
were unchanged. Each ten-task workflow completed with zero errors and two
warnings from deliberately mocked evidence-copy failures in the runner's unit
tests, not from actual acceptance collection. Each edition skipped the
mounted-volume case and the audit-rule read that needs an unavailable
privilege. The local gates ran on the host after the lab coverage was
collected, while the remaining lab work continued in the VMs; they touch
neither the lab nor its fixtures.

## Independent cleanup checks

Before anything was removed, all evidence files on `F1ADC1` and `F1AFile2`
matched their host copies, both controllers answered signed and sealed
Kerberos LDAP, ten marked baseline objects remained with no leftover target,
the member fixtures were ready, no HTTP.sys binding or suite backup file
remained, and every directory, KDC, DNS, ADWS, WinRM, and CA service ran.
Only directories that still carried the runner's marker, this run's console
logs, and the DSC staging were then removed.

A byte and ACL inventory taken before the run and again after cleanup shows no
difference in any path, length, hash, security descriptor, reparse flag, or
file time across the installations on `F1ADC1` and `F1DC1`, the module paths
of both file servers, `C:\WacRepo`, and `C:\WacLive`. All thirteen VMs were
running and all three checkpoint sets remained.

After these checks, at the maintainer's request, the two 2026-09-07
checkpoints were removed, as were `C:\WacRepo` and `C:\WacLive`, each first
re-verified file by file against the pre-run inventory. All thirteen VMs keep
running with checkpoint `wac07-pre-2ebb3a5-b4de5d73`, and the unmarked
installations on `F1ADC1` and `F1DC1` were kept. Without `C:\WacRepo`, the
runner's default payload root works again.

## Retention and remaining gates

Private evidence is retained under administrator `%TEMP%` in
`wac07-accept-2ebb3a5-b4de5d737dca43c6aabcf2b7100bd5b7`, in the profile's base
TEMP directory, because this host deletes per-session TEMP directories at
logoff. It holds the pinned candidate files, the Gallery package, the
GitVersion output, inspections, inventories, checkpoint identities, native
exit markers, raw console logs, per-pass reports, the coverage documents, and
the local test results. Raw evidence is not sanitized for publication. The
private evidence directories named in the 2026-09-07 records are no longer on
this host. Two agent-side completion markers reported failure although the
build and the Core gate succeeded, because their patterns missed a colored
summary line and a `succeeded with warnings` summary; the authoritative
summaries and exit codes are recorded.

All requested acceptance gates for this candidate are closed. A stable release
still requires explicit authorization to merge, tag, push, or publish. Broader
native fault injection, interrupted rollback, cancellation, soak tests,
unusual-ACE persistence, and untested topology profiles remain documented
limits, as do the changed paths listed above without live evidence.
