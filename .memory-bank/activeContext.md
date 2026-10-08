---
status: current
last-verified: 2026-10-08
owner: software-engineer
source: repository, GitHub API, PowerShell Gallery, and domain-lab evidence
---

# Active context

## Current task

Handoff 07 and its follow-ups are done. Asked on 2026-10-07 whether every live
test was done, the user chose to give a test to each of the 17 commands in the
declared domain-lab-only files that nothing executed, including a source change
to make four of them unit-testable. The
[2026-10-08 acceptance](../docs/lab-acceptance-2026-10-08.md) accepted the
branch candidate `bad1302`, built as `0.3.0-record` with GitVersion 5.12.0:

- `4096d02` routes `Get-WindowsADRootDse` and
  `Get-WindowsADEffectiveAccessRecord` through `Send-WindowsADSearchRequest`,
  so six unit cases reach their four guards. A deleted object during
  `Get-ADObjectCallerEffectiveAccess` now reports `ItemNotFoundException`
  (changelog `Changed`).
- `938bdff` and `bad1302` add eight live cases: five SMB share guards with the
  confirmation prompt, two injected enrichment failures, and a deletion inside
  the effective-access read. Each was red against a build with its guard
  removed.
- DSC 5 of 5; four passes of 109 cases with eight ready cleanup entries; local
  gates Core 1,937 at 91.26 percent and Desktop 1,892 at 90.53 percent
  asserted; domain-lab-only coverage 100 percent, 154 of 154.

The user then had the harness defect of that round corrected and its
AutomatedLab lesson moved into the shared Skill (2026-10-08):

- `a572d3d` runs the remote body of `Enter-WindowsAccessControlMemberCoverage`
  in a child scope, so arming coverage no longer leaves a member session
  stopping on every error. A unit case failed with `Stop` before the change,
  a live probe showed both behaviors, a built pass ran 109 of 109 in both
  editions with line-identical lab coverage, and the local gates passed:
  Core 1,938 and Desktop 1,893. The record's Harness correction section holds
  the evidence.
- The CopilotAtelier `automatedlab-deployment` Skill now warns, on a local
  branch there, that `Remove-LabVMSnapshot` deletes the named checkpoint's
  subtree, with a per-VM recipe that keeps newer checkpoints. Merging and
  deploying it is the user's step; deploying rewrites the installed copy that
  running sessions use.

The [2026-10-07 record](../docs/lab-acceptance-2026-10-07.md) holds the
acceptance of `2ebb3a5` as `0.3.0-preview0002` and the first follow-up. Every
commit since `ce22f00` sits on the local branch
`ai/record-post-release-publication` and is not pushed, because any push to
`main` publishes another preview. The branch returns to the development machine
as a bundle in the handoff folder, so these commits reach `main` together
(user, 2026-10-07).

## Handoff sequence

Eight prompts in the user's desktop folder
`WindowsAccessControl-handoffs-2026-10-06` drove the post-release work; its
ledger and reports hold every ruling and the validation evidence. All eight
are done. The user accepted every agent decision of 01 to 08, answered the
07 housekeeping questions explicitly, and ran each remote step of 08 from
commands the agent handed over, because the house rules block agent pushes.

## Lab state

- All thirteen VMs run with one checkpoint, `wac07-after-bad1302-9d9776ca`,
  taken after the 2026-10-08 acceptance. Removing `wac07-pre-livegaps-83cd16fa`
  with `Remove-LabVMSnapshot` also deleted its child
  `wac07-pre-938bdff-098b3392` on ten VMs, so the user had the new checkpoint
  taken and the remaining old ones merged away with `Remove-VMSnapshot`.
- The unmarked `C:\WacRepo` and `C:\WacLive` folders on `F1ADC1` were removed
  at the user's request after the run proved them unchanged, so the runner's
  default `-RemoteRepositoryPath` works again.
- The unmarked `0.0.1` and `0.2.0` installations on `F1ADC1` and the `0.0.1`
  installation on `F1DC1` stay (user). An installed-package pass of a `0.0.1`
  fallback build is therefore still refused on `F1ADC1`; build acceptance
  candidates with the GitVersion version.
- The lab host deletes per-session TEMP directories at logoff, and the private
  evidence of 2026-09-07 is no longer there. The 2026-10-07 evidence sits in
  the profile's base TEMP directory.

## Release state

- `v0.3.0-preview0002` shipped from `2ebb3a5` on 2026-10-07 and is now
  accepted in the domain lab, on the installed package as well.
- `v0.2.0` remains the stable release (2026-09-06).
- A stable release still needs explicit authorization to merge, tag, push,
  or publish.

## Open work, in recommended order

1. **Changelog pull request token.** `GitHubToken` is a fine-grained token,
   and the user is granting it "Pull requests: Read and write". The Actions
   setting "Allow GitHub Actions to create and approve pull requests" stays
   off, because it governs only `GITHUB_TOKEN`, which the changelog step does
   not use. The guard from handoff 06 fails the next stable release if the
   pull request is still refused.
2. **Lab-runner follow-ups** (user, 2026-10-06): the SMB, certificate
   private-key, Task Scheduler, and foreign-principal suites delete
   `C:\WindowsAccessControlLab\ModuleUnderTest` on the member server without
   an ownership check, and `-SkipPayloadDeployment -ModuleSource Installed`
   with no payload root creates an unmarked root that a later full deployment
   refuses.
3. **Observation, 2026-10-07:** `Invoke-WindowsAccessControl` writes one
   `$null` when its script block returns nothing, so `@()` around it counts
   one item. Emitting nothing instead would be a behavior change and needs a
   specification update first.
4. **Observation, 2026-10-08:** a prototype that stopped a remote job blocked
   on the share-write confirmation and then wrote again left the `WacLab$`
   description empty with its DACL unchanged. Four controlled replays did not
   reproduce it; the cause is not established.
5. **Review finding, unscheduled:** the opt-in ModuleFast path in the vendored
   `Resolve-Dependency.ps1` downloads and runs `bit.ly/modulefast` unverified;
   it is disabled by default.
6. **Observation:** `Remove-NTFSAccessRule` and `Remove-NTFSAuditRule` in their
   default `Exact` mode remove nothing and report nothing when no identical
   entry exists, which a migrated NTFSSecurity call that subtracts rights
   hits. The migration guide documents it; a warning would be a behavior
   change and needs a specification update first.
7. **Watch:** CI has no lab coverage, so its Desktop asserted coverage stays
   near the 80.95 percent of 2026-10-06 against the 80 percent threshold;
   with lab evidence merged it is 90.53 percent (2026-10-08). GitHub moves
   `ubuntu-latest`, which runs the publish job, to Ubuntu 26 from 2026-10-19.
## Limits

Agents may not push or otherwise mutate the remote, even with approval; the
user runs those commands. Pushes, merges, releases, remote deletions, and
pull request or issue comments need explicit user authorization. The
2026-09-10 review findings were confirmed by reading code, not by fault
injection or live runs.
