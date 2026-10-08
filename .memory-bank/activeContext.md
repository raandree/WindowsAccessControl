---
status: current
last-verified: 2026-10-08
owner: software-engineer
source: repository, GitHub API, PowerShell Gallery, and domain-lab evidence
---

# Active context

## Current task

The stable release `v0.3.0` shipped on 2026-10-08, at the user's request.
The user pushed the tag `v0.3.0` on `323928b`, the commit `v0.3.0-preview0003`
came from, and its run `37773125964` published the GitHub release, marked
Latest, the PowerShell Gallery's stable `0.3.0`, and the wiki. The stable
package differs from `0.3.0-preview0003` only in the manifest's prerelease
label and release-notes heading, so its root module is still the one the
domain lab accepted. The handoff 06 guard ran for the first time and passed:
Sampler opened the changelog pull request #7 from
`updateChangelogAfterv0.3.0`, which adds the `## [0.3.0] - 2026-10-08`
heading to `CHANGELOG.md`. Merging #7, after its CI, is the user's last step;
the merge starts no build, because the push ignores a change to only
`CHANGELOG.md`.

Handoff 09 is done. Pull request #6 merged
`ai/record-post-release-publication` into `main` as the merge commit `323928b`
on 2026-10-08, and the release run published `v0.3.0-preview0003`, the
version GitVersion 5.12.0 computed for a simulated merge beforehand. The user
had pushed the branch from the lab host before 09 ran, so its twelve commits
reached `main` unchanged, with the SHAs that the records cite:

- The two Memory Bank records of handoff 08 and the ten commits of handoff 07.
  One changes the module: `4096d02` routes `Get-WindowsADRootDse` and
  `Get-WindowsADEffectiveAccessRecord` through `Send-WindowsADSearchRequest`,
  so unit tests reach their four response guards, and a directory object
  deleted during `Get-ADObjectCallerEffectiveAccess` now fails with
  `ItemNotFoundException` (changelog `Changed`).
- `6ea9d7e`, `938bdff`, and `bad1302` give every command in the declared
  domain-lab-only files a test, each red against a build with its guard
  removed; `a572d3d` stops arming member coverage from leaving a member
  session stopping on every error.
- The [2026-10-07](../docs/lab-acceptance-2026-10-07.md) and
  [2026-10-08](../docs/lab-acceptance-2026-10-08.md) records hold the
  domain-lab acceptance of `2ebb3a5` and of the branch candidates `bad1302`
  and `a572d3d`, whose root modules are byte-identical.

Before the pull request, both local gates passed on `a95321c` without lab
coverage, as CI runs them: Core 1,938 tests at 83.19 percent asserted
coverage and Desktop 1,893 at 80.95 percent. CI on the pull request and on
`main` reported the same figures, with no error or warning annotation.

The CopilotAtelier `automatedlab-deployment` Skill warning about
`Remove-LabVMSnapshot` (`3f06142` on the local branch
`ai/automatedlab-snapshot-children` there) left 09: the user moved its push,
pull request, and merge to a prompt of their own in CopilotAtelier.
CopilotAtelier brief 01 waits for that merge, because both change that
repository's `CHANGELOG.md` under `[Unreleased]`.

## Handoff sequence

Nine prompts in the user's desktop folder
`WindowsAccessControl-handoffs-2026-10-06` drove the post-release work; its
ledger and reports hold every ruling and the validation evidence. All nine
are done. The user accepted every agent decision of 01 to 08, answered the
07 housekeeping questions explicitly, and ran each remote step of 08 and 09
from commands the agent handed over, because the house rules block agent
pushes.

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
  evidence of 2026-09-07 is no longer there. The 2026-10-07 and 2026-10-08
  evidence sits in the profile's base TEMP directory; the user approved its
  removal once the branch reached `main` (2026-10-08), which is done on the
  lab host, not from the development machine.

## Release state

- `v0.3.0` is the stable release, shipped from `323928b` on 2026-10-08 with
  the user's authorization. The unexplained `WacLab$` description loss of
  open work item 3 did not block it (user).
- `v0.3.0-preview0003` shipped from `323928b` on 2026-10-08. Its root module
  is byte-identical to the one the domain lab accepted on 2026-10-08
  (`A9671FD0…21CA`), and the Gallery and GitHub packages carry the same 25
  module files.
- `v0.3.0-preview0002` shipped from `2ebb3a5` on 2026-10-07 and is accepted
  in the domain lab, on the installed package as well.
- `v0.2.0` was the previous stable release (2026-09-06).
- Any later stable release needs explicit authorization to tag, push, or
  publish. Sampler's changelog step reads the tags on `origin/main`'s head
  and pushes its branch with `GitHubToken`, so tag `main`'s newest commit,
  merge nothing until the run ends, and keep the token's "Contents" and
  "Pull requests" permissions at "Read and write".

## Open work, in recommended order

1. **Lab-runner follow-ups** (user, 2026-10-06): the SMB, certificate
   private-key, Task Scheduler, and foreign-principal suites delete
   `C:\WindowsAccessControlLab\ModuleUnderTest` on the member server without
   an ownership check, and `-SkipPayloadDeployment -ModuleSource Installed`
   with no payload root creates an unmarked root that a later full deployment
   refuses.
2. **Observation, 2026-10-07:** `Invoke-WindowsAccessControl` writes one
   `$null` when its script block returns nothing, so `@()` around it counts
   one item. Emitting nothing instead would be a behavior change and needs a
   specification update first.
3. **Observation, 2026-10-08:** a prototype that stopped a remote job blocked
   on the share-write confirmation and then wrote again left the `WacLab$`
   description empty with its DACL unchanged. Four controlled replays did not
   reproduce it; the cause is not established. It did not block the stable
   release `v0.3.0` (user, 2026-10-08).
4. **Review finding, unscheduled:** the opt-in ModuleFast path in the vendored
   `Resolve-Dependency.ps1` downloads and runs `bit.ly/modulefast` unverified;
   it is disabled by default.
5. **Observation:** `Remove-NTFSAccessRule` and `Remove-NTFSAuditRule` in their
   default `Exact` mode remove nothing and report nothing when no identical
   entry exists, which a migrated NTFSSecurity call that subtracts rights
   hits. The migration guide documents it; a warning would be a behavior
   change and needs a specification update first.
6. **Watch:** CI has no lab coverage, so its Desktop asserted coverage stays
   at 80.95 percent against the 80 percent threshold, again on 2026-10-08;
   with lab evidence merged it is 90.53 percent. GitHub moves
   `ubuntu-latest`, which runs the publish job, to Ubuntu 26 from 2026-10-19.

## Limits

Agents may not push or otherwise mutate the remote, even with approval; the
user runs those commands. Pushes, merges, releases, remote deletions, and
pull request or issue comments need explicit user authorization. The
2026-09-10 review findings were confirmed by reading code, not by fault
injection or live runs.
