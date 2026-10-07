---
status: current
last-verified: 2026-10-07
owner: software-engineer
source: repository, GitHub API, PowerShell Gallery, and domain-lab evidence
---

# Active context

## Current task

The 2026-10-06 handoff sequence is complete. Handoff 07 ran on the Hyper-V
host that holds `WindowsAccessControlLab` on 2026-10-07 and accepted `main`
at `2ebb3a5`, built release-equivalent as `0.3.0-preview0002` with GitVersion
5.12.0. Its 25 module files are byte-identical to the package on the
PowerShell Gallery. Four full lab passes, built and installed in Desktop and
Core, each passed 97 cases with eight ready cleanup entries; the isolated
Desktop DSC-engine gate passed 5 of 5; and both local gates passed with the
fresh lab coverage merged: Core 1,931 passed at 91.22 percent asserted,
Desktop 1,886 at 90.49 percent, two environment skips each. The runner's two
ownership refusals were proven against run-owned decoys, and a byte and ACL
inventory proves the restoration. The
[acceptance record](../docs/lab-acceptance-2026-10-07.md) holds the evidence.

A follow-up the same day, at the user's request, gave the four handoff 02
paths that only unit tests covered their own live cases: the Task Scheduler
repair of a protected DACL without Local System, and the SMB description that
the native write clears, edits concurrently, or cannot read. Each case failed
for its expected reason against builds of `96d6671` and `5531824` and passed
against the candidate. All four passes were repeated with 101 cases each, and
both local gates passed again with the new lab coverage `B3EE4313…6FD6`.

The acceptance record, the follow-up test commit, and the two earlier Memory
Bank commits sit on the local branch `ai/record-post-release-publication` and
are not pushed, because any push to `main` publishes another preview. The
branch travels back to the development machine as a bundle in the handoff
folder, so these commits reach `main` together (user, 2026-10-07).

## Handoff sequence

Eight prompts in the user's desktop folder
`WindowsAccessControl-handoffs-2026-10-06` drove the post-release work; its
ledger and reports hold every ruling and the validation evidence. All eight
are done. The user accepted every agent decision of 01 to 08, answered the
07 housekeeping questions explicitly, and ran each remote step of 08 from
commands the agent handed over, because the house rules block agent pushes.

## Lab state

- All thirteen VMs run. Only checkpoint `wac07-pre-livegaps-83cd16fa`, taken
  before the follow-up, remains; the user had the 2026-09-07 checkpoints and
  `wac07-pre-2ebb3a5-b4de5d73` removed.
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
4. **Review finding, unscheduled:** the opt-in ModuleFast path in the vendored
   `Resolve-Dependency.ps1` downloads and runs `bit.ly/modulefast` unverified;
   it is disabled by default.
5. **Observation:** `Remove-NTFSAccessRule` and `Remove-NTFSAuditRule` in their
   default `Exact` mode remove nothing and report nothing when no identical
   entry exists, which a migrated NTFSSecurity call that subtracts rights
   hits. The migration guide documents it; a warning would be a behavior
   change and needs a specification update first.
6. **Watch:** CI has no lab coverage, so its Desktop asserted coverage stays
   near the 80.95 percent of 2026-10-06 against the 80 percent threshold;
   with lab evidence merged it is 90.49 percent. GitHub moves
   `ubuntu-latest`, which runs the publish job, to Ubuntu 26 from 2026-10-19.
## Limits

Agents may not push or otherwise mutate the remote, even with approval; the
user runs those commands. Pushes, merges, releases, remote deletions, and
pull request or issue comments need explicit user authorization. The
2026-09-10 review findings were confirmed by reading code, not by fault
injection or live runs.
