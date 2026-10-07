---
status: current
last-verified: 2026-10-07
owner: software-engineer
source: repository, GitHub API, and PowerShell Gallery evidence
---

# Active context

## Current task

The 2026-10-06 handoff sequence is complete except handoff 07. Pull request
#5 merged the integration branch into `main` at 13:01 UTC on 2026-10-07 as
merge commit `2ebb3a5`, and release run `37625244450` published
`v0.3.0-preview0002` to GitHub Releases and the PowerShell Gallery at 13:21
UTC; the wiki Home page carries the NTFSSecurity migration guide link.
GitVersion 5.12.0 had predicted that version on a simulated merge. The pull
request CI and the release run passed in both editions without a single
annotation, so the Node.js 20 deprecation warnings are gone. Dependabot #1-#3
are closed as superseded, and issue #4 has the approved reply (comment
`6038696531`); it stays open for the reporters to answer. The remote branches
`updateChangelogAfterv0.2.0`, `ai/post-release-fixes`, and
`ai/test-gap-audit` are gone, and the local branches `ai/post-release-fixes`,
`ai/post-release-triage`, and `ai/performance-refactor` were deleted with
approval. The house rules block every remote-mutating command from an agent,
even with approval, so the user ran each remote step from commands the agent
handed over, and the agent verified every result read-only. This record sits
on the local branch `ai/record-post-release-publication` and is not pushed,
because any push to `main` publishes another preview.

## Handoff sequence

Eight prompts in the user's desktop folder
`WindowsAccessControl-handoffs-2026-10-06` drove the post-release work; its
ledger and reports hold every ruling and the validation evidence. Handoffs 01
to 06 and 08 are done, and the user accepted all 22 agent decisions of 04 to
08 one by one. Handoff 07, live domain-lab acceptance of the merged candidate,
is Blocked: this machine has Hyper-V and AutomatedLab but no lab VMs. The user
keeps the 13 VMs, checkpoint `wac-pre-f5731f1-b1fe0b1f`, and the old evidence
until 07 has run.

## Release state

- `v0.3.0-preview0002` shipped from `2ebb3a5` on 2026-10-07.
- `v0.2.0` remains the stable release (2026-09-06).
- The [reacceptance record](../docs/lab-reacceptance-2026-09-07.md) and the
  [security review](../docs/security-review-2026-09-07.md) cover
  `v0.3.0-preview0001`; live evidence for the post-release changes is owed
  before the next stable release.

## Open work, in recommended order

1. **Handoff 07, live lab acceptance**, on the Hyper-V host that holds
   `WindowsAccessControlLab`, before the next stable release. It covers 01's
   lab-runner refusals (the unmarked `C:\WacRepo` and the `0.0.1` module on
   `F1ADC1` predate the marker and need a decision with fresh evidence), 02's
   new Active Directory live cases and the Task Scheduler and SMB behavior,
   and 03's shared batching, which so far only the full gates cover.
2. **Changelog pull request token.** `GitHubToken` is a fine-grained token,
   and the user is granting it "Pull requests: Read and write". The Actions
   setting "Allow GitHub Actions to create and approve pull requests" stays
   off, because it governs only `GITHUB_TOKEN`, which the changelog step does
   not use. The guard from handoff 06 fails the next stable release if the
   pull request is still refused.
3. **Lab-runner follow-ups** (user, 2026-10-06): the SMB, certificate
   private-key, Task Scheduler, and foreign-principal suites delete
   `C:\WindowsAccessControlLab\ModuleUnderTest` on the member server without
   an ownership check, and `-SkipPayloadDeployment -ModuleSource Installed`
   with no payload root creates an unmarked root that a later full deployment
   refuses.
4. **Review finding, unscheduled:** the opt-in ModuleFast path in the vendored
   `Resolve-Dependency.ps1` downloads and runs `bit.ly/modulefast` unverified;
   it is disabled by default.
5. **Observation:** `Remove-NTFSAccessRule` and `Remove-NTFSAuditRule` in their
   default `Exact` mode remove nothing and report nothing when no identical
   entry exists, which a migrated NTFSSecurity call that subtracts rights
   hits. The migration guide documents it; a warning would be a behavior
   change and needs a specification update first.
6. **Watch:** the Desktop gate's asserted coverage is 80.95 percent against
   the 80 percent threshold, and GitHub announced that `ubuntu-latest`, which
   runs the publish job, moves to Ubuntu 26 from 2026-10-19.

## Limits

Agents may not push or otherwise mutate the remote, even with approval; the
user runs those commands. Pushes, merges, releases, remote deletions, and
pull request or issue comments need explicit user authorization. The
2026-09-10 review findings were confirmed by reading code, not by fault
injection or live runs.
