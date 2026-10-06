---
status: current
last-verified: 2026-10-06
owner: software-engineer
source: repository, git reflog, and public GitHub API evidence
---

# Active context

## Current task

Handoff 04 of the 2026-10-06 sequence is complete on the local branch
`ai/post-release-fixes`. The user confirmed the positioning:
`WindowsAccessControl` is the successor of NTFSSecurity, which is deprecated
and will be archived, as the NTFSSecurity 5.0.0-rc4 Gallery description and
change log already said on 2026-10-06. `docs/migration-from-ntfssecurity.md`
maps all 37 commands that the 4.2.6 and 5.0.0-rc4 manifests export, confirmed
against the built module, with the parameter and output differences and the
decision behind each missing feature. Every published example ran verbatim in
Core 7.6.6 and Desktop 5.1. The documentation index, the wiki Home page, the
README, and three See also lists point at the guide, and the README no longer
calls private keys read-only. The issue #4 reply is a draft in the handoff
`reports` folder. Next is handoff 05. No git remote was mutated.

Handoffs 01 to 03 made the lab runner refuse to delete what it did not
create, fixed the Task Scheduler, SMB, and AD review defects, and ported and
re-measured the performance refactor; the Desktop gate passes narrowly at
80.95 percent asserted coverage, and handoff 07 owns the first live and
installed-package acceptance of the refactor. On 2026-10-06 the user reviewed
all 14 recorded agent decisions of handoffs 01 to 03: twelve are accepted as
recorded, and the other two were overtaken by doing the work (the decision log
moved out of `systemPatterns.md`, and specs 0005 and 0006 name the descriptor
benchmark). WinRM stays enabled here. Later handoffs ask their own questions
with fresh evidence. The 2026-10-06 triage below remains the record of the
open work. `main` is `40e364a`, in sync with `origin/main`;
`ai/performance-refactor` stays at `5f06c03` until handoff 08 deletes it with
approval.

## Handoff sequence

Eight sequential handoff prompts now drive the open work. They live outside
the repository in the user's desktop folder
`WindowsAccessControl-handoffs-2026-10-06`, with a README, a ledger, and a
`reports` folder; trust that ledger and git history for progress. All prompts
commit to the local integration branch `ai/post-release-fixes`, created from
`ai/post-release-triage`. Execution order, which supersedes the triage order
below: 01 lab-runner ownership guard, 02 Task Scheduler, SMB, and AD
defects, 03 performance-refactor port, 04 NTFSSecurity guide and issue #4
draft, 05 Actions bumps, 06 changelog section, silent changelog pull request
step, and FIND-002, 07 live lab acceptance, 08 push, pull request, release,
and cleanup. Only 08 touches the remote, with approval per action.

## Release state

- `v0.3.0-preview0001` shipped from `40e364a` on 2026-09-07: Build run
  `34158650074` passed, and the GitHub release and PowerShell Gallery package
  were published at 20:32 UTC. The earlier "release awaits authorization"
  note was stale.
- `v0.2.0` is the current stable release (2026-09-06).
- The [reacceptance record](../docs/lab-reacceptance-2026-09-07.md) and the
  [security review](../docs/security-review-2026-09-07.md) remain the evidence
  for the shipped candidate.

## Open work, in recommended order

1. **Performance refactor, ported by handoff 03.** `ai/performance-refactor`
   (five commits on `5991673`, 2026-09-10, never pushed) is now on
   `ai/post-release-fixes` as `fbced95`, `d13a517`, and `b860448`, re-measured
   against the current baseline. Live-lab and installed-package acceptance of
   it never ran; handoff 07 owns them. The source branch stays at `5f06c03`
   until handoff 08 deletes it with approval.
2. **Repository-wide review findings (2026-09-10).** They were recorded only
   on that branch. Rechecked by reading `main` on 2026-10-06, not by running
   anything:
   - Blocker (lab harness), fixed by handoff 01 on `ai/post-release-fixes`:
     `tests/Lab/Invoke-WindowsAccessControlLabAcceptance.ps1` recursively
     deleted `-RemoteRepositoryPath` (only `ValidateNotNullOrEmpty`) on the
     domain controller and replaced any same-version module under
     `%ProgramFiles%\WindowsPowerShell\Modules\WindowsAccessControl`. It now
     refuses unmarked directories. The existing `C:\WacRepo` and the `0.0.1`
     installation on `F1ADC1` predate the marker, so 07 must decide what to do
     with them before its first run.
   - Post-release follow-ups (user, 2026-10-06): the SMB, certificate
     private-key, Task Scheduler, and foreign-principal suites recursively
     delete `C:\WindowsAccessControlLab\ModuleUnderTest` on the member server
     without an ownership check; it is a fixed child of the harness's marked
     member root. And `-SkipPayloadDeployment -ModuleSource Installed` with no
     payload root creates an unmarked root that a later full deployment
     refuses; it fails safe and can be removed by hand.
   - Major, fixed by handoff 02: `Test-WindowsTaskSchedulerSystemAce`
     refused a write that restores SYSTEM to a DACL without a SYSTEM ACE. A
     missing or null current DACL is still refused.
   - Major, fixed by handoff 02: `Set-WindowsSmbShareSecurityDescriptor`
     restored the description captured at target resolution, overwriting a
     concurrent edit.
   - Major: the opt-in ModuleFast path in the vendored `Resolve-Dependency.ps1`
     downloads and runs `bit.ly/modulefast` unverified. Disabled by default.
   - Major (CNG final read) is FIND-001, resolved on `main` by `f5731f1`.
   - Minor, fixed by handoff 02: `Get-ADObjectCallerEffectiveAccess` requested
     `nTSecurityDescriptor` it never used, and a caller without read-control
     access got a null-index error. Live evidence is owed by handoff 07.
   - Follow-ups: the batch dispatcher `CommandName`/`ObjectFamily` guard is
     tested since handoff 03, and handoff 04 corrected the README private-key
     statement against specification 0015.
3. **Dependabot pull requests #1-#3** bump `actions/checkout` to 7.0.1,
   `actions/upload-artifact` to 7.0.1, and `actions/download-artifact` to
   8.0.1. Their red test jobs are inherited: all three branch from `4806726`
   (2026-08-15, 42 commits behind `main`), whose own push build failed the
   same four NTFS path tests. `0502254` fixed those tests the next morning.
   The API's base `4c204ff` is the later branch tip, and its tests passed.
   All three merge cleanly onto `main`, and no test pins action versions.
   The v4 pins raise the Node.js 20 deprecation warning. Land the artifact
   pair together after reading the major-version release notes.
4. **Issue #4** (2026-09-07) asks whether this module replaces NTFSSecurity.
   Handoff 04 answered it in `docs/migration-from-ntfssecurity.md` and left
   the reply as a draft in the handoff `reports` folder. Handoff 08 posts it
   only with approval and only after the guide reaches `main`, because the
   linked URL returns 404 until then; re-check the NTFSSecurity Gallery state
   first. Observation for a later decision: `Remove-NTFSAccessRule` and
   `Remove-NTFSAuditRule` in their default `Exact` mode remove nothing and
   report nothing when no identical entry exists, which a migrated
   NTFSSecurity call that subtracts rights hits. The guide documents it; no
   behavior changed.
5. **Changelog.** The v0.2.0 run reported "Send changelog pull request" as
   successful, yet the repository has no closed pull request. Branch
   `updateChangelogAfterv0.2.0` (`38cdabd`) inserts `## [0.2.0]` directly
   below `[Unreleased]`, which would now mislabel seven post-0.2.0 entries;
   do not merge it as-is. Find the cause before the next stable release.
6. **FIND-002**: two test files still lack a final newline.
7. **Housekeeping**: remote `ai/test-gap-audit` is merged. The thirteen lab
   VMs, their checkpoints, and the administrator `%TEMP%` evidence are not
   visible from this session's account; confirm before keeping or removing
   them.

## Limits

Remote deletions, pull request comments, issue replies, pushes, and releases
need explicit user authorization. The review findings above were confirmed by
reading code, not by fault injection or live runs.
