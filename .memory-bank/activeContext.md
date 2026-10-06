---
status: current
last-verified: 2026-10-06
owner: software-engineer
source: repository, git reflog, and public GitHub API evidence
---

# Active context

## Current task

Handoff 03 of the 2026-10-06 sequence is complete on the local branch
`ai/post-release-fixes`; the user chose to finish the orphaned performance
refactor. `fbced95` ports its code, tests, and benchmarks from
`ai/performance-refactor` as one revertable `perf:` commit, and `d13a517` and
`b860448` port its documentation; every Memory Bank hunk resolved to the
current files. The ported private-key DACL comparison holds over the FIND-001
returned-bytes setter, and the seven batch adapters still pass handoff 02's
Task Scheduler, SMB, and AD parameters unchanged. `87d4f35` pins the
dispatcher's `CommandName`/`ObjectFamily` guard and an NTFS adapter worker's
per-target parameter copy; each test failed with its guard removed. The
`docs(performance)` commit re-measured both benchmarks before and after the
`perf:` commit: hashes and checksums match, and the gains hold. One
independent review approved with one Minor and three Nits, all addressed. The
ported `5f06c03` body was reworded because "Major" in it would have made the
next release 1.0.0. The Desktop gate still fails only the two WinRM-bound
DSC-engine tests. No live lab run took place; handoff 07 owns the first live
and installed-package acceptance of the refactor. Next is handoff 04. No git
remote was mutated.

Handoffs 01 and 02 made the lab runner refuse to delete what it did not
create and fixed the Task Scheduler, SMB, and AD review defects. The
2026-10-06 triage below remains the record of the open work. `main` is
`40e364a`, in sync with `origin/main`; `ai/performance-refactor` stays at
`5f06c03` until handoff 08 deletes it with approval.

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
   - Follow-up (review of handoff 01, not scheduled): the SMB, certificate
     private-key, Task Scheduler, and foreign-principal suites recursively
     delete `C:\WindowsAccessControlLab\ModuleUnderTest` on the member server
     without an ownership check; it is a fixed child of the harness's marked
     member root.
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
   - Follow-ups: `README.md` line 315 still calls private keys read-only. The
     batch dispatcher `CommandName`/`ObjectFamily` guard is tested since
     handoff 03.
3. **Dependabot pull requests #1-#3** bump `actions/checkout` to 7.0.1,
   `actions/upload-artifact` to 7.0.1, and `actions/download-artifact` to
   8.0.1. Their red test jobs are inherited: all three branch from `4806726`
   (2026-08-15, 42 commits behind `main`), whose own push build failed the
   same four NTFS path tests. `0502254` fixed those tests the next morning.
   The API's base `4c204ff` is the later branch tip, and its tests passed.
   All three merge cleanly onto `main`, and no test pins action versions.
   The v4 pins raise the Node.js 20 deprecation warning. Land the artifact
   pair together after reading the major-version release notes.
4. **Issue #4** (2026-09-07, unanswered) asks whether this module replaces
   NTFSSecurity. `docs/README.md` and `source/WikiSource/Home.md` promise an
   NTFSSecurity migration map, but `docs/migration-from-ntfspermission.md`
   covers only the unpublished NTFSPermission rename. Source material:
   `docs/research.md#detailed-ntfssecurity-comparison`.
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
