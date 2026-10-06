---
status: current
last-verified: 2026-10-06
owner: software-engineer
source: repository, git reflog, and public GitHub API evidence
---

# Active context

## Current task

Post-release triage of open work on 2026-10-06. `main` is `40e364a`, in sync
with `origin/main`. No code was changed and no git remote was mutated. The
only repository-state change was restoring the deleted local branch
`ai/performance-refactor` at `5f06c03` so its commits survive reflog expiry.

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

1. **Orphaned performance refactor.** `ai/performance-refactor` holds five
   commits on `5991673` (2026-09-10): `a3e3152` plus review and documentation
   commits. It was never pushed, and its ref was deleted before 2026-10-05.
   Source and test files merge cleanly onto `main`; the Memory Bank files and
   `docs/README.md` conflict. Its CNG comparison change must be revalidated
   over `f5731f1`. Live-lab and installed-package acceptance never ran.
   Decide whether to rebase and finish it or drop it deliberately.
2. **Repository-wide review findings (2026-09-10).** They were recorded only
   on that branch. Rechecked by reading `main` on 2026-10-06, not by running
   anything:
   - Blocker (lab harness):
     `tests/Lab/Invoke-WindowsAccessControlLabAcceptance.ps1` recursively
     deletes `-RemoteRepositoryPath` (only `ValidateNotNullOrEmpty`) on the
     domain controller and replaces any same-version module under
     `%ProgramFiles%\WindowsPowerShell\Modules\WindowsAccessControl`. There is
     no ownership marker or backup; a High-impact confirmation is the only
     guard. Still present.
   - Major: `Test-WindowsTaskSchedulerSystemAce` returns `$false` when the
     current DACL has no SYSTEM ACE, so a write that restores SYSTEM is
     refused. Still present; no test pins it as intended behavior.
   - Major: `Set-WindowsSmbShareSecurityDescriptor` restores the description
     captured at target resolution, overwriting a concurrent edit. Still
     present.
   - Major: the opt-in ModuleFast path in the vendored `Resolve-Dependency.ps1`
     downloads and runs `bit.ly/modulefast` unverified. Disabled by default.
   - Major (CNG final read) is FIND-001, resolved on `main` by `f5731f1`.
   - Minor: `Resolve-WindowsADObjectTarget` always requests
     `nTSecurityDescriptor`, and `Get-WindowsADObjectRecord` indexes it
     without an absence check. `Get-ADObjectCallerEffectiveAccess` does not
     need it; the impact on callers without read-control access needs live
     evidence.
   - Follow-ups: `README.md` line 315 still calls private keys read-only; the
     batch dispatcher `CommandName`/`ObjectFamily` guard has no test.
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
