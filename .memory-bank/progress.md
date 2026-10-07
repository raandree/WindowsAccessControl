---
status: current
last-verified: 2026-10-06
owner: software-engineer
source: repository evidence
---

# Progress

## Current status

`v0.3.0-preview0002` shipped from `2ebb3a5` on 2026-10-07; `v0.2.0` remains
the stable release. Pull request #5 carried the post-release work that a
2026-10-06 triage split into eight handoffs: the lab-runner Blocker, the Task
Scheduler, SMB, and AD review defects, the performance refactor, the
NTFSSecurity migration guide, the Node 24 action releases, the restored 0.2.0
changelog section with a release guard, and FIND-002. Handoff 07, live lab
acceptance, is still owed before the next stable release. `activeContext.md`
holds the open work.

## Recent milestones

- 2026-10-07: Published `v0.3.0-preview0002`. The user answered every pending
    question and ran each remote step from commands the agent handed over,
    because the house rules block agent pushes; the agent verified each
    result read-only. Pull request #5 passed CI in both editions without an
    annotation and merged as `2ebb3a5`; the GitHub release, the Gallery entry,
    and the wiki Home page carry the version GitVersion had predicted.
    Dependabot #1-#3 are closed as superseded, issue #4 has its reply, and
    the stale branches are deleted.

- 2026-10-06: With the user's overnight delegation, handoff 07 was recorded
    as Blocked (no lab VMs on this machine) and handoff 08 was prepared up to
    its first remote action: a pull request body on the repository template,
    and a simulated merge that GitVersion 5.12.0 versions as
    `0.3.0-preview0002`. Both full gates pass on `023afe9`: Core 1,931 tests
    at 83.11 percent asserted coverage, Desktop 1,886 at 80.95 percent.

- 2026-10-06: Handoff 06 restored the `## [0.2.0] - 2026-09-06` section that
    the release never merged, with a multiset proof that no content line
    moved, and made a missing changelog pull request end the release:
    Sampler's task catches a refused creation and only logs it, which is why
    the green v0.2.0 step left no pull request behind. The publish job now
    asks the API for that branch's pull request; a token without pull-request
    access is the likeliest cause, and the run log would settle it. FIND-002
    is closed, and QA, Build, and the two suites pass 709 tests per edition.

- 2026-10-06: Handoff 05 moved the build workflow to the Node 24 releases of
    `checkout` 7.0.1, `upload-artifact` 7.0.1, and `download-artifact` 8.0.1,
    each pinned by the SHA its own tag resolves to. Every release note from v4
    to the target was checked against this workflow; no input changed meaning,
    so the commit is seven pins. `download-artifact` v8 now fails a job on a
    digest mismatch instead of warning, which is kept. A new test holds every
    `uses:` to a SHA pin with a version comment and a Node 24 release line.
    Dependabot #1 to #3 are superseded; the pull-request CI in 08 is the proof.

- 2026-10-06: Handoff 04 documented the move from NTFSSecurity, which the
    user positioned as deprecated, with `WindowsAccessControl` as its
    successor. `docs/migration-from-ntfssecurity.md` maps every command of the
    NTFSSecurity 4.2.6 and 5.0.0-rc4 manifests, confirmed against the built
    module, and names what changes for a migrated script: exact removal by
    default, confirmation prompts, `AppliesTo` instead of flags, and long
    paths only in PowerShell 7. Its examples ran verbatim in both editions.
    The README private-key statement now matches specification 0015, and the
    issue #4 reply is drafted but not posted.

- 2026-10-06: The user reviewed all 14 recorded agent decisions of handoffs
    01 to 03 and accepted twelve as recorded. The other two were overtaken:
    the decision log moved unchanged to `topics/decision-log.md`, bringing
    `systemPatterns.md` within budget, and specs 0005 and 0006 now name the
    descriptor benchmark and the per-instance rights cache. WinRM stays
    enabled; the two lab-runner follow-ups are post-release items.

- 2026-10-06: Handoff 03 finished the orphaned performance refactor on
    `ai/post-release-fixes`, as the user chose. Its code, tests, and
    evidence were ported without the old Memory Bank hunks, and the code
    stays one revertable commit. A new test pins the dispatcher's
    `CommandName`/`ObjectFamily` guard, and one pins an adapter worker's
    per-target parameter copy; each failed with its guard removed.
    Re-measured in fresh processes against the branch before the port, with
    matching hashes and checksums: Core rights display 69 percent faster,
    removed ACEs 66, dispatch 18, isolated CNG 15; Desktop removed ACEs 95.
    The Core gate passes 1,917 tests with two environmental skips at 83.11
    percent asserted coverage. Once WinRM ran on the development machine,
    the Desktop gate passed 1,872 at 80.95 percent asserted coverage; before
    that, only its two WinRM-bound DSC-engine tests failed. One
    independent review approved; its Minor and three Nits were addressed.

- 2026-10-06: Handoff 02 fixed three review defects test-first on
    `ai/post-release-fixes`, one commit each. A Task Scheduler write may
    repair a DACL without a Local System ACE; a missing or null current DACL
    is still refused. An SMB DACL write reads the description just before
    the native call, keeps concurrent edits, and warns instead of failing
    after a committed write. `Get-ADObjectCallerEffectiveAccess` no longer
    requests `nTSecurityDescriptor`; an absent descriptor elsewhere raises a
    typed read-control error. The Core gate passes 1,905 tests with two
    environmental skips at 83.2 percent asserted coverage. The Desktop gate
    fails only the two WinRM-bound DSC-engine tests; its scoped coverage,
    computed from its document, is 81.03 percent. One review approved with
    minor findings, most fixed. No live lab run; 07 owns two new AD cases.

- 2026-10-06: Handoff 01 made the domain-lab acceptance runner refuse to
    delete what it did not create, test-first on `ai/post-release-fixes`. It
    marks the payload root, `package`, and installed module version directory
    it creates; replaces only absent or marked directories with no junction or
    symbolic link inside; validates the payload root on the management
    controller in every mode; and stops when a remote step does not confirm
    its directory, because AutomatedLab does not stop on a remote throw. 79
    lab-runner tests pass in Core 7.6.6 and Desktop 5.1; the full gate passes
    1,873 tests with two environmental skips at 83.0 percent asserted coverage.
    One independent review approved with Minor findings; seven fixed, three
    recorded. No live lab run; handoff 07 owns it.

- 2026-10-06: Wrote eight sequential handoff prompts for the triaged work,
    outside the repository, with a ledger and per-prompt reports. They commit
    to local `ai/post-release-fixes`; only the final prompt touches the
    remote, with approval per action.

- 2026-10-06: Triaged open work. Verified from git, the public GitHub API,
    and the PowerShell Gallery that `v0.3.0-preview0001` shipped on
    2026-09-07, so the pending-authorization note was stale. Found the
    2026-09-10 performance refactor and repository-wide review only on a
    deleted, never-pushed local branch; restored `ai/performance-refactor` at
    `5f06c03` before reflog expiry. Rechecked its findings against `main`:
    the lab-runner deletion, Task Scheduler SYSTEM refusal, SMB description
    overwrite, and AD descriptor overfetch remain; its CNG Major is FIND-001.
    Dependabot failures are inherited from their parent `4806726`, fixed on
    `main` by `0502254`. No code change and no remote mutation.

- 2026-09-03 to 2026-09-07: OI-31, the 105-command audit, the audit-gap
    closure, the `6f7ba15` close-out, the `34026468199` wiki-publication hang
    (DscResource.DocGenerator#111), the `34021812398` completer fix, the
    `ai/access-rights-completion` review, the script-inventory audit, the
    wiki-publisher investigation that run `34055979655` closed, the
    `ai/test-gap-audit` handoff push, the 2026-09-07 lab checkpoints, review,
    FIND-001 resolution, and `f5731f1` reacceptance are in
    `git show 2ebb3a5:.memory-bank/progress.md`,
    `git show 023afe9:.memory-bank/progress.md`,
    `git show 4461b90:.memory-bank/progress.md`,
    `git show 8b67058:.memory-bank/progress.md`, and, for the oldest,
    `git show a48ec3d:.memory-bank/progress.md`. Lessons kept: record
    transient host paths without a user profile; keep imports unforced and run
    docs and tests in separate processes; bind completers to an instance, not
    a disposed worker context; publish the wiki with the standard task from an
    Ubuntu runner.
