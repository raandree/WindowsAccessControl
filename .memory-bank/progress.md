---
status: current
last-verified: 2026-10-08
owner: software-engineer
source: repository and domain-lab evidence
---

# Progress

## Current status

`v0.3.0` is the stable release, shipped from `323928b` on 2026-10-08 after
`v0.3.0-preview0003` from the same commit: pull request #6 brought the
domain-lab acceptance of `v0.3.0-preview0002`, a test for every command in
the declared domain-lab-only files, the RootDSE and effective-access seam
change, and the lab harness correction to `main`. `v0.2.0` was the previous
stable release. Pull request #5 carried the
post-release work that a 2026-10-06 triage split into eight handoffs: the
lab-runner Blocker, the Task Scheduler, SMB, and AD review defects, the
performance refactor, the NTFSSecurity migration guide, the Node 24 action
releases, the restored 0.2.0 changelog section with a release guard, and
FIND-002; handoff 09 published the lab acceptance. All nine handoffs are
done. `activeContext.md` holds the open work.

## Recent milestones

- 2026-10-08: Published the stable release `v0.3.0` from `323928b`, with the
    user's authorization: the user pushed the tag, and run `37773125964`
    published the GitHub release, marked Latest, the Gallery's stable `0.3.0`,
    and the wiki. The stable package differs from `0.3.0-preview0003` only in
    the manifest's prerelease label and release-notes heading. The handoff 06
    guard passed on its first run, because Sampler opened the changelog pull
    request #7, so `GitHubToken` has the pull-request permission the v0.2.0
    release lacked; the user merged it as `8cc42a1` without starting a build.
    A throwaway-clone simulation had predicted the version, the selected tag,
    and the released changelog section beforehand.

- 2026-10-08: Published `v0.3.0-preview0003` from `323928b`, the merge commit
    of pull request #6, which carried `ai/record-post-release-publication`
    unchanged after the user pushed it from the lab host. Both local gates
    passed on `a95321c` first (Core 1,938 tests at 83.19 percent asserted
    coverage, Desktop 1,893 at 80.95 percent), GitVersion 5.12.0 predicted
    the version on a simulated merge, and CI passed on the pull request and
    on `main` with the same figures and no error or warning annotation. The
    GitHub release, the Gallery entry, and the wiki Home page carry the
    version, and the published root module is byte-identical to the one the
    lab accepted. The user ran every remote step from commands the agent
    handed over, and moved the CopilotAtelier Skill warning's pull request to
    a prompt of their own.

- 2026-10-08: `a572d3d` stops arming member coverage from leaving a member
    session stopping on every error: `Invoke-Command -Session` runs a script
    block at the session's top level, so the preference the harness set there
    outlasted the call, and it now sets it in a child scope. A unit case
    failed with `Stop` before the change, a live probe showed both behaviors
    in each edition, and a built pass ran 109 of 109 in both editions with
    line-identical lab coverage; the local gates passed with Core 1,938 and
    Desktop 1,893 tests. The CopilotAtelier `automatedlab-deployment` Skill
    gained the `Remove-LabVMSnapshot` warning on a local branch there.

- 2026-10-08: Every command in the declared domain-lab-only files now has a
    test. `4096d02` routes the RootDSE and effective-access reads through
    `Send-WindowsADSearchRequest`, so six unit cases reach their four guards;
    `938bdff` and `bad1302` add eight live cases for the SMB share guards, the
    confirmation prompt, the enrichment catches, and a deletion inside the
    effective-access read. Each was red against a build with its guard
    removed. `bad1302` passed the DSC gate, four passes of 109 cases, and both
    local gates; domain-lab-only coverage is 100 percent
    (`docs/lab-acceptance-2026-10-08.md`). The first built pass of `938bdff`
    stopped because a session opened without a user interface cannot arm
    coverage breakpoints until its remote debugging is enabled. Removing the
    older checkpoint afterwards with `Remove-LabVMSnapshot` also deleted the
    newer one on ten VMs; the lab now holds one checkpoint,
    `wac07-after-bad1302-9d9776ca`, taken after the acceptance.

- 2026-10-07: A follow-up gave the four handoff 02 paths that only unit tests
    covered live cases: Task Scheduler repair of a protected DACL without
    Local System, and the SMB description that the native write clears, edits
    concurrently, or cannot read before the write. Each case failed against
    builds of `96d6671` and `5531824` and passed against the candidate; all
    four passes ran 101 cases each, and both local gates passed again. The
    SMB usage page and specification 0009 now name both windows in which a
    concurrent description edit can be replaced.

- 2026-10-07: Handoff 07 accepted `2ebb3a5` in the domain lab, recorded in
    `docs/lab-acceptance-2026-10-07.md`. The release-equivalent build matches
    the Gallery package byte-for-byte; four full passes of 97 cases, the DSC
    engine gate, and both local gates with fresh lab coverage passed; the two
    lab-runner refusals were proven against decoys. At the user's request the
    two older lab checkpoints, `C:\WacRepo`, and `C:\WacLive` were removed
    afterwards; checkpoint `wac07-pre-2ebb3a5-b4de5d73` remains.

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

- 2026-09-03 to 2026-10-06: OI-31, the 105-command audit, the audit-gap
    closure, the `6f7ba15` close-out, the `34026468199` wiki-publication hang
    (DscResource.DocGenerator#111), the `34021812398` completer fix, the
    `ai/access-rights-completion` review, the script-inventory audit, the
    wiki-publisher investigation that run `34055979655` closed, the
    `ai/test-gap-audit` handoff push, the 2026-09-07 lab checkpoints, review,
    FIND-001 resolution, `f5731f1` reacceptance, the 2026-10-06 triage, the
    eight handoff prompts, and handoffs 01 and 02 are in
    `git show a572d3d:.memory-bank/progress.md`,
    `git show 2ebb3a5:.memory-bank/progress.md`,
    `git show 023afe9:.memory-bank/progress.md`,
    `git show 4461b90:.memory-bank/progress.md`,
    `git show 8b67058:.memory-bank/progress.md`, and, for the oldest,
    `git show a48ec3d:.memory-bank/progress.md`. Lessons kept: record
    transient host paths without a user profile; keep imports unforced and run
    docs and tests in separate processes; bind completers to an instance, not
    a disposed worker context; publish the wiki with the standard task from an
    Ubuntu runner.
