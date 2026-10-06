---
status: current
last-verified: 2026-10-06
owner: software-engineer
source: repository evidence
---

# Progress

## Current status

`v0.3.0-preview0001` shipped from `40e364a` on 2026-09-07 with the accepted
FIND-001 correction; `v0.2.0` remains the stable release. A 2026-10-06 triage
found unmerged and untracked work and split it into eight handoffs on local
`ai/post-release-fixes`. Handoffs 01 to 03 fixed the lab-runner Blocker, the
Task Scheduler, SMB, and AD review defects, and ported and re-measured the
performance refactor there; three dependabot pull requests with inherited
failures, unanswered issue #4 with a missing NTFSSecurity migration map, an
uncreated v0.2.0 changelog pull request, and the FIND-002 newline nit remain.
`activeContext.md` holds the evidence and the order.

## Recent milestones

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

- 2026-09-07: Completed fresh reacceptance of `f5731f1` without replacing the
    lab. All four built/installed passes have 95 passed tests, zero failures or
    skips, and ready cleanup. Five DSC-engine tests and both fresh local gates
    pass; Core has 91.15 percent asserted coverage and Desktop 90.41 percent.
    Verified original installation bytes/ACLs, fixture restoration, and all 38
    retained guest evidence files before staging removal. Thirteen VMs and
    checkpoints remain. Final completion is 18:52:19 UTC; no git remote mutation.

- 2026-09-07: Resolved FIND-001 test-first. A uniquely named persisted CNG key
    reproduced the third-read exception after its requested DACL was already
    stored, then passed with exactly two helper reads after the one-line source
    correction. Core and Desktop each pass all 52 affected CNG tests; a focused
    Desktop live mutation restores the fixture descriptor byte-for-byte and
    removes its binding and staging. Full local runs pass 1,806 and 1,761 tests
    at 83.00 and 80.81 percent asserted coverage without prior lab evidence.
    PSScriptAnalyzer is clean on both changed files, and independent review
    approved with no finding. The 22-task pack is clean and package SHA-256 is
    `D93B2644B31A38B37F9FAC08DBD1D28C85AF8AD452D81E1428E0A3054530588C`.
    Prior accepted artifacts remain preserved.

- 2026-09-07: Completed one independent review of `3321350..358651e` plus the
    CNG persistence path. Verified one Minor post-write read defect and two
    missing-newline locations under one Nit; no Blocker or Major findings.
    Reconciled raw-report tally and topology errors against the retained
    evidence. No runtime or test code changed and no live tests were repeated.

- 2026-09-07: Checkpointed all thirteen existing lab VMs and verified signed,
    sealed Kerberos LDAP, WSMan, test dependencies, and the renewable template.
    Rebuilt and byte-verified the candidate; closed the five-test Desktop DSC
    gate on the reserved member. Fixed the stale cleanup-list entry exposed by
    live acceptance, retained the failed evidence, and verified exact-identity
    recovery. All four repaired passes finish with 95 tests each and clean
    fixtures. Original installation bytes and ACLs are restored; final lab
    services, LDAP, and checkpoint checks pass. Local Core passes 1,805 tests
    and 91.16 percent asserted coverage; Desktop passes 1,760 tests and 90.41
    percent. Both imported the successful lab coverage byte-for-byte, with the
    80 percent threshold unchanged. Validation completed at 12:08 UTC and
    monitoring stopped. The dated lab acceptance report retains candidate
    hashes and the failure, recovery, and successful-run evidence.

- 2026-09-07: User requested a handoff commit and push on `ai/test-gap-audit`
    after creating the remote branch. Reuse the recorded audit validation;
    no runtime code changes were made in this handoff. Keep the two blocked
    Desktop DSC checks, live acceptance, and independent review as open gates.
    Generated packages and raw logs remain excluded from the Git transfer.

- 2026-09-06: Audited the complete script inventory and controlling safety
    paths. Reproduced and fixed escaped-DN containment, restore GUID loss,
    wrong native ACE removal, DSC cleanup ownership, and misleading lab
    evidence success. Core: 1,802 passed, zero failed, two environment skips;
    coverage: 82.74 percent after moving the locally exercised AD setter into
    asserted scope. Added the audit record and detached lab checklist. All
    eight live suites discover 95 tests, but no live acceptance was run.
    Desktop: 1,755 passed, two failed, two skips. The failing DSC-engine calls
    cannot reach local WS-Management; WinRM is stopped with manual startup.
    No test or host remoting setting was changed to bypass that prerequisite.
    Packaging passed all 22 tasks; the local `0.0.1` candidate contains the
    exact tested module plus generated help. The audit record retains hashes,
    raw-evidence location, and the remaining lab/review obligations.

- 2026-09-06: Confirmed hosted closure in run `34055979655` for `830a909`.
    All four jobs passed; the Ubuntu publish job completed at 20:04:59 UTC.
    The live wiki Home page names `v0.2.0-preview0002` and the sidebar contains
    generated command and DSC resource navigation. The standard task works on
    the selected runner, closing the outstanding Linux validation without a
    custom task or manual wiki seed. No further incident work remains.

- 2026-09-06: Reinvestigated why the stock wiki publisher works elsewhere.
    With the actual release archive and upstream 0.13.0 on Windows, 126 added
    files plus Home timed out at 3,042 ms with a shortened 3,000 ms timeout;
    modifying 127 existing files passed in 157 ms and emitted only 112 bytes.
    A quiet initial commit passed in 104 ms. Both DSC Community comparison
    pipelines publish on Ubuntu. Removed the rejected custom publisher and
    changed only the publish runner; build/test runners and standard task
    order are unchanged. The new workflow guard was red then green; all 20
    build-specific tests pass in both editions, and Sampler resolves the
    upstream wiki task.
    Actual Ubuntu publication awaits a hosted run. No commit or remote write.

- 2026-09-06: A custom wiki workaround passed the Core and Desktop gates
    (1,771 and 1,726 tests; 82.40% and 80.20% asserted coverage), but remained
    uncommitted. It was subsequently withdrawn at the user's request in favor
    of the standard task and runner investigation recorded above.

- 2026-09-03 to 2026-09-06: OI-31, the 105-command audit, the audit-gap
    closure, the `6f7ba15` close-out, the `34026468199` wiki-publication hang
    (DscResource.DocGenerator#111), the `34021812398` completer fix, and the
    `ai/access-rights-completion` review are in
    `git show 8b67058:.memory-bank/progress.md` and, for the oldest,
    `git show a48ec3d:.memory-bank/progress.md`. Lessons kept: record
    transient host paths without a user profile; keep imports unforced and run
    docs and tests in separate processes; bind completers to an instance, not
    a disposed worker context.
