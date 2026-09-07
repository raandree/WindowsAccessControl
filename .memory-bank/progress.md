---
status: current
last-verified: 2026-09-07
owner: software-engineer
source: repository evidence
---

# Progress

## Current status

Lab acceptance from `5991673` on `ai/test-gap-audit` is complete. The rebuilt
package and five isolated Desktop DSC-engine tests pass. Initial Desktop lab
acceptance exposed a test cleanup defect after 95 passing bodies; its overall
result remains failed. The test-only fix passes three lifecycle regressions in
both editions and all twelve live replication cases. Exact-GUID cleanup
restored the lab. All four full lab passes now pass with zero skips and ready
cleanup. Local Core passes 1,805 tests at 91.16 percent asserted coverage;
Desktop passes 1,760 tests at 90.41 percent. Both have zero failures and two
existing environment skips. The requested independent review found no Blocker
or Major issue. Its Minor CNG post-write defect and newline Nit remain open;
the CNG correction and fault-injection evidence precede stable release. No
remote write is authorized for this task.

## Recent milestones

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

- 2026-09-06: Diagnosed GitHub Actions run `34026468199`, attempt 2. Secret
    validation, the GitHub release, both release assets, and PowerShell Gallery
    publication succeeded. `Publish_GitHub_Wiki_Content` then hung at
    `git commit` for exactly the dependency's 120-second timeout and reported
    exit code `-1` with empty output. The generated archive has 127 files and
    about 6,878 bytes of per-file commit summary. `Invoke-Git` waits for Git to
    exit before draining redirected output, reproducing the open upstream bug
    DscResource.DocGenerator#111. The wiki remains at its initial Home page and
    has no version tag. A blind rerun can collide with the already-published,
    immutable Gallery version; no rerun or remote mutation was performed.

- 2026-09-06: Fixed GitHub Actions run `34021812398`. A static PowerShell
    class method left all new `AccessRights` completers attached to a disposed
    bounded-worker context in Windows PowerShell 5.1. The shared completion
    method is now instance-bound, and a real before/after batch regression was
    red then green. A direct HTTP.sys, WinRM, and Remote Desktop binding test
    raised hosted executable-scope coverage without weakening ADR 0027. Final
    Desktop: 1,723 passed, zero failed, two skips, 80.20% coverage. Final Core:
    1,768 passed, zero failed, two skips, 82.40% coverage. Both Sampler gates
    passed ten tasks with zero errors or warnings; no remote operation ran.

- 2026-09-06: Reviewed `ai/access-rights-completion` against the validated
    audit result and found one focused, additive commit. Its production and
    test files merge cleanly; documentation conflicts came from stale complete
    copies and retain the current records plus the new completion facts. The
    fresh build passed, both PowerShell editions passed 30 focused completion
    tests, and the full Core gate passed 1,766 tests with two environmental
    skips and 81.93% asserted coverage.

- 2026-09-05: Closed the validated cycle locally in `6f7ba15`. The Desktop
    coverage merge completed at 23:01 UTC with 90.37% asserted coverage and
    90.34% whole-module coverage; all ten tasks passed without warnings.
    Monitoring was stopped at 23:02 UTC. Both package editions and the
    instrumented lab build had already passed all 93 tests and cleanup checks.
    A closing self-review then found that the evidence note had introduced the
    local Windows account name into a version-controlled file, which `main` did
    not contain; `5d291c5` replaced it with `%TEMP%` while keeping every marker
    identifier. Record transient host paths without a user profile.
    No push, release, or tag was performed.

- 2026-09-05: The user accepted the security and quality review and requested
    development-cycle close-out. Documented reliable privilege-name completion,
    the private-key rule table with SID fallback and unchanged object
    properties, private lab diagnostics, and complete generated release notes.
    The final specification regression passed 20 tests. The release-note task
    passed without altering the validated manifest, module, or package.
    Both controllers and the member server passed post-acceptance service
    checks. Temporary baseline worktrees, dependency junctions, and the scratch
    analysis script were removed; no old raw logs remain in the lab payload.

- 2026-09-05: Closed the remaining local audit gaps with failing-then-passing
    guards: every export has an evidence row and a real test link, all 52
    requirement identifiers occur in the suites that prove them, public output
    types and DSC catalogs are checked, and the documented lab order is compared
    with its owning function. Added the private-key rule view with orphan SID
    fallback. Corrected stale selector, path, concurrency, and coverage prose
    and retained raw lab console output for independent progress inspection.
    Consolidated duplicate changelog categories without losing any of the 754
    non-heading content lines; the parser had omitted content across duplicates.
    The final focused gates pass 20 specification and five runner tests.
    Earlier audit claims about missing contributor guidance and uncited ADRs
    were partly false: the guidance and several Markdown links already existed.
    A rule type is not a view count, a requirement reference is not a behavioral
    proof, and not every direct command test is under Unit/Public. Vendored
    Sampler TODOs remain upstream under the no-local-bootstrap-edit rule.

- 2026-09-05: Closed the seven proven-false specification statements the audit
    found, on `ai/specification-code-audit`. `specs/0003` now admits Task
    Scheduler backup, restore, and desired state instead of excluding them,
    counts five server-qualified backup families and names the four fields a
    private-key record binds, lists the nine output type names the module stamps
    that it had omitted, and states twenty curated table views rather than five.
    `specs/0005` says ten DSC exports where both contract suites enumerate ten,
    names the certificate private-key adapter route, distinguishes the two LCM
    configurations, and describes the lab acceptance as its eight suites with
    the run counts left to this file, which is the rule that document already
    states. The QA closed-issue loop now pins OI-31. Evidence: the QA
    specification suite passes 11 of 11; the new pin was proved able to fail by
    reopening `## OI-31:` in the register, watching it go red, and restoring the
    file byte for byte; `Get-ChangelogData` still parses the changelog;
    PSScriptAnalyzer reports nothing on the changed test file; and no edited
    line exceeds the 80-column convention. G8 and G9 from the audit are
    deliberately left open: a table view for the private-key rule family changes
    user-visible output, and back-filling requirement identifiers into 29 test
    files is a convention decision. So is the guard that would stop `specs/0005`
    drifting again, which needs a rule for what belongs in its command table.

- 2026-09-05: Specification audit confirmed 105 public commands, 20 DSC
    resources, and all 39 roadmap identifiers. Documentation trailed code in
    its command-evidence table, family/resource counts, Task Scheduler scope,
    output types, and views. The root cause was asymmetric QA guarding:
    exports were checked in 0003, while the 0005 table and other catalogs were
    not. The private-key view and OI-31 pin also needed follow-up. Subsequent
    milestones above record the corrections; detailed counts remain in history.

- 2026-09-03: Closed OI-31: duplicate module compilation created incompatible
    class identities. Ten reproductions per mode and 1,742 passing tests with
    two skips proved the fix; coverage was 81.92 percent. Keep imports unforced,
    isolate load/unload tests, and run docs/tests in separate processes. The QA
    AST guard preserves the rule; detailed cache analysis remains in history.
