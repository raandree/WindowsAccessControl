---
status: current
last-verified: 2026-09-06
owner: software-engineer
source: repository evidence
---

# Progress

## Current status

GitHub Actions run `34026468199` partially published
`0.2.0-preview0001` before the wiki task failed. The GitHub release and Gallery
package exist; the wiki was not changed. `DscResource.DocGenerator` 0.13.0
deadlocked on the output from a 127-file `git commit` and timed out after 120
seconds. [Active context](activeContext.md) records the evidence and rerun risk.
No remote operation or production-file change was performed in the diagnosis.

## Recent milestones

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

- 2026-09-05: Audited the specifications against the code. The register in
    `specs/open-issues.md` is empty and the implemented surface matches its
    contract exactly: 105 public commands and 20 DSC resources, each named in
    `specs/0003`, documented under `docs/`, and covered by a test file of its
    own name; every test file and script the specifications name exists, and all
    39 roadmap task identifiers in 0008 are mapped in 0005. Every gap found is
    specification text that trails the code. `specs/0005` lists 89 of the 105
    commands in its command-evidence table, still says the two DSC contract
    suites verify "nine" exports where both enumerate ten, and still describes
    the lab acceptance as four suites plus the CNG suite at 18 tests and
    ENT-8 as six suites, where the runner fixes eight. `specs/0003` says Task
    Scheduler backup/restore and DSC "remain outside this contract" while the
    same file tables four Task Scheduler DSC resources and 0014 delivers the
    portability; it counts "four server-qualified families" at record version 2
    where FR-25 and `ConvertTo-WindowsSecurityDescriptorBackupRecord` have five,
    omitting the certificate private key; its output-type list omits nine names
    the module stamps and its own tables return; and its format-view sentence
    names five views where the module ships eighteen. The root cause is
    asymmetric guarding: `tests/QA/Specifications.Tests.ps1` asserts that every
    exported command appears in 0003, and nothing asserts the 0005 table, the
    stated counts, or the output-type list. Two smaller items: the private-key
    rule type is the only rule family without a curated table view, and the QA
    closed-issue loop stops at OI-30, so OI-31 has no regression pin.

- 2026-09-03: Closed OI-31 by reproducing it. The intermittent `Expected [X],
    but got [X]` failures happen when the test process compiles the module file
    a second time: PowerShell caches a file's compiled script block by path and
    content, and a read that misses that cache builds a second dynamic assembly
    carrying a second copy of every module-defined class and enumeration. All
    six script-side resolution routes were measured and every one of them stays
    pinned to the first copy while the module's own commands emit the second, so
    no assertion could have been rewritten to be correct. The gate suites now
    import the module without `-Force` and never unload it, the two tests whose
    subject is the load and unload cycle do it inside `Start-Job`, both strict
    assertions are restored, and a new QA suite walks the abstract syntax tree of
    every gate test file to keep it that way. The trigger that fired on
    2026-08-11 is still unnamed: the engine's own cache drop above 1024 entries
    is what the reproducer uses, but a measured `build, test` process peaked at
    528 entries and a bare Pester run at 411, the two import routes spell the
    module path identically, and `Get-DscResource` reuses the loaded instance in
    both editions. The fix removes the precondition rather than one trigger. The
    reproducer was repeated ten times in each mode with ten of ten behaving as
    expected, and the local gate is green at 17 tasks, 0 errors, 0 warnings,
    1,742 tests passed, 0 failed, 2 skipped, and 81.92 percent asserted
    coverage. One local constraint follows: `docs` and `test` can no longer
    share a process, which is how `build.yaml` and the CI workflow already run
    them.
