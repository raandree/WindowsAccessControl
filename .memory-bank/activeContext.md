---
status: current
last-verified: 2026-09-05
owner: software-engineer
source: current task evidence
---

# Active context

## Current task

The user requested unattended closure of the repository audit gaps, including
live validation, and explicitly granted access to the existing lab. Work is on
`ai/specification-code-audit`, based on `124a356`; this turn's edits are not yet
committed. The user accepted the review and requested user-impact documentation
and development-cycle close-out. Documentation is complete; the final coverage
assertion and local commit remain pending. Do not publish, push, tag, or change
repository settings without a specific request.

## Implemented

- The command-evidence catalog covers every export and links to its actual
    command-specific test suite. Some original commands have Integration suites,
    not Unit/Public suites; the earlier audit overstated that distinction.
- Specification QA checks all requirement references, command rows and links,
    output types, DSC exports, canonical status, and ordered lab suites.
- Private-key access rules have a default table with key, scope, identity,
    readable rights, and qualifier; unresolved accounts fall back to the SID.
- Stale path, private-key selector, concurrency, replication, coverage, and
    documentation statements are corrected. Existing contextual ADR links were
    retained and missing ones added. Accepted deferrals remain unchanged.
- The lab host runner now retains per-edition console logs on the management VM
    in the running administrator's private TEMP directory, while preserving
    returned output and exit codes. Only redacted JSON is shareable evidence.
- A real Desktop runtime defect is fixed: a bounded batch left the privilege
    completer's static helper bound to a disposed worker context. The lookup is
    now instance-bound. The retained before/after batch regression failed
    without the two-line fix and passes with it; all 18 focused tests pass.
- Repeated Added, Changed, and Fixed headings within Unreleased were merged.
    All 754 non-heading content lines were preserved; the changelog parser had
    previously missed content across repeated categories. A regression protects
    per-release category uniqueness.
- The usage guide explains the private-key rule table and unchanged object
    properties. The changelog describes reliable privilege completion, private
    diagnostics, and complete release notes in user-facing terms. The final
    release-note task passed without changing the tested manifest or package.

## Verified so far

- Specification QA: 20 passed, zero failed or skipped. The final Desktop QA
    and console-log regression run passed 25 tests. The new guards and
    format/log fixes were first demonstrated red.
- Packaging: 22 tasks, zero errors or warnings; package
    `output/WindowsAccessControl.0.2.0-specification.nupkg`, 105 commands and 20
    DSC resources. GitVersion 5.12.0 is installed under the user's local app-data
    folder; Sampler intentionally normalizes its compound prerelease label.
- The first packaging attempt had a transient output-file sharing violation.
    An exclusive-read probe subsequently succeeded; the unchanged rerun passed.
    No process was killed and no retry was added to the build. Owner unconfirmed.
- Full local Core gate: 1,751 passed, zero failed, two privilege/environment
    skips; 81.92% asserted coverage; all 35 module-defined types compiled once.
    The changelog-only guard was added afterward and passes in focused Core QA.
- Final Core gate: 1,753 passed, zero failed, two environmental skips, 81.92%
    asserted coverage, all 35 module-defined types compiled once. The final
    package matches the built module/manifest/format bytes and contains 21
    conceptual help files plus external help. Module SHA-256 is
    `E82AF3DACC764D37DEACB55CFBDB427A1ED42C357919E9DBB7386C7FDBD5D349`.
- The first Desktop gate had 17 completion failures plus a Git line-ending
    warning. The completion defect was reproduced without coverage and fixed;
    changed files were normalized to `.gitattributes`. The corrected Desktop
    local-only pass has 1,708 passing tests, but coverage is 79.72%, below
    the unchanged 80% threshold. The import location held stale lab evidence;
    the fresh final lab document was accepted and the merge is running after
    1,709 tests passed with zero failures and two environmental skips.
    A clean-main baseline reproduced all 17 completion failures and stopped
    before the threshold assertion. This proves the completion defect was
    pre-existing, not a baseline coverage percentage. Its worktree is removed.
- The isolated Hyper-V lab has 13 running VMs. Authenticated checks passed on
    the management controller, replication partner, and member. The current lab
    earlier candidate passed 93 tests across eight suites in both editions.
    The final instrumented Desktop build pass also passed all 93 tests and
    eight suites with every cleanup ledger ready, at 45.43% lab coverage.
    Installed-package acceptance passed all 93 tests in both editions, with
    zero failures or skips and eight ready cleanup ledgers per edition.
    Required services on both controllers and the member were independently
    confirmed running after acceptance at 22:56 UTC.
- The independent review approved the exact current 31-file code and
    documentation diff against main, with no Blockers or Majors. Two Minor
    observations are contained to the trusted lab harness: predictable console
    filenames and executing a repository-owned AST fragment in a unit test.
    An independent VM check found no broad user read grant on the new raw log
    and no old console logs left in the payload directory.
- Final documentation checks: all 20 specification tests passed after the
    user-impact edits; Markdown rendering, table columns, local anchors, and
    diff whitespace passed. The release-note task passed with zero warnings.
- Public GitHub state: zero open issues, three Dependabot pull requests, no
    published releases, and the generated rather than custom social preview.
- Vendored bootstrap TODOs stay upstream: Sampler rules prohibit local edits
    to `build.ps1` and `Resolve-Dependency.ps1`.

## Evidence and remaining process

Evidence root is
`C:/Users/install/AppData/Local/Temp/2/wac-closure-a8d8a95f9dd14813907a881c8cef950e`.
Its generated `run-state.json` contains complete process, log, and result paths.
Read result markers and logs; a PID alone does not prove success.

- Final Core gate: PID 15032, marker
    `detached-b451393af889451f88e4220b3c22d101.exit`.
- Final package: PID 14452, marker
    `detached-c9acabafb6b6471d89f0ce43b1a65907.exit`.
- Final Desktop gate: PID 6216, marker
    `detached-e86d746a8fcb44b7bc8d1c267c084090.exit`.
- Desktop gate with current lab evidence: PID 8676, marker
    `detached-bb5e32a0893643eda99f135e2e366c32.exit`; log
    `wac-desktop-merged-coverage-13f2c78bc6804b1e87d041cc327183bf.log`.
- Completed clean-main Desktop baseline: marker
    `detached-eaaef34f574c49ffb39e41a1fce3984d.exit`; log
    `wac-main-desktop-baseline3-16149d5df7964daa9921d25d52218747.log`.
    The temporary worktree and dependency junction were removed. Inspect the
    inner build result, not just the launcher marker: the session's native
    wrapper emitted marker 0 although the baseline build exited 1.
- Final lab chain: PID 18316, marker
    `detached-48bcc4fa0e8b4073828fe3e0c43d9358.exit`; log is
    `wac-lab-final-a1bf4f4864c8455c913c3b9ea55fb8b9.log` in `Temp/2`.
    The chain checks evidence/cleanup after the build pass before installing
    the package and running both editions. Results go under the evidence root
    as `lab-final-build-desktop.json`, `final-domain-lab-coverage.xml`, and
    `lab-final-installed-desktop.json` / `lab-final-installed-core.json`.
- Final documentation regression: marker
    `detached-aa72694507994eb380945eb953ed4950.exit` is 0; log
    `wac-closeout-specifications-0f282bbb6bf049ad919bc9c9251deaae.log`.
- Final release notes: marker
    `detached-c7680a6655a14736a1fa1710e48b319a.exit` is 0; log
    `wac-closeout-release-notes-4c8b54b6eb3d4a47ae181d68ca87a843.log`.
- These markers are in the same `Temp/2` directory as the evidence root.
- Lab console: `wac-lab-acceptance-<edition>.console.log` in the running
    administrator's `TEMP` directory on `F1ADC1`. Use a separate
    `Invoke-LabCommand` session to inspect progress. Console logs are private
    diagnostics; only redacted JSON is shareable evidence.
- Heartbeat job: `wac-closure-a8d8a95f`, ten-minute cadence. Re-arm each tick
    while needed and cancel it at completion. Last armed at 22:53 UTC for
    23:03 UTC. Only the Desktop coverage merge is still running.

## Remaining work

1. Read the merged Desktop gate's actual threshold assertion and completion
    marker. Do not weaken assertions or introduce exclusions to pass it.
2. Cancel the heartbeat after completion. The temporary worktree, dependency
    junction, old payload logs, and scratch coverage script are already gone.
3. Record the final verdict, run Memory Bank health checks, review the staged
    diff, and commit locally. No push, publication, or tag.

Historical OI-31 diagnostics remain in [debugging-insights.md](debugging-insights.md)
and in the pre-audit history. Current contract authority remains
[specs/README.md](../specs/README.md).
