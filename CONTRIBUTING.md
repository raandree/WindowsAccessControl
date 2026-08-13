# Contributing to WindowsAccessControl

If you are keen to make `WindowsAccessControl` better, why not consider
contributing your work to the project? Every little change helps us make a
better module for everyone to use, and we would love to have contributions from
the community.

Everyone participating is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Core contribution guidelines

This project is built with [Sampler](https://github.com/gaelcolas/Sampler) and
follows the common DSC Community
[contributing guidelines](https://dsccommunity.org/guidelines/contributing).
The sections below record only what is specific to this repository.

## The specifications are the source of truth

The numbered documents under [specs](specs/README.md) define scope,
requirements, the public API shape, the security boundaries, and how each
requirement is verified. Architecture decisions live in
[specs/decisions](specs/decisions/README.md).

Read them before proposing a change, because several behaviors that look like
defects are refusals the project accepted deliberately. Combined SMB and NTFS
effective access, directory effective access, and audit rules on families that
exclude them are recorded decisions, not gaps.

A change that alters behavior changes a specification first. The QA suite
enforces the structure: every specification is indexed, requirement identifiers
are unique, every requirement traces to executable evidence, every exported
command appears in the public API contract, and every decision record is
indexed. A pull request that changes behavior without the matching
specification and evidence fails that suite.

Open an issue before a large change. It is cheaper to agree on scope than to
withdraw a finished branch.

## Build and test

```powershell
.\build.ps1 -ResolveDependency   # first time only, restores dependencies
.\build.ps1 -Tasks build         # build the module into output\module
.\build.ps1 -Tasks test          # the full gate
```

There are also `build` and `test` tasks in the VS Code workspace.

Run the build in a separate console rather than in an editor-hosted terminal.
The suite spawns runspaces and child processes, and an editor-hosted session
can hang on them.

The full gate takes about 25 minutes. It runs the unit, integration, QA, and
performance suites, applies PSScriptAnalyzer, and asserts code coverage.

## Tests

The project is test-first. A behavior change arrives with a test that fails for
the expected reason before the change and passes after it, and a bug fix keeps
a regression test that fails without the fix.

| Folder | What belongs there |
| --- | --- |
| `tests/Unit` | One file per public command, private function, class, and DSC resource. Deterministic, no live object required |
| `tests/Integration` | Live behavior against disposable local objects. Privilege-dependent cases skip with an exact reason rather than pass silently |
| `tests/QA` | Module, changelog, help, and specification conformance |
| `tests/Performance` | Bounded-execution benchmarks. Repeatable evidence, no hard timing assertions |
| `tests/Lab` | The multi-forest domain acceptance lab. Not required for a pull request; see below |

The QA suite requires every public command to have a unit test file, a
`.SYNOPSIS`, a `.DESCRIPTION` longer than 40 characters, at least one example,
and a description for every parameter.

Coverage is asserted at 80 percent over the commands the running test profile
can execute, not over the whole module. Decisions
[0025](specs/decisions/0025-fix-coverage-measurement-not-threshold.md) and
[0027](specs/decisions/0027-assert-coverage-over-executable-scope.md) record why.
A source file may be declared out of that scope only while the local profile
executes no command of it, and two guards fail the build when that declaration
stops being true.

Never weaken an assertion, suppress an error, or skip a failing test to get a
green result.

## Style

- Run `Invoke-ScriptAnalyzer` over anything you change. A suppression carries a
  `Justification` that states why the rule does not apply.
- The module targets Windows PowerShell 5.1 and PowerShell 7 on Windows, with no
  third-party runtime dependency. Both editions must pass.
- Preserve the security descriptor sections a command did not select. Losing an
  unselected section is a defect even when the selected one is correct.
- Comment only what the code cannot show on its own, and keep it short.

## The domain acceptance lab

[tests/Lab](tests/Lab/README.md) deploys a disposable multi-forest AutomatedLab
environment for the SMB share, Active Directory, Task Scheduler, and certificate
private-key evidence. It needs an elevated Hyper-V host, AutomatedLab, and about
47 GB of memory across 13 machines.

You do not need it to contribute. Say so in the pull request when a change
touches an enterprise family, and a maintainer runs the acceptance.

## Changelog

Add an entry under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md), following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The QA suite compares
the working tree against the default branch and fails when a change ships
without one.

Write what changed for someone using the module, and why, rather than what you
did. Do not add a version heading; the release pipeline creates it.

## Commits and pull requests

Use [Conventional Commits](https://www.conventionalcommits.org/), for example
`feat(ntfs):`, `fix(batch):`, `docs:`, or `test(lab):`.

[GitVersion.yml](GitVersion.yml) reads the commit messages to calculate the next
version, so the wording decides the bump:

| Message contains | Bump |
| --- | --- |
| `breaking change`, `breaking`, or `major` | Major |
| `add`, `adds`, `feature`, `features`, or `minor` | Minor |
| `fix` or `patch` | Patch |
| `+semver: none` or `+semver: skip` | None |

Keep a pull request focused on one change, and keep every commit green. State
in the description what you ran and what the result was; a maintainer should not
have to guess which gate you exercised.

## Security

Do not report a vulnerability in a public issue. [SECURITY.md](SECURITY.md)
gives the private route and states what is in and out of scope.
