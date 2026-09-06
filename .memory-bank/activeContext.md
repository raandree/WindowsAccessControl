---
status: current
last-verified: 2026-09-06
owner: software-engineer
source: current task evidence
---

# Active context

## Current task

The wiki publication incident is closed. The user committed and pushed
`830a909` to `main`; GitHub Actions run `34055979655` passed all four jobs,
including Ubuntu publication of `0.2.0-preview0002`. The live wiki Home page
names that version and its sidebar lists generated commands and DSC resources.
The standard imported wiki task is retained, with no custom override. Only
these closure records were edited in this turn; no commit or remote write ran.

## Reproduction and comparison

The unmodified `DscResource.DocGenerator` 0.13.0 `Invoke-Git` was tested on
Windows with the actual 127-file `v0.2.0-preview0001` wiki archive. The probe
used disposable local repositories and shortened the timeout to 3,000 ms.

| Commit scenario | Added | Modified | Result |
| --- | --- | --- | --- |
| Initial import over Home only | 126 | 1 | Exit -1 after 3,042 ms; empty captured output |
| Update an already populated wiki | 0 | 127 | Exit 0 in 157 ms; 112 bytes of stdout |
| Initial import with quiet commit | 126 | 1 | Exit 0 in 104 ms; no stdout |

The original failure is output-dependent, not a failure of every wiki update.
The wrapper waits for exit before draining redirected streams; a first import
prints a create-mode line for each new file. This matches
[upstream issue 111](https://github.com/dsccommunity/DscResource.DocGenerator/issues/111).
The previous replacement-only tests did not make this comparison.

Both reference pipelines build on Windows and publish on Ubuntu with the
standard `Publish_GitHub_Wiki_Content` task:

- [ActiveDirectoryDsc pipeline](https://github.com/dsccommunity/ActiveDirectoryDsc/blob/main/azure-pipelines.yml)
- [SqlServerDsc pipeline](https://github.com/dsccommunity/SqlServerDsc/blob/main/azure-pipelines.yml)

## Current implementation

- Use the standard Ubuntu publish runner, matching the reference pipelines.
- Keep `build.yaml`, dependency versions, release order, credentials, and the
  build/test runners unchanged. There is no local wiki task or Git helper.
- `tests/Unit/Build/WikiWorkflow.Tests.ps1` guards the runner split, upstream
  task order, and absence of a local wiki task redefinition.
- The changelog describes the runner change, not the discarded custom token
  handling, quiet commit, or atomic push.

## Partial release state

- GitHub release `v0.2.0-preview0001` exists for commit `764f0b1` with
  `WindowsAccessControl.0.2.0-preview0001.nupkg` and `WikiContent.zip`.
- PowerShell Gallery version `0.2.0-preview0001` was published at
  2026-09-06 10:51:48 UTC.
- A blind rerun can collide with the immutable Gallery version before it
  reaches the wiki task. The fix is intended for a new version-producing build,
  not a rerun of the already-published commit.

## Verification

- The workflow regression first failed on the Windows publish runner and the
  custom override. After the change, all four checks pass.
- The complete build-specific Pester suite passes all 20 tests without skips
  in both PowerShell 7 and Windows PowerShell 5.1.
- A secrets-cleared Sampler invocation resolves the wiki task to
  `DscResource.DocGenerator/0.13.0/tasks/Publish_GitHub_Wiki_Content.build.ps1`
  and takes its empty-token skip path. This verifies task selection only.
- PSScriptAnalyzer and editor diagnostics report no findings on the new test
  and workflow. The unrelated module runtime suites were not rerun.
- Log: `%TEMP%\wac-stock-wiki-validation-db3d3206200d4efe97d735a25493b8ea.log`;
  detached exit marker is 0 and `STOCK-WIKI-VALIDATION-DONE` is present.
- Desktop log: `%TEMP%\wac-stock-wiki-desktop-8ccbab6efb5e44e5aade4bbfcfddf3fb.log`;
  exit marker is 0 and `STOCK-WIKI-DESKTOP-DONE` is present.

## Hosted validation and closure

- [Run 47](https://github.com/raandree/WindowsAccessControl/actions/runs/34055979655)
  completed successfully for `830a909` on 2026-09-06 at 20:05 UTC.
- The Windows build and both PowerShell test jobs passed. The Ubuntu publish
  job passed secret verification, release publication, and the changelog step.
- The live wiki Home page is stamped `v0.2.0-preview0002`; generated command
  and DSC resource navigation is present. No manual wiki seed was needed.
- This supplies the previously missing hosted Linux evidence. No further work
  remains for this incident. The upstream wait-before-read defect is not
  repaired generally, so this result is not a guarantee for arbitrarily large
  process output on every platform.
