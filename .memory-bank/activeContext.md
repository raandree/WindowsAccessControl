---
status: current
last-verified: 2026-09-06
owner: software-engineer
source: current task evidence
---

# Active context

## Current task

The user rejected a custom wiki build task. The uncommitted override, helper,
and their tests were removed after comparing the stock publisher with DSC
Community pipelines. The production change is now only
`jobs.publish.runs-on: ubuntu-latest` in `.github/workflows/build.yml`.
Build, documentation generation, and both test editions remain on Windows.
Changes remain uncommitted; no external publication was performed.

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

## Remaining validation

There is no configured local Linux distribution. Actual Ubuntu publication of
this artifact remains unverified until the hosted pipeline runs. The upstream
wait-before-read defect is still present; the runner change follows the
standard pipeline rather than repairing that dependency for arbitrarily large
output on every platform. A one-time manual wiki seed was considered but not
performed; it would leave future large Windows additions exposed to the bug.
