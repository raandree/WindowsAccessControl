---
status: current
last-verified: 2026-09-06
owner: software-engineer
source: current task evidence
---

# Active context

## Current task

GitHub Actions run `34021812398` failed in the Windows PowerShell 5.1 job
because every new `AccessRights` argument completer returned no matches after
the test process disposed a bounded worker runspace. The controlling static
PowerShell class method had the same lifetime defect previously fixed in the
privilege completer. The implementation, regression guard, executable-scope
coverage repair, and release note are complete on
`ai/fix-desktop-rights-completion`. No push, publication, tag, or repository
setting change was requested or performed.

## Implemented

- `WindowsAccessRightsCompletion.Complete()` is a hidden instance method.
  Filesystem and Active Directory completers inherit it and call it through
  `$this`, binding completion to the live completer instead of a static script
  method that can retain a disposed worker context.
- The access-rights completion suite compares results before and after a real
  two-target `Get-NTFSItemOwner` batch. The new check failed on Windows
  PowerShell 5.1 before the implementation change and passes afterward.
- A direct unit test now verifies normalized certificate bindings from
  HTTP.sys, WinRM, and Remote Desktop. This covers a locally reachable safety
  probe that callers previously mocked and restores the hosted executable-scope
  coverage gate without accepting stale domain-lab evidence or lowering the
  threshold.
- The Unreleased changelog records reliable `AccessRights` completion after
  parallel multi-target commands and confirms that raw mask binding is
  unchanged.

## Final verification

- The red Desktop regression passed 12 tests and failed the new worker-lifetime
  check because `Modify` became null after the batch. After the fix, all 13
  focused completion tests pass in both Windows PowerShell 5.1 and PowerShell
  7.
- The module build passed seven tasks with zero errors or warnings.
- Final Windows PowerShell 5.1 gate: 1,723 passed, zero failed, two
  environmental skips; 80.20% asserted coverage (6,583 of 8,208 executable
  commands); all ten tasks passed with zero errors or warnings.
- Final PowerShell 7 gate: 1,768 passed, zero failed, two environmental skips;
  82.40% asserted coverage (6,763 of 8,208 executable commands); all ten tasks
  passed with zero errors or warnings.
- The retained domain-lab coverage correctly remained unmerged because it
  measures the earlier `0.2.0` module. ADR 0027 requires the hosted profile to
  pass over its executable scope without that evidence.
- The certificate-binding test passes after restoring the prior
  `$LASTEXITCODE` in `finally`. The built module and both tests parse without
  errors. PSScriptAnalyzer reports zero warnings or errors and one expected
  informational cross-file notice for `WindowsActiveDirectoryRights`.
- VS Code diagnostics and `git diff --check` report no errors.

## Retained evidence

- Desktop final log: `%TEMP%\wac-desktop-final-7e21e8f515cd4629ae67558287d9ed9d.log`.
- Core final log: `%TEMP%\wac-core-final-a63ed95748ca4afeab9bcc2f128aa9a4.log`.
- The corresponding detached markers are `0`, and both logs contain their
  unique DONE marker.

## Closure

The implementation, tests, and repository records are complete. Git history is
authoritative for local commit status. Remote mutation remains outside this
task unless the user explicitly requests it.
