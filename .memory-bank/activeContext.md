---
status: current
last-verified: 2026-08-08
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

The domain-lab acceptance now runs in both supported PowerShell editions and
covers a seventh suite for foreign and orphaned principals. Before this, every
enterprise claim rested on one Windows PowerShell pass using one principal from
the fixture domain.

## What changed

- `tests/Lab/Invoke-WindowsAccessControlLabAcceptance.ps1` takes
    `-PowerShellEdition` and `-CoverageEdition`. It runs one complete pass per
    edition against the same fixture set, writes one evidence file per pass, and
    carries every artifact back before it fails the run. Only one pass arms
    coverage: instrumentation is the cost, and the second pass reaches no line
    the first cannot.
- `tests/Lab/ForeignPrincipalPermissions.Live.Tests.ps1` is new. It writes and
    reads an access control entry for a principal from another domain in the
    forest, from a trusted forest, and for a security identifier no lookup can
    resolve, across the share, task-folder, directory-object, and private-key
    families.
- `tests/Integration/ExactSecurityDescriptorDscLcm.Tests.ps1` gained a compile
    test for all ten enterprise resources and a discovery test asserting that
    `Get-DscResource` advertises every resource the manifest exports. The five
    enterprise pairs had only ever been converged by direct class instantiation.

## Acceptance evidence

- Two-edition lab acceptance green on 2026-08-08: 7 suites, 50 passed, 0 failed,
    0 skipped in each edition, `Result = Passed`, every suite `Ready = True`.
    Per suite: DomainLab 4, CertificatePrivateKey 7, TaskScheduler 8, SmbShare 7,
    ADObjectPermissions 12, ForeignPrincipal 5, ADObjectReplication 7.
- The instrumented Windows PowerShell pass took 22 minutes and the
    uninstrumented PowerShell 7 pass 5 minutes, which is the measurement behind
    the single-coverage-pass decision.
- `./build.ps1 -Tasks test` succeeds: 10 tasks, 0 errors, 0 warnings. Local
    Pester is 1,495 passed, 0 failed, 0 skipped.
- Domain-lab coverage 43.07 percent (3,422 of 7,945 commands),
    `Domain-lab evidence merged: yes`. Whole-module 90.51 percent (7,191 of
    7,945) reported; asserted scope 90.54 percent (6,952 of 7,678) over the 80
    percent threshold.
- `ExactSecurityDescriptorDscLcm.Tests.ps1` passes 5 of 5 in Windows PowerShell.

## Host fix that unblocked the DSC evidence

`Invoke-DscResource` failed for every resource that reads an access control
list. The machine-level `PSModulePath` had grown three PowerShell 7 entries, so
the DSC provider host running as `SYSTEM` loaded PowerShell 7's
`Microsoft.PowerShell.Security` and refused it as duplicate type data. The
machine value is now the two Windows PowerShell paths only, backed up at
`$env:TEMP\wac-machine-psmodulepath.backup.txt`, and the WMI service was
restarted so provider hosts inherit it. `debugging-insights.md` records the
proof.

## Environment notes

- `WindowsAccessControlLab` has 13 machines across three forests. After a host
    reboot they must be started before an acceptance run.
- `F1BDC1` and `F2DC1` are no longer reserved; the foreign-principal suite takes
    one principal from each. `forest1.net` holds bidirectional forest-transitive
    trusts to `forest2.net` and `forest3.net`, which is what makes the
    cross-forest case resolvable from `a.forest1.net`.
- A standalone Pester run must import Pester by explicit path or prepend
    `output/RequiredModules` to `PSModulePath`.
- The changelog QA check compares the working tree against the default branch,
    so a gate started before `CHANGELOG.md` is edited fails on that one test.

## Next step

The remaining lab-specific gaps, in order of the evidence they would add:
concurrent writers on the two writable controllers to prove `RequireUnchanged`
across replication; an enterprise certificate template plus a key-reusing
renewal to test specification 0017's thumbprint claim against a real issued
key; a second Active Directory site for inter-site replication; selective
authentication on the forest trust; a read-only domain controller; and running
the suites against the installed package rather than `output/module`.
