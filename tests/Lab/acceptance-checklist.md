# Lab Acceptance Checklist

Use this checklist for the next live run after the
[2026-09-06 audit](../../docs/test-gap-audit-2026-09-06.md). The local checks
prepare the candidate; they do not replace live acceptance.

The [2026-09-07 execution record](../../docs/lab-acceptance-2026-09-07.md)
documents the completed cross-edition, DSC, package, and cleanup gates and the
test-fixture repair found during that run. A later candidate needs fresh proof.

## Candidate and prerequisites

- Use the audited topic branch and record its commit and worktree status.
- Use one fresh package/build pair. Record the module and package SHA-256
  hashes, not only the version, because a local build without GitVersion can
  use the `0.0.1` fallback version.
- Use an elevated Hyper-V host session and the existing isolated
  `WindowsAccessControlLab`. Do not redeploy or remove it for this run.
- Checkpoint the disposable lab using the normal operator procedure.
- Confirm AutomatedLab, both PowerShell editions, Pester 5.7.1, RSAT, the two
  writable fixture-domain controllers, and the renewable CNG template are
  present as described in the [lab guide](README.md).
- Start the machines and verify AD readiness before acceptance. A running VM
  or successful ping is not proof that LDAP, Kerberos, or WinRM is ready.
- On the machine running Desktop DSC-engine integration, require
  `Test-WSMan -ComputerName localhost -ErrorAction Stop` to succeed. The audit
  host has WinRM stopped with manual startup; its two actual DSC-engine
  invocation tests cannot run successfully there. No remoting configuration
  was changed. Use a prepared lab machine, and do not skip those tests.
- Do not use `-SkipPayloadDeployment` for this first run: the old lab payload
  does not contain the new tests or fixes.
- Decide first what happens to directories that predate the runner's
  ownership marker, because the runner refuses to replace them. The unmarked
  `C:\WacRepo` payload on `F1ADC1` was removed after the 2026-10-07
  acceptance, so the default payload root works again. The unmarked `0.0.1`
  and `0.2.0` installations there were kept; a local build without GitVersion
  has that same `0.0.1` version. Either keep such a directory and add a new,
  absent `RemoteRepositoryPath` to `$parameters` or install a package with
  another version, or inspect it and remove it yourself. The runner has no
  backup and restore. See
  [payload and module ownership](README.md#payload-and-module-ownership).

Inspect the candidate locally:

```powershell
git status --short --branch
git log -1 --oneline
Get-ChildItem .\output\module\WindowsAccessControl\*\WindowsAccessControl.psm1 |
    Get-FileHash -Algorithm SHA256
Get-ChildItem .\output\WindowsAccessControl.*.nupkg |
    Get-FileHash -Algorithm SHA256
```

Rebuild after any source change, then rerun the local gates. The `test`
workflow alone tests the existing build. Keep `pack` and `test` in separate
processes because documentation generation can affect PowerShell's module-type
cache. Never run two profiles concurrently against the shared fixture set.

## Detached live run

Run this from the repository root in the elevated host session. It uses the
installed canonical detached launcher, unique TEMP artifacts, and the existing
host acceptance runner. It contains no credentials and does not elevate itself.
The final `LAB-ACCEPTANCE-DONE` marker is emitted only after the runner returns
successfully.

```powershell
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
  $principal = [Security.Principal.WindowsPrincipal]::new($currentIdentity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this checklist from an elevated PowerShell host session.'
  }
} finally {
  $currentIdentity.Dispose()
}
$runId = [guid]::NewGuid().ToString('N')
$logPath = Join-Path $env:TEMP "wac-live-$runId.log"
$evidencePath = Join-Path $env:TEMP "wac-live-$runId.json"
$repositoryPath = (Get-Location).Path.Replace("'", "''")
$escapedLogPath = $logPath.Replace("'", "''")
$escapedEvidencePath = $evidencePath.Replace("'", "''")
$payload = @"
Set-Location -LiteralPath '$repositoryPath'
`$ErrorActionPreference = 'Stop'
try {
    & {
        '[{0:u}] LAB-ACCEPTANCE-START' -f [datetime]::UtcNow
        Import-Module AutomatedLab -ErrorAction Stop
        Import-Lab -Name WindowsAccessControlLab -NoValidation
        Start-LabVM -ComputerName (Get-LabVM).Name -Wait
        Wait-LabADReady -ComputerName (Get-LabVM -Role RootDC, FirstChildDC, DC).Name
        `$parameters = @{
            PowerShellEdition = @('Desktop', 'Core')
            CoverageEdition = 'Desktop'
            EvidencePath = '$escapedEvidencePath'
            Confirm = `$false
            ErrorAction = 'Stop'
        }
        & .\tests\Lab\Invoke-WindowsAccessControlLabAcceptance.ps1 @parameters
        '[{0:u}] LAB-ACCEPTANCE-DONE' -f [datetime]::UtcNow
    } *>&1 | Out-File -LiteralPath '$escapedLogPath' -Encoding utf8
} catch {
    `$_ | Format-List * -Force | Out-String |
        Out-File -LiteralPath '$escapedLogPath' -Encoding utf8 -Append
    exit 1
}
"@
$launcher = Join-Path $HOME (
    '.copilot\skills\long-running-job-monitor\scripts\Start-DetachedPowerShell.ps1'
)
if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
    throw "The required detached launcher is missing: $launcher"
}
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
$run = & $launcher -EncodedCommand $encoded
$run | Add-Member -NotePropertyName LogPath -NotePropertyValue $logPath -PassThru
```

Inspect the returned result marker and log on demand, without a foreground
sleep/poll loop:

```powershell
Get-Content -LiteralPath $run.ResultPath -ErrorAction SilentlyContinue
Get-Content -LiteralPath $logPath -Tail 30
```

An absent exit marker means no completion result is available, not success.
Require marker `0`, `LAB-ACCEPTANCE-DONE`, and the collected evidence checks
below. A dropped control channel is not permission to rerun against fixtures
that might still be active; inspect the guest console log first.

## Required passes

| Pass | Selection | Gate |
| --- | --- | --- |
| Built module | Desktop and Core; coverage on Desktop only | All eight suites pass in each edition with zero skipped tests and ready cleanup ledgers. |
| Desktop DSC engine | Run [ExactSecurityDescriptorDscLcm.Tests.ps1](../Integration/ExactSecurityDescriptorDscLcm.Tests.ps1) in an isolated Windows PowerShell 5.1 process on a prepared lab machine before the installed-package pass | Five tests pass, including both actual `Invoke-DscResource` cases. The fixture refuses to overwrite an existing installation of the same version. |
| Installed package | A separate run with `ModuleSource = 'Installed'`, `CoverageEdition = 'None'`, and explicit `PackagePath` | Both editions import and test the packaged candidate, not a previous installed version. |
| Local regression and coverage merge | Fresh detached `build.ps1 -Tasks test` after collecting lab coverage | The current-build lab coverage is accepted and the configured 80 percent gate passes. |

For the installed pass, use a new run ID and the same detached wrapper. Add
`ModuleSource = 'Installed'` and an explicit absolute `PackagePath` inside
`$parameters`, and change `CoverageEdition` to `None`. Do not reuse the first
run's evidence name. The runner deliberately refuses installed-package coverage
because it instruments the built module, not the installed copy. It marks the
module version directory it installs and refuses to replace an unmarked
installation of the same version.

The most recently added live cases are:

- `Should accept and repair a protected folder and task DACL that has no Local
  System ACE` in
  [TaskSchedulerPermissions.Live.Tests.ps1](TaskSchedulerPermissions.Live.Tests.ps1).
  It creates its own disposable folder and task and deletes both.
- `Should restore a description that the native DACL write cleared`,
  `Should keep a description edited during the DACL write and warn with the
  earlier value`, and `Should stop before writing when the description cannot
  be read before the write` in
  [SmbSharePermissions.Live.Tests.ps1](SmbSharePermissions.Live.Tests.ps1).
  The second races a native watcher against the setter's read-back and retries
  a lost race, up to five writes; the third injects its read failure through a
  module-scope shadow of `Get-SmbShare`.

Every earlier case still runs, including the escaped-name and reused-GUID
regressions, which require unchanged DACL evidence and exact-identity cleanup.
The existing replication suite still intentionally stops and restores the
partner directory service; check that the partner answers LDAP after the
suite.

## Evidence and stop conditions

- Require newly collected `-desktop.json` and `-core.json` reports with
  `Result = 'Passed'`, eight suites each, zero skips, and eight ready cleanup
  entries. Discovery-only results never qualify.
- Inspect both domain and member readiness flags in every cleanup entry.
- Require current-build JaCoCo coverage at the configured collection path.
  Missing or stale coverage must fail, not be replaced by an older report.
- Retain exact failure messages and raw logs in administrator TEMP. Raw logs
  are not sanitized and must not be published or put in the lab payload tree.
- Stop on a failed suite, missing evidence, unknown exit status, unexpected
  target, cleanup error, unavailable prerequisite, or ownership refusal. Do
  not weaken a test, force a write, or skip a suite to complete the run, and
  do not delete a refused directory before inspecting it.
- Review residual risks in the audit record before treating the candidate as
  release-ready. In particular, request independent security review for the
  containment, immutable-identity, and exact-ACE changes.

After a failure, verify the actual descriptors and fixture ownership before
retrying. Restore the disposable checkpoint when the stored state or cleanup
cannot be established. No schema migration is required for this candidate.
