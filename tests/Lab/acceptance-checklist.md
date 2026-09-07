# Lab Acceptance Checklist

Use this checklist for the next live run after the
[2026-09-06 audit](../../docs/test-gap-audit-2026-09-06.md). The local checks
prepare the candidate; they do not replace live acceptance.

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
because it instruments the built module, not the installed copy.

The new live cases are:

- `Should reject an escaped name outside the allowed OU without changing its
  DACL` in [ADObjectPermissions.Live.Tests.ps1](ADObjectPermissions.Live.Tests.ps1).
- `Should reject an old expected GUID after a distinguished name is reused` in
  [ADObjectReplication.Live.Tests.ps1](ADObjectReplication.Live.Tests.ps1).

Both require unchanged DACL evidence and exact-identity cleanup. The existing
replication suite still intentionally stops and restores the partner directory
service; check that the partner answers LDAP after the suite.

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
  target, cleanup error, or unavailable prerequisite. Do not weaken a test,
  force a write, or skip a suite to complete the run.
- Review residual risks in the audit record before treating the candidate as
  release-ready. In particular, request independent security review for the
  containment, immutable-identity, and exact-ACE changes.

After a failure, verify the actual descriptors and fixture ownership before
retrying. Restore the disposable checkpoint when the stored state or cleanup
cannot be established. No schema migration is required for this candidate.
