# Domain acceptance lab

This directory holds the disposable multi-forest lab that the enterprise
acceptance suites run against, together with the runners and the test-only
fixture harness. It is written for the operator who deploys the lab on a
Hyper-V host and runs the unattended acceptance profile.

For the next audit candidate, use the [acceptance checklist](acceptance-checklist.md)
for detached execution, the new regression cases, and current-run evidence gates.

## Baseline

The topology starts from the AutomatedLab sample scenario
`Multi-AD Forest with Trusts.ps1`, which ships with AutomatedLab under
`<LabSources>\SampleScripts\Scenarios`. That sample defines:

- three forests: `forest1.net` with the child domains `a.forest1.net` and
  `b.forest1.net`, plus the single-domain forests `forest2.net` and
  `forest3.net`
- one domain controller and one file server in every domain
- the parent-child and forest-transitive trusts AutomatedLab creates between
  them

[Deploy-WindowsAccessControlLab.ps1](Deploy-WindowsAccessControlLab.ps1) keeps
that domain, machine-name, and trust shape and is the only lab definition this
repository supports. The sample itself is not copied into the repository: it
hard-codes an installation password, and a second lab definition would drift
from the one the suites assert against.

## Why the baseline alone is not sufficient

The sample deploys directory infrastructure only. On it no suite can even be
discovered, because Windows Server ships Pester 3.4; once that is fixed, the
replication suite stops in `BeforeAll` and the directory-service binding
assertion in the private-key suite fails. The deployment adds what those suites
need, plus the reserved capacity listed below.

| Addition | Where | Required because |
| --- | --- | --- |
| Enterprise root certification authority | `F1CA1` with the `CaRoot` role | Every domain controller in the forest then automatically enrolls a server-authentication certificate. The directory-service branch of the fail-closed private-key binding gate asserts that at least one `DirectoryServices` binding exists and that its detail names `NTDS\MY` or `My`. Without a certification authority in the forest no such certificate exists and the assertion fails. |
| Second writable domain controller in the fixture domain | `F1ADC2` with the `DC` role | `ADObjectReplication.Live.Tests.ps1` throws in `BeforeAll` when the fixture domain has fewer than two writable domain controllers. Replication convergence, controller switch, and the pinned-controller outage test all need a partner. Specification 0016 records the resulting contract. |
| PowerShell 7 on every machine | `Install-LabSoftwarePackage` | Acceptance runs in both supported editions. The sample installs Notepad++ and WinRAR instead, and no suite uses either. |
| Pester 5 in both module roots on every machine | `Copy-LabFileItem` | The suites are Pester 5 files and Windows Server ships Pester 3.4. Copying into the `WindowsPowerShell` and the `PowerShell` module root keeps the cross-edition run working without an ad-hoc payload copy. |
| `RSAT-AD-PowerShell` | `Invoke-LabCommand` | The replication suite calls `Get-ADDomain` and `Get-ADDomainController`. The feature is present on a domain controller but not on a member server. |
| Installation credential as a parameter | `-InstallationCredential` | The sample hard-codes `Somepass1`. This repository stores no credential, key, or recovery value. |
| Predecessor lab, orphaned switch, and stale host-entry removal | `-RemoveExistingLab` and `-RemoveLabName` | A teardown that fails partway leaves the virtual switch behind. The host adapter then keeps the retired subnet while the new lab picks the next free one, and every new machine is stranded with no route to the host. A stale host-file entry additionally makes `Install-Lab` refuse to redirect a machine name. |
| Separate memory budgets per role | `-DomainControllerMemoryMB` and `-MemberMemoryMB` | The lab defines 13 machines rather than the sample's nine, so member servers take less memory than domain controllers. |
| Renewable CNG certificate template | `New-LabCATemplate` on `F1CA1` | Specification 0017 states that a certificate thumbprint is evidence rather than a selector, because a renewal that reuses the key changes the thumbprint over the same key. No built-in template both issues a CNG key and requires the same key on renewal, so the deployment publishes `WacLabRenewableComputer` at schema version 4 with `ReuseKeysRenewal`. |

The answer to "should it also deploy a public key infrastructure" is therefore
yes, and it already does. The certification authority is the one added service
without which an existing assertion fails.

## Machines

| Machine | Domain | AutomatedLab role | Exercised by |
| --- | --- | --- | --- |
| `F1DC1` | `forest1.net` | `RootDC` | Forest root and trust shape |
| `F1DC2` | `forest1.net` | `DC` | Reserved |
| `F1CA1` | `forest1.net` | `CaRoot` | Domain-controller certificate enrollment for the private-key binding suite |
| `F1ADC1` | `a.forest1.net` | `FirstChildDC` | Management machine: hosts the harness, the directory suites, and the directory-service binding suite |
| `F1ADC2` | `a.forest1.net` | `DC` | Replication, convergence, controller switch, and pinned-controller outage |
| `F1AFile1` | `a.forest1.net` | `FileServer` | Member fixtures: SMB share, Task Scheduler folder, and the private key |
| `F1AFile2` | `a.forest1.net` | `FileServer`, `WebServer` | Reserved |
| `F1BDC1` | `b.forest1.net` | `FirstChildDC` | Cross-domain principal for the foreign-principal suite |
| `F1BFile1` | `b.forest1.net` | `FileServer` | Reserved |
| `F2DC1` | `forest2.net` | `RootDC` | Cross-forest principal for the foreign-principal suite |
| `F2File1` | `forest2.net` | `FileServer` | Reserved |
| `F3DC1` | `forest3.net` | `RootDC` | Reserved |
| `F3File1` | `forest3.net` | `FileServer` | Reserved |

Reserved machines are deployed but not referenced by a suite today. `F1DC2`
and `F1AFile2` are additions beyond the baseline; the rest come from the sample
itself. `F1BDC1` and `F2DC1` are no longer reserved:
`ForeignPrincipalPermissions.Live.Tests.ps1` takes one principal from each, so
a cross-domain and a cross-forest security identifier are written and read for
real. That identity surface is why the multi-forest sample was chosen as the
baseline rather than a single-domain one.

## Files

| File | Purpose |
| --- | --- |
| [Deploy-WindowsAccessControlLab.ps1](Deploy-WindowsAccessControlLab.ps1) | Defines and installs the lab, and removes a predecessor lab, its orphaned virtual switch, and stale host-file entries first. |
| [Invoke-WindowsAccessControlLabAcceptance.ps1](Invoke-WindowsAccessControlLabAcceptance.ps1) | Copies the current build and the suites into the management domain controller, runs one unattended profile per PowerShell edition there, and carries the redacted evidence and the coverage document back to the host. |
| [Start-WindowsAccessControlDomainLabAcceptance.ps1](Start-WindowsAccessControlDomainLabAcceptance.ps1) | Starts the profile in a child console process inside the lab, because a session runspace allows far fewer nested script frames than a console host. |
| [Resolve-WindowsAccessControlLabModuleRoot.ps1](Resolve-WindowsAccessControlLabModuleRoot.ps1) | Returns the module directory every suite imports. It is the build output unless `WAC_LAB_MODULE_ROOT` names an installed module, and it fails rather than falling back when that variable is wrong. |
| [WindowsAccessControl.LabRunnerOwnership.ps1](WindowsAccessControl.LabRunnerOwnership.ps1) | The runner's ownership and path decisions. Every remote step that creates or deletes a directory on the management domain controller makes them there; see [Payload and module ownership](#payload-and-module-ownership). |
| [WindowsAccessControl.DomainLab.psm1](WindowsAccessControl.DomainLab.psm1) | Test-only harness: fixture plan, setup, status, teardown, coverage arming, and the unattended acceptance profile. |
| `*.Live.Tests.ps1` | The eight acceptance suites. |
| `coverage/` | The JaCoCo document the acceptance carries back. The build merges it into the reported coverage when it measures the current build; see decisions 0025 and 0027. |

## Run the lab

Prerequisites: an elevated host session, Hyper-V, AutomatedLab, the operating
system in the AutomatedLab inventory (`Get-LabAvailableOperatingSystem`), and
restored repository dependencies, because the Pester payload defaults to
`output\RequiredModules\Pester\5.7.1`.

```powershell
.\build.ps1 -ResolveDependency

$credential = Get-Credential -UserName Install -Message 'Lab administrator'
.\tests\Lab\Deploy-WindowsAccessControlLab.ps1 -InstallationCredential $credential
```

Redeploy over an existing lab of the same name:

```powershell
.\tests\Lab\Deploy-WindowsAccessControlLab.ps1 -InstallationCredential $credential -RemoveExistingLab
```

Build the module, then run the acceptance from the host:

```powershell
.\build.ps1 -Tasks build
.\tests\Lab\Invoke-WindowsAccessControlLabAcceptance.ps1
```

Reuse the repository tree already copied to the management domain controller:

```powershell
.\tests\Lab\Invoke-WindowsAccessControlLabAcceptance.ps1 -SkipPayloadDeployment -Confirm:$false
```

`-SkipPayload` remains available as a compatibility alias, and
`-SkipDeployment` is the concise equivalent. Omit `-Confirm:$false` to retain
the safety confirmation for the acceptance run, which still changes disposable
lab fixtures even when it does not deploy the payload.

Start the machines before that call and give the domain controllers time to
answer:

```powershell
Import-Lab -Name WindowsAccessControlLab -NoValidation
Start-LabVM -ComputerName (Get-LabVM).Name -Wait
Wait-LabADReady -ComputerName (Get-LabVM -Role RootDC, FirstChildDC, DC).Name
```

Forcing replication before the run does not help, and an earlier revision of
this file wrongly said it did. The fixture is recreated at the start of every
run, so what matters is whether the partner receives it *during* the run.
Measured on 2026-08-11: `F1ADC2` reported `failures=0` with its last inbound
replication of the domain partition timed at the pre-run sync, and it still
served the previous run's `Targets` organizational unit thirty minutes later.
`ADObjectReplication.Live.Tests.ps1` therefore pushes the fixture chain to the
partner itself, in `BeforeAll` and again for every disposable object, rather
than assuming the partner is current.

That runs one complete pass per supported PowerShell edition against the same
fixture set. Only the pass named by `-CoverageEdition` arms code coverage:
instrumentation is what makes a pass slow, and the second pass reaches no line
the first cannot. Measured on 2026-08-08, the instrumented Windows PowerShell
pass took 22 minutes and the uninstrumented PowerShell 7 pass 5 minutes. Run a
single edition with `-PowerShellEdition Core`.

Each pass retains its console output on the management domain controller as
`wac-lab-evidence-<run-id>-<edition>.console.log` in the running administrator's `TEMP`
directory, and the runner prints the resolved path. The log advances while the
child process runs, so a separate session can inspect suite progress without
waiting for the host runner to return.

Remote evidence and coverage names also include the run ID. A missing current
artifact cannot be satisfied by a previous run's file. Missing exit status,
failed evidence collection, and coverage-finalization errors fail acceptance.

That log is raw child-process output and is **not** redacted, unlike the
retained JSON evidence. It is deliberately kept out of `C:\WacRepo`, because
that payload directory inherits a `BUILTIN\Users` read grant, which on a domain
controller includes every domain user. Treat it as an administrator-only
diagnostic, delete it when an investigation ends, and share only the JSON.

Remove the lab:

```powershell
Import-Lab -Name WindowsAccessControlLab -NoValidation
Remove-Lab -Confirm:$false
```

The suites read `WAC_DOMAIN_LAB_MEMBER` to reach the fixture member server and
`WAC_DOMAIN_LAB_COVERAGE` to arm coverage in the member runspace. The
acceptance profile sets both for the duration of the call and restores them
afterwards, so neither has to be set by hand.

## Run against the installed package

Every suite imports the module from `output\module` by default, which is the
tree the build wrote rather than the tree a consumer installs.
`-ModuleSource Installed` closes that gap: it expands the packaged module into
the machine module path of the management domain controller, points every suite
at that copy through `WAC_LAB_MODULE_ROOT`, and asserts that the module is
reachable by name from `PSModulePath`.

```powershell
.\build.ps1 -Tasks pack
.\tests\Lab\Invoke-WindowsAccessControlLabAcceptance.ps1 -ModuleSource Installed -CoverageEdition None
```

Coverage instruments the built module, so an installed-package run refuses to
arm it. Measuring a module no suite loads would report a green run over an
unmeasured module rather than report the gap.

## Payload and module ownership

The runner deletes only directories it created. It writes the marker file
`.windows-access-control-lab-runner` into each directory it may later replace
on the management domain controller: the payload root named by
`-RemoteRepositoryPath`, its `package` staging directory, and the installed
module version directory under
`%ProgramFiles%\WindowsPowerShell\Modules\WindowsAccessControl`. A later run
replaces one of them only when it is absent, or still carries that marker and
contains no junction or symbolic link at any depth, because Windows PowerShell
5.1 deletes through a junction during a recursive removal.

The management domain controller makes these checks itself, before anything
there changes and also with `-SkipPayloadDeployment`. The payload root must be
an absolute path on a local fixed drive, and it must not be a drive root, pass
through a junction or symbolic link, or lie under the Windows directory,
Program Files, ProgramData, or the user profile root.

When a directory exists without the marker, or contains a junction or symbolic
link, the run stops before it deletes anything. The error names the directory,
and the link when there is one, and the way out:

| Refused directory | Resolution |
| --- | --- |
| Payload root | Inspect it, then remove or rename it yourself if it is disposable, or pass `-RemoteRepositoryPath` with a directory that does not exist yet. |
| `package` under a reused payload root | Inspect it, then remove or rename it yourself if it is disposable, or deploy a fresh payload without `-SkipPayloadDeployment`. |
| Installed module of the package's version | Inspect it, then uninstall or move it yourself if it is disposable, or install a package with a different module version. |

For a junction or symbolic link, remove the link itself rather than what it
points to, and run again.

Directories left by runs before the marker existed carry no marker. The
`C:\WacRepo` payload that `F1ADC1` held until 2026-10-07 was one of them; it
was removed after that day's acceptance, so the default payload root works
again. The installed-package pass likewise refuses an unmarked installation of
the package's version, such as the `0.0.1` installation the
[2026-09-07 reacceptance](../../docs/lab-reacceptance-2026-09-07.md) found and
restored on `F1ADC1`; a local build without GitVersion also has version
`0.0.1`. Decide before the run whether to keep such a directory and choose a
new payload path or package version, or to remove it after confirming that
nothing else uses it. The runner has no backup and restore; it refuses
instead.

AutomatedLab can report a failed remote step without ending the calling
script, so the runner also stops when a step does not confirm the directory it
checked or prepared.

## Known gaps

- No read-only domain controller. AutomatedLab exposes no read-only domain
  controller role, so any claim about read-only directory behavior needs manual
  promotion first.
- No second site, so no claim about inter-site replication latency or
  scheduling.
- Selective authentication is not configured on the forest trust, so no claim
  about a principal that is resolvable but not allowed to authenticate.

## Safety

The lab is disposable, holds no production data, and must never be attached to
a production network. It uses an internal Hyper-V switch with no external
adapter. The operator supplies the installation credential at run time, and no
credential, key, or recovery value is stored in this repository. The fixture
harness owns its resources through exact identities and markers; the marker is
a collision and cleanup-ownership guard inside this trusted lab, not an
authorization control.

## See also

- [Domain lab inventory](../../docs/domain-lab-inventory.md)
- [Enterprise access-control expansion](../../specs/0008-enterprise-access-control-expansion.md)
- [Active Directory multi-controller behavior](../../specs/0016-active-directory-multi-controller-behavior.md)
- [Enterprise domain-lab decision](../../specs/decisions/0014-stage-enterprise-expansion-behind-domain-lab.md)
- [Coverage measurement decision](../../specs/decisions/0025-fix-coverage-measurement-not-threshold.md)
- [Project README](../../README.md)
