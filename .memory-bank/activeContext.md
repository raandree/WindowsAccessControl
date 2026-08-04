---
status: current
last-verified: 2026-08-03
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

Two unit tests failed only on Windows PowerShell 5.1. Both were defects in the
test file, not in the module, and both are fixed in
`tests/Unit/Private/WindowsRegistryInheritanceSource.Tests.ps1`.

## Why the suite was green on PowerShell 7 and red on 5.1

- `Get-Acl -LiteralPath 'HKCU:\Control Panel'` fails on 5.1 with
    `GetAcl_PathNotFound` and returns nothing, so
    `.GetSecurityDescriptorBinaryForm()` reported "You cannot call a method on a
    null-valued expression" one line later. The registry provider is what breaks;
    `-Path` returns the descriptor on 5.1 and PowerShell 7 accepts both. The
    module itself only passes `-LiteralPath` a filesystem path, which works in
    both editions, so this never reached production code.
- `[AceFlags]::Inherited -bor [AceFlags]::ContainerInherit` throws
    `InvalidCastException` on 5.1. The discriminator is the underlying type, and
    it was measured rather than assumed: `AceFlags` and `AceType` are `Byte`,
    while `ControlFlags`, `AuditFlags`, `ObjectAceFlags`, `AceQualifier`,
    `AccessControlSections`, `InheritanceFlags`, and `PropagationFlags` are
    `Int32` and combine directly. Every other `AceFlags` mask in the repository
    already used `[int]` operands or the string form.

## Acceptance evidence

- The Windows PowerShell 5.1 `-Tasks test` workflow now passes 1,448 of 1,448
    with zero skips, and the merged coverage gate reports SUCCESS at 80.69
    percent over the 7,678 commands this profile can execute.
- The same run before the fixes passed 1,444 of 1,448. Two failures were the
    test defects above; the other two were the host defect below.
- The fixed file passes 17 of 17 in Windows PowerShell 5.1 and 17 of 17 in
    PowerShell 7.
- `Invoke-ScriptAnalyzer` over the changed test file is clean.

## Two of the four 5.1 failures were this host, not the repository

`ExactSecurityDescriptorDscLcm.Tests.ps1` fails its two `Invoke-DscResource`
cases with "The 'Get-Acl' command was found in the module
'Microsoft.PowerShell.Security', but the module could not be loaded". It
reproduces with that file alone, so it is not test-order contamination. The
same host also aborts `.\build.ps1` in the VS Code PowerShell Extension
terminal with "The term 'Import-PowerShellDataFile' is not recognized".

Both are one cause. The machine `PSModulePath` carries
`c:\program files\powershell\7\Modules` ahead of
`C:\Windows\system32\WindowsPowerShell\v1.0\Modules`, so Windows PowerShell 5.1
resolves PowerShell 7's `Core`-only `Microsoft.PowerShell.Security` and
`Microsoft.PowerShell.Utility` first and cannot load either. Only a host that
must autoload them is affected, which is why `powershell.exe -File build.ps1`
succeeds while the extension terminal and the DSC engine fail. Removing that
one path entry was measured to fix both lookups. Nothing in the repository
writes that variable, and PowerShell 7's installer does not add its own
`$PSHOME\Modules` there.

The Windows PowerShell 5.1 test job now repairs the machine variable itself
before it runs, because a build worker has the rights to do so and the repair
must be reproducible rather than a manual step on one developer host. It
removes every `\PowerShell\<n>\Modules` entry, republishes the corrected value
to later steps, and restarts `Winmgmt` so `Invoke-DscResource` sees it. It is a
no-op on a worker that carries no such entry. This developer host was repaired
the same way, and `ExactSecurityDescriptorDscLcm.Tests.ps1` then passed 3 of 3
without any source change, which is the proof that the diagnosis was right.

## Environment notes

- The development host is the Hyper-V host and is a workgroup machine. The
    module pins Kerberos for its LDAP bind, so the enterprise suites run inside
    the lab through AutomatedLab credential delegation.
- `WindowsAccessControlLab` has 13 machines across three forests. After a host
    reboot the machines must be started before the acceptance runs, and the
    member fixture reports not ready for a short time while its services start.
- A standalone Pester run must prepend `output/module` and
    `output/RequiredModules` to `PSModulePath`. Without them, 36 DSC discovery
    and Sampler-dependent tests fail for a reason none of them caused.
- The certificate private-key unit tests remain flaky here because they
    exercise the live key storage provider.
- The committed domain-lab coverage document still measures a module the current
    `main` build does not produce, so the merged whole-module verdict is
    reported rather than asserted until the lab acceptance is rerun.

## Next step

No specification is in `Draft` and no focused issue is open. One operational
candidate remains: rerun the domain-lab coverage document so the merged
whole-module number can be reported with lab evidence again.

Every other candidate (SMB-6, AD-7, directory audit rules, directory
inheritance and owner/group mutation, CAPI) is a written deferral and needs a
new accepted scope decision before implementation.
