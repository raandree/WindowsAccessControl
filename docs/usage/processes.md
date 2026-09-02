# Live processes

Process permissions are ephemeral. They belong to one running process instance
and end when that instance exits. Process ACLs do not support inheritance.

## Target a process

Commands accept a PID, a local `System.Diagnostics.Process` object, module
output, or a caller-owned handle:

```powershell
$process = Get-Process -Id $PID

$descriptor = $process | Get-ProcessSecurityDescriptor -Sections Access
$descriptor | Get-ProcessAccessRule
```

`InputObject` has the aliases `Process`, `Id`, and `ProcessId`, so a PID works
positionally or by name:

```powershell
Get-ProcessSecurityDescriptor -ProcessId $PID -Sections Access
```

## PID reuse fails closed

Windows reuses process identifiers. The module pins a PID target by PID **plus
creation `FILETIME`** and revalidates that pairing before every descriptor read
and write. If the original process exited, subsequent operations fail with an
identity mismatch instead of silently changing whichever process now holds that
PID.

When you see that error, reacquire the live process and read its descriptor
again:

```powershell
$process = Get-Process -Name 'MyService' | Select-Object -First 1
$descriptor = $process | Get-ProcessSecurityDescriptor -Sections Access
```

## Caller-owned handles

A handle you opened stays yours. The module uses it and never closes it:

```powershell
Get-ProcessSecurityDescriptor -Handle $process.Handle -Sections Access
```

For PID targets, the module opens its own handle once per operation,
revalidates creation time, and uses that handle for the read, the comparison,
and the write.

## Manage access rules

```powershell
Add-ProcessAccessRule -InputObject $descriptor `
    -Account 'BUILTIN\Users' `
    -ProcessRights QueryLimitedInformation `
    -WhatIf

Get-ProcessAccessRule -InputObject $PID -Account 'BUILTIN\Users' |
    Remove-ProcessAccessRule -WhatIf
```

`Clear-ProcessAccessRule` removes every explicit rule from the process DACL.

## Process rights

`WindowsProcessRights` names the operation each mask authorizes:

| Group | Values |
| --- | --- |
| Read | `QueryInformation`, `QueryLimitedInformation`, `VmRead` |
| Write | `SetInformation`, `SetLimitedInformation`, `SetQuota`, `VmWrite`, `VmOperation` |
| Control | `Terminate`, `SuspendResume`, `CreateThread`, `CreateProcess`, `SetSessionId` |
| Handles | `DuplicateHandle` |
| Descriptor | `Delete`, `ReadControl`, `WriteDac`, `WriteOwner`, `AccessSystemSecurity` |
| Composite | `AllAccess`, plus the generic rights |

`QueryLimitedInformation` is the right a monitoring agent usually needs. It
exposes the process image name and basic state without granting the memory
access that `QueryInformation` implies.

## SeDebugPrivilege

Opening a process you would otherwise be denied can require
`SeDebugPrivilege`. The module retries with it **only** after an access denial,
and only when the privilege is already present in the process token. It never
enables it speculatively.

## Audit rules

```powershell
Add-ProcessAuditRule -InputObject $PID `
    -Account 'S-1-1-0' `
    -ProcessRights Terminate `
    -AuditFlags Success `
    -WhatIf
```

See [Auditing and SACLs](auditing.md).

## Desired state is ephemeral

A process desired-state resource is valid only while the pinned instance is
alive, and requires both the PID and the creation `FILETIME` so that PID reuse
fails closed. Use it for a long-lived process instance rather than for
something that restarts routinely. See
[Desired State Configuration](dsc.md).

## Commands on this page

| Area | Commands |
| --- | --- |
| Descriptors | `Get-ProcessSecurityDescriptor`, `Set-ProcessSecurityDescriptor` |
| Access rules | `Get-ProcessAccessRule`, `Add-ProcessAccessRule`, `Set-ProcessAccessRule`, `Remove-ProcessAccessRule`, `Clear-ProcessAccessRule` |
| Audit rules | `Get-ProcessAuditRule`, `Add-ProcessAuditRule`, `Set-ProcessAuditRule`, `Remove-ProcessAuditRule`, `Clear-ProcessAuditRule` |

## See also

- [Services and the SCM](services.md)
- [Safety, preview, and privileges](safety-and-privileges.md)
- [Troubleshooting](troubleshooting.md)
