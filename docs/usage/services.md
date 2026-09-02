# Services and the SCM

The service family covers two different objects: an individual Windows service,
and the local Service Control Manager that owns the service database. They use
separate parameter sets and separate rights enumerations, so a command can
never target one while you meant the other.

Neither object supports ACL inheritance.

## Target a named service

Commands use the **service name**, not the display name, and accept local
`ServiceController` objects through the pipeline:

```powershell
Get-ServiceAccessRule -Name BITS -Account 'BUILTIN\Users'

Get-Service -Name BITS | Get-ServiceAccessRule
```

If a target is "not found", the most common cause is a display name such as
`Background Intelligent Transfer Service` where the service name `BITS` was
required. Remote controllers and qualified remote names are rejected.

## Manage service access rules

```powershell
Get-Service -Name BITS |
    Add-ServiceAccessRule -Account 'BUILTIN\Users' `
        -ServiceRights QueryStatus `
        -WhatIf

Set-ServiceAccessRule -Name BITS `
    -Account 'BUILTIN\Users' `
    -ServiceRights QueryStatus, Start `
    -WhatIf
```

Removal consumes a rule emitted by the matching `Get` command, which keeps the
deletion bound to the exact ACE you inspected:

```powershell
Get-ServiceAccessRule -Name BITS -Account 'BUILTIN\Users' |
    Remove-ServiceAccessRule -WhatIf
```

`Clear-ServiceAccessRule` removes every explicit rule from the service DACL.

## Service rights

`WindowsServiceRights` names the service control operations rather than
exposing raw masks:

| Group | Values |
| --- | --- |
| Query | `QueryConfig`, `QueryStatus`, `EnumerateDependents`, `Interrogate` |
| Control | `Start`, `Stop`, `PauseContinue`, `UserDefinedControl` |
| Change | `ChangeConfig`, `Delete` |
| Descriptor | `ReadControl`, `WriteDac`, `WriteOwner`, `AccessSystemSecurity` |
| Composite | `AllAccess`, plus the generic rights |

Grant the narrowest set that satisfies the workload. `QueryStatus` alone lets a
monitoring account read service state without any ability to start or
reconfigure it.

## Target the Service Control Manager

The SCM is an explicit parameter set with its own rights enumeration, so you
cannot reach it by accident:

```powershell
Get-ServiceAccessRule -ServiceControlManager

Add-ServiceAccessRule -ServiceControlManager `
    -Account 'BUILTIN\Administrators' `
    -ControlManagerRights Connect `
    -WhatIf
```

| Right | Authorizes |
| --- | --- |
| `Connect` | Connecting to the service control manager |
| `CreateService` | Creating a new service |
| `EnumerateService` | Enumerating the installed services |
| `Lock` | Locking the service database |
| `QueryLockStatus` | Querying the database lock status |
| `ModifyBootConfig` | Changing the boot configuration |
| `AllAccess` | Every SCM right |

SCM access uses a local `OpenSCManagerW` handle that the module closes after
each operation.

## Descriptors

Read and write selected sections directly when a rule command is too granular:

```powershell
$descriptor = Get-ServiceSecurityDescriptor -Name BITS -Sections Access
$descriptor.Sddl

Set-ServiceSecurityDescriptor -Name BITS `
    -Sddl $descriptor.Sddl `
    -Sections Access `
    -WhatIf
```

Select the same sections on the write that you selected on the read. `Sections`
defaults to `All`, which would try to persist owner, group, and audit state
that an access-only read never captured.

Only the selected sections are written. Audit operations scope
`SeSecurityPrivilege`, and owner or group writes scope `SeRestorePrivilege`
when it is present in the token.

## Audit rules

Service and SCM audit rules mirror the access-rule commands:

```powershell
Add-ServiceAuditRule -Name BITS `
    -Account 'S-1-1-0' `
    -ServiceRights ChangeConfig `
    -AuditFlags Failure `
    -WhatIf

Get-ServiceAuditRule -Name BITS | Remove-ServiceAuditRule -WhatIf
```

See [Auditing and SACLs](auditing.md) for the privilege and audit-policy
requirements.

## Commands on this page

| Area | Commands |
| --- | --- |
| Descriptors | `Get-ServiceSecurityDescriptor`, `Set-ServiceSecurityDescriptor` |
| Access rules | `Get-ServiceAccessRule`, `Add-ServiceAccessRule`, `Set-ServiceAccessRule`, `Remove-ServiceAccessRule`, `Clear-ServiceAccessRule` |
| Audit rules | `Get-ServiceAuditRule`, `Add-ServiceAuditRule`, `Set-ServiceAuditRule`, `Remove-ServiceAuditRule`, `Clear-ServiceAuditRule` |

The same commands reach the SCM through the `ServiceControlManager` switch.

## See also

- [Live processes](processes.md)
- [Auditing and SACLs](auditing.md)
- [Desired State Configuration](dsc.md)
