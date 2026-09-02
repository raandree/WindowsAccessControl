# WindowsAccessControl usage guide

This guide shows the common workflows for inspecting, changing, validating,
and preserving Windows security descriptors with `WindowsAccessControl`.

It is split into focused pages so a reader who manages one object family does
not have to scroll past nine others. Start from the workflow table below, or
read [Getting started](usage/getting-started.md) end to end.

Use the command help when you need every parameter or output property:

```powershell
Get-Help Get-NTFSAccessRule -Full
Get-Help Get-NTFSAccessRule -Examples
```

## Before you begin

`WindowsAccessControl` supports Windows PowerShell 5.1 and PowerShell 7 on
Windows, and has no third-party runtime dependency:

```powershell
Install-PSResource -Name WindowsAccessControl
Get-Command -Module WindowsAccessControl
```

[Getting started](usage/getting-started.md) covers the older client, building
from source, verifying the import, the sample values every page uses, and the
local-target model.

## Choose a workflow

| Goal | Page |
| --- | --- |
| Install the module and run a first command | [Getting started](usage/getting-started.md) |
| Preview a change before it happens | [Safety, preview, and privileges](usage/safety-and-privileges.md) |
| Inspect or change file and directory permissions | [File system](usage/file-system.md) |
| Manage registry key permissions | [Registry keys](usage/registry.md) |
| Manage service or Service Control Manager permissions | [Services and the SCM](usage/services.md) |
| Manage permissions on a running process | [Live processes](usage/processes.md) |
| Manage SMB share permissions | [SMB shares](usage/smb-shares.md) |
| Delegate Active Directory object access | [Active Directory objects](usage/active-directory.md) |
| Manage task folder and scheduled task DACLs | [Task Scheduler](usage/task-scheduler.md) |
| Grant a service account access to a private key | [Certificate private keys](usage/certificate-private-keys.md) |
| Make several edits with one descriptor write | [Descriptor editing and concurrency](usage/descriptor-editing.md) |
| Configure auditing | [Auditing and SACLs](usage/auditing.md) |
| Copy, back up, or restore descriptors | [Backup, restore, and copy](usage/backup-and-restore.md) |
| Resolve an identity or check effective access | [Diagnostics, batching, and metrics](usage/diagnostics.md) |
| Enforce permissions as desired state | [Desired State Configuration](usage/dsc.md) |
| Understand an error | [Troubleshooting](usage/troubleshooting.md) |
| Find a command by name | [Command reference](usage/command-reference.md) |

## Guide map

### Foundations

- [Getting started](usage/getting-started.md)
- [Safety, preview, and privileges](usage/safety-and-privileges.md)
- [Descriptor editing and concurrency](usage/descriptor-editing.md)

### Object families

- [File system](usage/file-system.md)
- [Registry keys](usage/registry.md)
- [Services and the SCM](usage/services.md)
- [Live processes](usage/processes.md)
- [SMB shares](usage/smb-shares.md)
- [Active Directory objects](usage/active-directory.md)
- [Task Scheduler](usage/task-scheduler.md)
- [Certificate private keys](usage/certificate-private-keys.md)

### Cross-cutting workflows

- [Auditing and SACLs](usage/auditing.md)
- [Backup, restore, and copy](usage/backup-and-restore.md)
- [Diagnostics, batching, and metrics](usage/diagnostics.md)
- [Desired State Configuration](usage/dsc.md)
- [Troubleshooting](usage/troubleshooting.md)
- [Command reference](usage/command-reference.md)

## How the module is organized

Every supported object family follows the same shape, so learning one family
teaches you the rest:

| Layer | Pattern | Example |
| --- | --- | --- |
| Descriptor | `Get-*SecurityDescriptor`, `Set-*SecurityDescriptor` | `Get-NTFSItemSecurityDescriptor` |
| Access rules | `Get`, `Add`, `Set`, `Remove`, `Clear` `*AccessRule` | `Add-RegistryKeyAccessRule` |
| Audit rules | `Get`, `Add`, `Set`, `Remove`, `Clear` `*AuditRule` | `Remove-ServiceAuditRule` |
| Inheritance | `Get`, `Enable`, `Disable` `*Inheritance` | `Disable-NTFSItemInheritance` |
| Desired state | `WindowsAccessControl<Family>AccessRule` and `...SecurityDescriptor` | `WindowsAccessControlNtfsAccessRule` |

Not every family exposes every layer. Services, processes, SMB shares, and
private keys have no inheritance commands. SMB shares, Active Directory
objects, Task Scheduler objects, and private keys expose no audit rules. The
[command reference](usage/command-reference.md) lists exactly what each family
has.

Two verbs carry meaning that is easy to miss:

- `Add` accumulates. It leaves unrelated rules alone.
- `Set` replaces the rules for the same account and the same allow or deny
  qualifier, and preserves the opposite qualifier and other accounts.

## Preview every mutation

Rule, descriptor, owner, inheritance, backup, restore, and privilege mutators
support `WhatIf` and `Confirm`. Preview a change, review the target and action,
and then run the same command without `WhatIf`:

```powershell
$grantParameters = @{
    LiteralPath  = 'C:\Data'
    Account      = 'CONTOSO\Analysts'
    AccessRights = 'Modify'
    AppliesTo    = 'ThisFolderSubfoldersAndFiles'
}

Add-NTFSAccessRule @grantParameters -WhatIf
Add-NTFSAccessRule @grantParameters -Confirm:$false -PassThru
```

Use `Confirm:$false` only when the preview has been reviewed or when established
automation provides equivalent controls. See
[Safety, preview, and privileges](usage/safety-and-privileges.md) for the
confirmation model, the privileges Windows requires, and local impersonation.

## What the module does not do

Knowing the boundaries early saves a wasted afternoon:

- It has no remote target parameters. Run it inside a remoting session on the
  computer that owns the object. Active Directory is the exception: its
  commands bind LDAP to a domain controller directly.
- It does not manage registry value permissions, because a value has no
  independent security descriptor.
- It does not compute Active Directory effective access, because only a domain
  controller can answer that question authoritatively.
- It does not export private key material.
- It does not author Group Policy, Central Access Policy, or Windows audit
  policy. A SACL decides what is eligible for auditing; audit policy decides
  whether events are written.

## Resolve common failures

| Symptom | Check |
| --- | --- |
| A SACL operation reports access denied | Confirm `SeSecurityPrivilege` is present in the process token; the module cannot add a privilege that the token does not contain. |
| An audit rule produces no events | Enable the applicable Windows object access audit policy as well as the SACL rule. |
| An inherited ACE cannot be removed | Change the source ancestor or disable inheritance on the child. |
| A service target is not found | Supply the service name, not the display name. |
| A registry value appears to have no ACL | Manage the containing registry key; values have no independent security descriptor. |
| A process operation reports an identity mismatch | Reacquire the live process and its descriptor; the original pinned instance exited or changed. |
| A batch runs one target at a time | Pass one target array rather than individual streaming pipeline records. |
| The DSC LCM cannot find the resource | Install the module in a machine-wide module path visible to the SYSTEM process. |
| A remote target is rejected | Enter a remote session and run the command locally on the destination computer. |

[Troubleshooting](usage/troubleshooting.md) covers these and the family-specific
refusals in more detail.

## See also

- [Documentation index](README.md)
- [Project overview and command catalog](../README.md)
- [Migration from NTFSPermission](migration-from-ntfspermission.md)
- [Public API contract](../specs/0003-public-api.md)
- [Security and persistence contract](../specs/0004-security-and-persistence.md)
- [Design research](research.md)
