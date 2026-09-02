# Auditing and SACLs

A system access control list decides which operations on an object are
*eligible* for auditing. Windows audit policy decides whether events are
actually written. Both have to be right before an event appears in the security
log.

Audit rules exist for the file system, registry keys, services and the SCM, and
live processes. SMB shares, Active Directory objects, Task Scheduler objects,
and certificate private keys expose no audit rules in this module.

## Check the privilege first

Every SACL read and write requires `SeSecurityPrivilege`:

```powershell
Get-WindowsPrivilege
Test-WindowsPrivilege -Name SeSecurityPrivilege
```

The module temporarily enables the privilege when it is present in the process
token and restores its original state afterwards. It cannot add a privilege the
token does not contain, so run the operation from a process whose token holds
it. See
[Safety, preview, and privileges](safety-and-privileges.md#privileges).

## Configure a file system audit rule

Audit failed writes by Everyone on a directory and its children:

```powershell
Add-NTFSAuditRule -LiteralPath 'C:\Data' `
    -Account 'S-1-1-0' `
    -AccessRights Write `
    -AuditFlags Failure `
    -AppliesTo ThisFolderSubfoldersAndFiles `
    -WhatIf
```

Inspect and remove exactly what is there:

```powershell
Get-NTFSAuditRule -LiteralPath 'C:\Data' -ExcludeInherited

Get-NTFSAuditRule -LiteralPath 'C:\Data' -Account 'S-1-1-0' -ExcludeInherited |
    Remove-NTFSAuditRule -WhatIf
```

`Clear-NTFSAuditRule` removes every explicit audit rule from the selected
items.

## Audit flags

| Value | Records |
| --- | --- |
| `Success` | Successful attempts |
| `Failure` | Denied attempts |
| `Success, Failure` | Both |

`Failure` is the higher-signal choice for detecting a misconfiguration or an
unauthorized attempt. `Success` on a busy path can produce a very large volume
of events.

## Other families

The audit commands follow the same shape everywhere:

```powershell
Add-RegistryKeyAuditRule -Path 'HKLM:\Software\Contoso' `
    -Account 'S-1-1-0' `
    -AccessRights SetValue `
    -AuditFlags Failure `
    -WhatIf

Add-ServiceAuditRule -Name BITS `
    -Account 'S-1-1-0' `
    -ServiceRights ChangeConfig `
    -AuditFlags Failure `
    -WhatIf

Add-ProcessAuditRule -InputObject $PID `
    -Account 'S-1-1-0' `
    -ProcessRights Terminate `
    -AuditFlags Success `
    -WhatIf
```

Each family uses its own rights parameter: `AccessRights` for the file system
and registry, `ServiceRights` or `ControlManagerRights` for services and the
SCM, and `ProcessRights` for processes.

## Audit inheritance

The file system and registry families expose the audit section separately from
the access section, so audit inheritance can be changed on its own:

```powershell
Get-NTFSItemInheritance -LiteralPath 'C:\Data' -Section Audit

Disable-NTFSItemInheritance -LiteralPath 'C:\Data' `
    -Section Audit `
    -WhatIf

Disable-RegistryKeyInheritance -Path 'HKLM:\Software\Contoso' `
    -Section Audit `
    -PreserveInherited $true
```

Services, the SCM, and processes have no inheritance at all.

## Turn on audit policy

A SACL alone produces nothing. The matching Windows object access audit policy
subcategory has to be enabled as well, which this module does not manage:

```powershell
auditpol.exe /get /category:"Object Access"
```

Enable the applicable subcategory through Group Policy or `auditpol.exe`, then
verify that events appear in the security log.

## No events after configuring a SACL

Work through this in order:

1. Confirm the audit rule is present and explicit:
   `Get-NTFSAuditRule -LiteralPath $path -ExcludeInherited`.
2. Confirm the audit flag matches what you expect to see: a denied attempt
   produces nothing when only `Success` is audited.
3. Confirm the object access audit policy subcategory is enabled.
4. Confirm the operation actually reached the object. Access denied by a share
   permission never reaches the file system SACL.

## Portability

A selected absent SACL is encoded explicitly in a backup as
`S:NO_ACCESS_CONTROL`, which is different from an empty protected SACL (`S:P`).
The first can inherit audit rules later; the second cannot. Use the second when
audit inheritance must remain empty. See
[Backup, restore, and copy](backup-and-restore.md).

## Commands on this page

| Family | Commands |
| --- | --- |
| File system | `New-NTFSAuditRule`, `Get-NTFSAuditRule`, `Add-NTFSAuditRule`, `Set-NTFSAuditRule`, `Remove-NTFSAuditRule`, `Clear-NTFSAuditRule` |
| Registry | `Get-RegistryKeyAuditRule`, `Add-RegistryKeyAuditRule`, `Set-RegistryKeyAuditRule`, `Remove-RegistryKeyAuditRule`, `Clear-RegistryKeyAuditRule` |
| Service and SCM | `Get-ServiceAuditRule`, `Add-ServiceAuditRule`, `Set-ServiceAuditRule`, `Remove-ServiceAuditRule`, `Clear-ServiceAuditRule` |
| Process | `Get-ProcessAuditRule`, `Add-ProcessAuditRule`, `Set-ProcessAuditRule`, `Remove-ProcessAuditRule`, `Clear-ProcessAuditRule` |
| Privileges | `Get-WindowsPrivilege`, `Test-WindowsPrivilege`, `Enable-WindowsPrivilege`, `Disable-WindowsPrivilege` |

## See also

- [Safety, preview, and privileges](safety-and-privileges.md)
- [File system](file-system.md)
- [Troubleshooting](troubleshooting.md)
