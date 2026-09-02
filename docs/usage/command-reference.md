# Command reference

Every public command grouped by object family, with the page that explains it.
Use `Get-Help <command> -Full` for parameters and examples, or the
[project wiki](https://github.com/raandree/WindowsAccessControl/wiki), which is
regenerated from the module on each release.

List what your installed version actually exports:

```powershell
Get-Command -Module WindowsAccessControl
Get-DscResource -Module WindowsAccessControl
```

## Naming pattern

| Verb | Means |
| --- | --- |
| `Get` | Reads. Never changes state |
| `New` | Builds an in-memory rule. Changes nothing on disk |
| `Add` | Accumulates. Leaves unrelated rules alone |
| `Set` | Replaces the rules for the same account and qualifier, or writes an exact descriptor |
| `Remove` | Deletes matching rules, with a removal mode where the family supports one |
| `Clear` | Deletes every explicit rule of that kind |
| `Enable` / `Disable` | Changes inheritance or a privilege |
| `Backup` / `Restore` | Reads to or writes from a portable envelope |
| `Copy` | Applies one item's selected sections to others |
| `Test` | Reports a condition without changing state |
| `Edit` | Reads, runs a callback, and writes inside one lock |
| `Invoke` | Runs a script block in an explicit context |
| `Resolve` | Normalizes an identity |

## File system

See [File system](file-system.md).

| Area | Commands |
| --- | --- |
| Access rules | `New-NTFSAccessRule`, `Get-NTFSAccessRule`, `Add-NTFSAccessRule`, `Set-NTFSAccessRule`, `Remove-NTFSAccessRule`, `Clear-NTFSAccessRule` |
| Audit rules | `New-NTFSAuditRule`, `Get-NTFSAuditRule`, `Add-NTFSAuditRule`, `Set-NTFSAuditRule`, `Remove-NTFSAuditRule`, `Clear-NTFSAuditRule` |
| Owner | `Get-NTFSItemOwner`, `Set-NTFSItemOwner` |
| Inheritance | `Get-NTFSItemInheritance`, `Enable-NTFSItemInheritance`, `Disable-NTFSItemInheritance` |
| Descriptors | `Get-NTFSItemSecurityDescriptor`, `Edit-NTFSItemSecurityDescriptor`, `Set-NTFSItemSecurityDescriptor`, `Copy-NTFSItemSecurityDescriptor` |
| Portability | `Backup-NTFSItemSecurityDescriptor`, `Restore-NTFSItemSecurityDescriptor` |
| Diagnostics | `Get-NTFSItemEffectiveAccess`, `Test-NTFSItemAcl` |

## Registry keys

See [Registry keys](registry.md).

| Area | Commands |
| --- | --- |
| Descriptors | `Get-RegistryKeySecurityDescriptor`, `Edit-RegistryKeySecurityDescriptor`, `Set-RegistryKeySecurityDescriptor` |
| Access rules | `Get-RegistryKeyAccessRule`, `Add-RegistryKeyAccessRule`, `Set-RegistryKeyAccessRule`, `Remove-RegistryKeyAccessRule`, `Clear-RegistryKeyAccessRule` |
| Audit rules | `Get-RegistryKeyAuditRule`, `Add-RegistryKeyAuditRule`, `Set-RegistryKeyAuditRule`, `Remove-RegistryKeyAuditRule`, `Clear-RegistryKeyAuditRule` |
| Inheritance | `Get-RegistryKeyInheritance`, `Enable-RegistryKeyInheritance`, `Disable-RegistryKeyInheritance` |

## Services and the SCM

See [Services and the SCM](services.md). The same commands reach the Service
Control Manager through the `ServiceControlManager` switch.

| Area | Commands |
| --- | --- |
| Descriptors | `Get-ServiceSecurityDescriptor`, `Set-ServiceSecurityDescriptor` |
| Access rules | `Get-ServiceAccessRule`, `Add-ServiceAccessRule`, `Set-ServiceAccessRule`, `Remove-ServiceAccessRule`, `Clear-ServiceAccessRule` |
| Audit rules | `Get-ServiceAuditRule`, `Add-ServiceAuditRule`, `Set-ServiceAuditRule`, `Remove-ServiceAuditRule`, `Clear-ServiceAuditRule` |

## Live processes

See [Live processes](processes.md).

| Area | Commands |
| --- | --- |
| Descriptors | `Get-ProcessSecurityDescriptor`, `Set-ProcessSecurityDescriptor` |
| Access rules | `Get-ProcessAccessRule`, `Add-ProcessAccessRule`, `Set-ProcessAccessRule`, `Remove-ProcessAccessRule`, `Clear-ProcessAccessRule` |
| Audit rules | `Get-ProcessAuditRule`, `Add-ProcessAuditRule`, `Set-ProcessAuditRule`, `Remove-ProcessAuditRule`, `Clear-ProcessAuditRule` |

## SMB shares

See [SMB shares](smb-shares.md).

| Area | Commands |
| --- | --- |
| Descriptors | `Get-SmbShareSecurityDescriptor`, `Set-SmbShareSecurityDescriptor` |
| Access rules | `Get-SmbShareAccessRule`, `Add-SmbShareAccessRule`, `Remove-SmbShareAccessRule` |
| Effective access | `Get-SmbShareEffectiveAccess` |

## Active Directory objects

See [Active Directory objects](active-directory.md).

| Area | Commands |
| --- | --- |
| Descriptors | `Get-ADObjectSecurityDescriptor`, `Set-ADObjectSecurityDescriptor` |
| Access rules | `Get-ADObjectAccessRule`, `Add-ADObjectAccessRule`, `Set-ADObjectAccessRule`, `Remove-ADObjectAccessRule`, `Clear-ADObjectAccessRule` |
| Schema baseline | `Get-ADObjectSchemaDefaultAccessRule` |
| Caller-scoped access | `Get-ADObjectCallerEffectiveAccess` |

## Task Scheduler

See [Task Scheduler](task-scheduler.md).

| Area | Commands |
| --- | --- |
| Folder descriptors | `Get-TaskFolderSecurityDescriptor`, `Set-TaskFolderSecurityDescriptor` |
| Folder access rules | `Get-TaskFolderAccessRule`, `Add-TaskFolderAccessRule`, `Remove-TaskFolderAccessRule` |
| Task descriptors | `Get-ScheduledTaskSecurityDescriptor`, `Set-ScheduledTaskSecurityDescriptor` |
| Task access rules | `Get-ScheduledTaskAccessRule`, `Add-ScheduledTaskAccessRule`, `Remove-ScheduledTaskAccessRule` |

## Certificate private keys

See [Certificate private keys](certificate-private-keys.md).

| Area | Commands |
| --- | --- |
| Descriptors | `Get-CertificatePrivateKeySecurityDescriptor`, `Set-CertificatePrivateKeySecurityDescriptor` |
| Access rules | `Get-CertificatePrivateKeyAccessRule`, `Add-CertificatePrivateKeyAccessRule`, `Remove-CertificatePrivateKeyAccessRule` |
| Diagnostics | `Test-CertificatePrivateKeyCriticalBinding` |

## Cross-cutting

| Area | Commands | Page |
| --- | --- | --- |
| Unified portability | `Backup-WindowsSecurityDescriptor`, `Restore-WindowsSecurityDescriptor` | [Backup, restore, and copy](backup-and-restore.md) |
| Identity | `Resolve-WindowsIdentity` | [Diagnostics](diagnostics.md) |
| Privileges | `Get-WindowsPrivilege`, `Test-WindowsPrivilege`, `Enable-WindowsPrivilege`, `Disable-WindowsPrivilege` | [Safety, preview, and privileges](safety-and-privileges.md) |
| Local impersonation | `Invoke-WindowsAccessControl` | [Safety, preview, and privileges](safety-and-privileges.md) |
| Metrics | `Get-WindowsAccessControlMetric` | [Diagnostics](diagnostics.md) |

## What each family supports

| Family | Access rules | Audit rules | Inheritance | Owner and group | Portability | DSC |
| --- | :---: | :---: | :---: | :---: | :---: | :---: |
| File system | Yes | Yes | Yes | Yes | Yes | Yes |
| Registry keys | Yes | Yes | Yes | Yes | Yes | Yes |
| Services and the SCM | Yes | Yes | No | Yes | Yes | Yes |
| Live processes | Yes | Yes | No | Yes | Yes | Yes |
| SMB shares | Yes | No | No | No | Yes | Yes |
| Active Directory objects | Yes | No | Yes | No | Yes | Yes |
| Task Scheduler | Yes | No | Yes | No | Yes | Yes |
| Certificate private keys | Yes | No | No | No | Yes | Yes |

Inheritance for Active Directory and Task Scheduler means that inherited rules
are read and scoped through `InheritanceType` or `AppliesTo`; those families
expose no `Enable`/`Disable` inheritance commands.

## DSC resources

| Exact descriptor | Access rule |
| --- | --- |
| `WindowsAccessControlNtfsSecurityDescriptor` | `WindowsAccessControlNtfsAccessRule` |
| `WindowsAccessControlRegistryKeySecurityDescriptor` | `WindowsAccessControlRegistryKeyAccessRule` |
| `WindowsAccessControlServiceSecurityDescriptor` | `WindowsAccessControlServiceAccessRule` |
| `WindowsAccessControlServiceControlManagerSecurityDescriptor` | `WindowsAccessControlServiceControlManagerAccessRule` |
| `WindowsAccessControlProcessSecurityDescriptor` | `WindowsAccessControlProcessAccessRule` |
| `WindowsAccessControlSmbShareSecurityDescriptor` | `WindowsAccessControlSmbShareAccessRule` |
| `WindowsAccessControlADObjectSecurityDescriptor` | `WindowsAccessControlADObjectAccessRule` |
| `WindowsAccessControlTaskFolderSecurityDescriptor` | `WindowsAccessControlTaskFolderAccessRule` |
| `WindowsAccessControlScheduledTaskSecurityDescriptor` | `WindowsAccessControlScheduledTaskAccessRule` |
| `WindowsAccessControlCertificatePrivateKeySecurityDescriptor` | `WindowsAccessControlCertificatePrivateKeyAccessRule` |

See [Desired State Configuration](dsc.md).

## Rights enumerations

| Enumeration | Used by |
| --- | --- |
| `System.Security.AccessControl.FileSystemRights` | File system |
| `System.Security.AccessControl.RegistryRights` | Registry keys |
| `WindowsServiceRights` | Named services |
| `WindowsServiceControlManagerRights` | The Service Control Manager |
| `WindowsProcessRights` | Live processes |
| `WindowsSmbShareRights` | SMB shares |
| `WindowsActiveDirectoryRights` | Active Directory objects |
| `WindowsTaskFolderRights` | Task folders |
| `WindowsScheduledTaskRights` | Registered tasks |
| `WindowsCryptoKeyRights` | Certificate private keys |

List the members of any of them:

```powershell
[System.Enum]::GetNames([WindowsProcessRights])
```

## See also

- [Usage guide overview](../usage-guide.md)
- [Public API contract](../../specs/0003-public-api.md)
- [Migration from NTFSPermission](../migration-from-ntfspermission.md)
