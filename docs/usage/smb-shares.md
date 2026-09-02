# SMB shares

An SMB share DACL and the NTFS DACL of the directory behind it are two separate
authorization layers. Windows evaluates both, and the more restrictive one
wins. This family manages the share layer only.

Run these commands on the computer that owns the share. They accept unqualified
local share names only.

## Inspect a share

```powershell
Get-SmbShareSecurityDescriptor -Name 'Data$'
Get-SmbShareAccessRule -Name 'Data$'
```

## Change share access

```powershell
Add-SmbShareAccessRule -Name 'Data$' `
    -Account 'CONTOSO\Analysts' `
    -AccessRights Change `
    -WhatIf
```

Remove one exact rule by piping the result of the matching `Get` command:

```powershell
Get-SmbShareAccessRule -Name 'Data$' -Account 'CONTOSO\Analysts' |
    Remove-SmbShareAccessRule -WhatIf
```

Write a complete desired share DACL when a rule command is too granular:

```powershell
$descriptor = Get-SmbShareSecurityDescriptor -Name 'Data$'

Set-SmbShareSecurityDescriptor -Name 'Data$' `
    -Sddl $descriptor.Sddl `
    -WhatIf
```

Share DACL writes preserve the share description.

## Share rights

`WindowsSmbShareRights` mirrors the three permission levels the Windows sharing
dialog offers, plus the underlying standard rights:

| Right | Equivalent |
| --- | --- |
| `Read` | Read in the sharing dialog |
| `Change` | Change in the sharing dialog |
| `Full` | Full Control in the sharing dialog |
| `ReadControl`, `WriteDac`, `WriteOwner`, `Delete` | Standard descriptor rights |
| `GenericRead`, `GenericWrite`, `GenericExecute`, `GenericAll` | Generic rights |

## Share types that are rejected

The family refuses share types where changing the DACL would break a system
function or where a cluster owns the authoritative state:

- Administrative shares
- Drive shares
- IPC shares
- Print shares
- Clustered shares
- Continuously available shares

## Share-only effective access

`Get-SmbShareEffectiveAccess` evaluates the local share DACL against an Authz
context derived from the account's SID:

```powershell
Get-SmbShareEffectiveAccess -Name 'Data$' `
    -Account 'CONTOSO\Analysts' `
    -AccessRights Read
```

Read the result's own labels before consuming it in automation:

| Property | Meaning |
| --- | --- |
| `AuthorizationContext` | Always `LocalSidDerived` for this command |
| `IncludesBackingNtfs` | Always `$false`; the backing NTFS DACL is not intersected |
| `EffectiveRights` | The share rights the DACL grants that SID |
| `IsAllowed` | Whether `AccessRights`, when supplied, is granted |

What it deliberately does not do:

- It does not intersect the backing NTFS DACL. A user allowed `Full` on the
  share can still be denied by the file system.
- It does not reproduce a remote network logon token, so it can omit
  logon-specific groups such as `NETWORK`.
- Authz reports an error rather than a partial result when the executing
  process cannot contact the account authority for the selected SID.

To reason about the end-to-end result, evaluate both layers and take the
narrower one:

```powershell
Get-SmbShareEffectiveAccess -Name 'Data$' -Account 'CONTOSO\Analysts'
Get-NTFSItemEffectiveAccess -LiteralPath 'D:\Shares\Data' -Account 'CONTOSO\Analysts'
```

## Portability

Share descriptors join the unified backup as record version 2 and bind the
owning server plus the immutable share name, so a record restores only on the
computer it names:

```powershell
Get-SmbShareSecurityDescriptor -Name 'Data$' |
    Backup-WindowsSecurityDescriptor -DestinationPath 'C:\Backup\share.json'
```

See [Backup, restore, and copy](backup-and-restore.md).

## Commands on this page

| Area | Commands |
| --- | --- |
| Descriptors | `Get-SmbShareSecurityDescriptor`, `Set-SmbShareSecurityDescriptor` |
| Access rules | `Get-SmbShareAccessRule`, `Add-SmbShareAccessRule`, `Remove-SmbShareAccessRule` |
| Effective access | `Get-SmbShareEffectiveAccess` |

This family exposes the access section only. It has no audit rules, no SACL, no
inheritance, and no `Set` or `Clear` rule command.

## See also

- [File system](file-system.md)
- [Diagnostics, batching, and metrics](diagnostics.md)
- [SMB share-only effective access contract](../../specs/0011-smb-share-only-effective-access.md)
