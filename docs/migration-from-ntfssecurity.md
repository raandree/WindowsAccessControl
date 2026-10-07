# Migrate from NTFSSecurity

This guide is for administrators and script authors who manage NTFS
permissions with the [NTFSSecurity](https://github.com/raandree/NTFSSecurity)
module. It maps every NTFSSecurity command to its `WindowsAccessControl`
replacement, explains the parameter and output differences that change what a
script does, and names the NTFSSecurity features that have no equivalent here,
with the decision behind each.

## Status of NTFSSecurity

`WindowsAccessControl` is the successor of `NTFSSecurity`. NTFSSecurity is
deprecated and will be archived: the PowerShell Gallery description of its
5.0.0 prerelease reads "NTFSSecurity will be archived; its successor is
WindowsAccessControl", and its change log deprecates the module as a whole.
Plan new automation on `WindowsAccessControl`, and move existing scripts over.

The successor is not a drop-in replacement. It keeps what worked in
NTFSSecurity, such as pipeline input, account filters, orphaned-SID reports,
and in-memory descriptor editing, but every command has a new name, some
defaults differ, and the general file system commands are gone.

## Before you start

- The command map applies to `WindowsAccessControl` 0.2.0 and later. Install
  the module as [Getting started](usage/getting-started.md) describes.
- No command name exists in both modules. Move one script at a time, and run
  each changed command with `WhatIf` before you remove NTFSSecurity.
- `WindowsAccessControl` runs on Windows PowerShell 5.1 and PowerShell 7. A
  path longer than 260 characters needs PowerShell 7; see
  [Long paths](#long-paths).
- The examples use placeholder accounts and paths such as `CONTOSO\Analysts`
  and `C:\Data`. Replace them with targets from your environment.

## Command map

The tables cover every command that the NTFSSecurity 4.2.6 and 5.0.0-rc4
manifests on the PowerShell Gallery export, checked on 2026-10-06. The notes
name the changes that need attention, and
[Parameter differences](#parameter-differences) explains them.

### Access rules

| NTFSSecurity | WindowsAccessControl | Notes |
| --- | --- | --- |
| `Get-NTFSAccess` | `Get-NTFSAccessRule` | `Account` accepts several accounts |
| `Add-NTFSAccess` | `Add-NTFSAccessRule` | `AccessType` is now `AccessControlType` |
| `Remove-NTFSAccess` | `Remove-NTFSAccessRule` | The default differs; see [Removal defaults differ](#removal-defaults-differ) |
| `Clear-NTFSAccess` | `Clear-NTFSAccessRule` | `DisableInheritance` is a separate command |
| `Get-NTFSOrphanedAccess` | `Get-NTFSAccessRule -Orphaned` | |
| `Get-NTFSEffectiveAccess` | `Get-NTFSItemEffectiveAccess` | Local paths only; no `ServerName` |
| `Get-NTFSSimpleAccess` | None | See [Features without an equivalent](#features-without-an-equivalent) |
| `Show-NTFSSimpleAccess` | None | Listed in the 4.2.6 manifest only; the command no longer existed |

### Audit rules

The audit commands that read or write a SACL need `SeSecurityPrivilege`. They
enable it for the duration of the operation when the process token holds it.
See [Auditing and SACLs](usage/auditing.md).

| NTFSSecurity | WindowsAccessControl | Notes |
| --- | --- | --- |
| `Get-NTFSAudit` | `Get-NTFSAuditRule` | `Account` accepts several accounts |
| `Add-NTFSAudit` | `Add-NTFSAuditRule` | |
| `Remove-NTFSAudit` | `Remove-NTFSAuditRule` | The default differs; see [Removal defaults differ](#removal-defaults-differ) |
| `Clear-NTFSAudit` | `Clear-NTFSAuditRule` | `DisableInheritance` is a separate command |
| `Get-NTFSOrphanedAudit` | `Get-NTFSAuditRule -Orphaned` | |

### Inheritance

| NTFSSecurity | WindowsAccessControl | Notes |
| --- | --- | --- |
| `Get-NTFSInheritance` | `Get-NTFSItemInheritance -Section All` | The default section is `Access` |
| `Enable-NTFSAccessInheritance` | `Enable-NTFSItemInheritance` | `RemoveExplicitAccessRules` is now `RemoveExplicitRules` |
| `Disable-NTFSAccessInheritance` | `Disable-NTFSItemInheritance` | `RemoveInheritedAccessRules` is now `PreserveInherited:$false` |
| `Enable-NTFSAuditInheritance` | `Enable-NTFSItemInheritance -Section Audit` | `RemoveExplicitAuditRules` is now `RemoveExplicitRules` |
| `Disable-NTFSAuditInheritance` | `Disable-NTFSItemInheritance -Section Audit` | `RemoveInheritedAuditRules` is now `PreserveInherited:$false` |
| `Set-NTFSInheritance` | `Enable-NTFSItemInheritance`, `Disable-NTFSItemInheritance` | One command for each direction |

Before NTFSSecurity 5.0.0, `Set-NTFSInheritance` removed the inherited entries
when it disabled access inheritance. `Disable-NTFSItemInheritance` keeps them
as explicit rules unless you pass `-PreserveInherited:$false`.

### Owner and security descriptor

| NTFSSecurity | WindowsAccessControl | Notes |
| --- | --- | --- |
| `Get-NTFSOwner` | `Get-NTFSItemOwner` | |
| `Set-NTFSOwner` | `Set-NTFSItemOwner` | Prompts for confirmation by default |
| `Get-NTFSSecurityDescriptor` | `Get-NTFSItemSecurityDescriptor` | `Sections` selects what is read and later written |
| `Set-NTFSSecurityDescriptor` | `Set-NTFSItemSecurityDescriptor` | Takes the descriptor from the pipeline |

### Privileges

| NTFSSecurity | WindowsAccessControl | Notes |
| --- | --- | --- |
| `Get-Privileges` | `Get-WindowsPrivilege` | |
| `Enable-Privileges` | `Enable-WindowsPrivilege` | Names each privilege; rarely needed, because commands enable what they use |
| `Disable-Privileges` | `Disable-WindowsPrivilege` | Names each privilege |

### File system commands

| NTFSSecurity | WindowsAccessControl | Use instead |
| --- | --- | --- |
| `Get-ChildItem2`, `Get-Item2`, `Test-Path2` | None | `Get-ChildItem`, `Get-Item`, `Test-Path` |
| `Copy-Item2`, `Move-Item2`, `Remove-Item2` | None | `Copy-Item`, `Move-Item`, `Remove-Item` |
| `New-NTFSHardLink`, `New-NTFSSymbolicLink` | None | `New-Item -ItemType HardLink` or `-ItemType SymbolicLink` |
| `Get-NTFSHardLink` | None | `fsutil hardlink list` |
| `Get-FileHash2` | None | `Get-FileHash` |
| `Get-DiskSpace` | None | `Get-Volume` |

### Commands without an NTFSSecurity predecessor

- `Set-NTFSAccessRule` replaces the rules of one account and one allow or deny
  type, and leaves other accounts alone. `Set-NTFSAuditRule` is its audit
  counterpart.
- `New-NTFSAccessRule` and `New-NTFSAuditRule` build a rule in memory without
  applying it.
- `Edit-NTFSItemSecurityDescriptor` reads, edits, and writes a descriptor
  inside one lock.
- `Copy-NTFSItemSecurityDescriptor`, `Backup-NTFSItemSecurityDescriptor`, and
  `Restore-NTFSItemSecurityDescriptor` copy, back up, and restore selected
  descriptor sections.
- `Test-NTFSItemAcl` reports access control entries that are out of canonical
  order.
- `Resolve-WindowsIdentity` returns the account name and the SID of an
  identity.

Beyond the file system, the module manages registry keys, services, live
processes, SMB shares, Active Directory objects, Task Scheduler, and
certificate private keys. The [command reference](usage/command-reference.md)
lists every command.

## Parameter differences

### Removal defaults differ

`Remove-NTFSAccess` and `Remove-NTFSAudit` take the named rights away from a
matching entry and delete the entry only when no right is left. With
`-RemoveSpecific`, they remove only an entry that matches exactly.
`Remove-NTFSAccessRule` and `Remove-NTFSAuditRule` select the behavior with
`RemovalMode`, and the default is the exact match:

| NTFSSecurity | WindowsAccessControl |
| --- | --- |
| Default behavior | `-RemovalMode Rights` |
| `-RemoveSpecific` | `-RemovalMode Exact`, the default |
| `Get-NTFSAccess` piped to `Remove-NTFSAccess` | `Get-NTFSAccessRule` piped to `Remove-NTFSAccessRule`, or `-RemovalMode All` for every explicit rule of one account |

A migrated call that names other rights than the entry holds, such as one
right of a larger entry, does not fail without `-RemovalMode Rights`. The exact
match finds no identical entry, and nothing is removed. Add
`-RemovalMode Rights` wherever a call takes rights away.

### Confirmation and preview

The NTFSSecurity permission cmdlets do not support `WhatIf` or `Confirm`.
Every mutating command here supports both, and the commands with a high impact
prompt before they act: `Remove-NTFSAccessRule`, `Remove-NTFSAuditRule`,
`Clear-NTFSAccessRule`, `Clear-NTFSAuditRule`, `Set-NTFSItemOwner`,
`Copy-NTFSItemSecurityDescriptor`, `Restore-NTFSItemSecurityDescriptor`,
`Enable-WindowsPrivilege`, and `Disable-WindowsPrivilege`.

A scheduled task or another non-interactive host cannot answer that prompt.
Preview the command with `-WhatIf`, then pass `-Confirm:$false` in the
unattended script. See
[The confirmation model](usage/safety-and-privileges.md#the-confirmation-model).

### Rights

- `AccessRights` keeps its name. The alias `FileSystemRights` does not exist
  here.
- Every right name except `None` and the four generic rights has the same
  value in both modules.
- Pass a generic right as a raw mask: `0x10000000` for `GenericAll`,
  `0x20000000` for `GenericExecute`, `0x40000000` for `GenericWrite`, and
  `0x80000000` for `GenericRead`. The `AccessRightsDisplay` property of a rule
  shows those names.
- An allow rule receives `Synchronize` in addition to the requested rights, as
  it did in NTFSSecurity.

### Scope with AppliesTo

The `InheritanceFlags` and `PropagationFlags` parameters do not exist here;
use `AppliesTo`. Its thirteen values are the same in both modules and set the
same flags:

| `AppliesTo` | `InheritanceFlags` | `PropagationFlags` |
| --- | --- | --- |
| `ThisFolderOnly` | `None` | `None` |
| `ThisFolderSubfoldersAndFiles` | `ContainerInherit, ObjectInherit` | `None` |
| `ThisFolderAndSubfolders` | `ContainerInherit` | `None` |
| `ThisFolderAndFiles` | `ObjectInherit` | `None` |
| `SubfoldersAndFilesOnly` | `ContainerInherit, ObjectInherit` | `InheritOnly` |
| `SubfoldersOnly` | `ContainerInherit` | `InheritOnly` |
| `FilesOnly` | `ObjectInherit` | `InheritOnly` |

Every value except `ThisFolderOnly` also exists with the suffix `OneLevel`,
which adds `NoPropagateInherit`. Without `AppliesTo`, a rule on a directory
applies to `ThisFolderSubfoldersAndFiles` and a rule on a file to
`ThisFolderOnly`, which matches what NTFSSecurity stored. Rule objects still
report `InheritanceFlags` and `PropagationFlags`.

### Accounts

- `Account` keeps its name. On the add commands it keeps the aliases
  `IdentityReference` and `ID`.
- Account names and SID strings are accepted. Each account is resolved to one
  SID before anything is written, and duplicates are removed
  ([ADR 0006](../specs/decisions/0006-prevalidate-and-deduplicate-identities.md)).
- The get and add commands accept several accounts; the set and remove
  commands accept one.
- `Get-NTFSItemEffectiveAccess` has no `NTAccount` alias for `Account`.

### Paths

- `Path` keeps its alias `FullName`. The new `LiteralPath` parameter, with
  the alias `PSPath`, takes a path exactly as written; the examples use it.
- The remove commands do not take piped files or folders. Pipe the rules from
  `Get-NTFSAccessRule` into them, or pass the paths to `-LiteralPath`.
- A path that starts with `\\?\` or `\\.\` is refused, and so is a bare drive
  such as `C:`; write `C:\`
  ([ADR 0029](../specs/decisions/0029-refuse-device-namespace-paths.md)).
- No command walks a folder tree. Pipe `Get-ChildItem -Recurse` into the
  command instead
  ([ADR 0031](../specs/decisions/0031-never-expand-a-supplied-target-set.md)).
- A UNC path works everywhere except in `Get-NTFSItemEffectiveAccess`.

### Long paths

NTFSSecurity reaches paths longer than 260 characters through the AlphaFS
library. `WindowsAccessControl` uses the in-box file system provider instead.
In PowerShell 7, such a path works without a prefix; in Windows PowerShell 5.1,
it cannot be reached
([ADR 0029](../specs/decisions/0029-refuse-device-namespace-paths.md)). Run
migrated scripts that touch long paths in PowerShell 7.

### Descriptor editing

- The access, audit, owner, and inheritance commands accept the result of
  `Get-NTFSItemSecurityDescriptor` from the pipeline. Each one returns the
  edited descriptor without writing, and `Set-NTFSItemSecurityDescriptor`
  writes it once. See
  [Descriptor editing and concurrency](usage/descriptor-editing.md).
- A descriptor can be edited only in the sections it was read with, which
  `Get-NTFSItemSecurityDescriptor -Sections` selects.
- `Get-NTFSAccessRule`, `Get-NTFSAuditRule`, `Get-NTFSItemOwner`,
  `Get-NTFSItemInheritance`, and `Get-NTFSItemEffectiveAccess` read from the
  path and have no `SecurityDescriptor` parameter. A descriptor object exposes
  its .NET security object as `NativeSecurity` and its SDDL as `Sddl`.
- `Clear-NTFSAccess -DisableInheritance` becomes two steps:
  `Disable-NTFSItemInheritance -PreserveInherited:$false` and
  `Clear-NTFSAccessRule`. Together they leave an empty DACL, which denies
  everyone access, so grant the access you need in the same write. The
  [rebuild example](#rebuild-a-folder-acl-in-one-write) chains all three.

### Other parameters

- `Get-NTFSItemEffectiveAccess` has no `ServerName` and no
  `ExcludeNoneAccessEntries`. Its `AccessRights` parameter tests the named
  rights and fills `IsAllowed`, so `Where-Object IsAllowed` keeps the items
  on which the account holds them.
- `Add-NTFSAccessRule -PassThru` returns the rule that was written, not every
  entry of the item. Call `Get-NTFSAccessRule` to list the whole DACL.
- Commands that take several targets accept `ThrottleLimit` and process up to
  that many targets in parallel.

## Output differences

| NTFSSecurity type | WindowsAccessControl type | Returned by |
| --- | --- | --- |
| `Security2.FileSystemAccessRule2` | `WindowsAccessControl.AccessRule` | `Get-NTFSAccessRule`, `New-NTFSAccessRule` |
| `Security2.FileSystemAuditRule2` | `WindowsAccessControl.AuditRule` | `Get-NTFSAuditRule`, `New-NTFSAuditRule` |
| `Security2.FileSystemAccessRule2` | `WindowsAccessControl.EffectiveAccess` | `Get-NTFSItemEffectiveAccess` |
| `Security2.FileSystemInheritanceInfo` | `WindowsAccessControl.Inheritance` | `Get-NTFSItemInheritance` |
| `Security2.FileSystemOwner` | `WindowsAccessControl.Owner` | `Get-NTFSItemOwner` |
| `Security2.FileSystemSecurity2` | `WindowsAccessControl.SecurityDescriptor` | `Get-NTFSItemSecurityDescriptor` |
| `ProcessPrivileges.PrivilegeAndAttributes` | `WindowsAccessControl.Privilege` | `Get-WindowsPrivilege` |

An access rule keeps `Account`, `AccessRights`, `AccessControlType`,
`InheritanceFlags`, `PropagationFlags`, `IsInherited`, and `InheritedFrom`.
The item path moves from `FullName` to `Path`. New properties are `SID`,
`AccessMask`, `AccessRightsDisplay`, `AppliesTo`, `IsOrphaned`, and
`NativeRule`, the underlying .NET rule. `AccountType`, which NTFSSecurity
read from Active Directory, has no counterpart.

The module has no settings in its manifest:

- `InheritedFrom` is always filled when Windows can name the source of an
  inherited rule, so `GetInheritedFrom` has no counterpart.
- Every rule carries `SID`, so `ShowAccountSid` becomes a column choice, such
  as `Format-Table Account, SID, AccessRightsDisplay`.
- Each operation enables the privilege it needs, so `EnablePrivileges` has no
  counterpart.

The module adds no members to file and folder objects. Instead of the `Owner`
and `IsInheritanceBlocked` properties and the `EnableInheritance()` and
`DisableInheritance()` methods, use `Get-NTFSItemOwner`,
`Get-NTFSItemInheritance`, `Enable-NTFSItemInheritance`, and
`Disable-NTFSItemInheritance`.

## Features without an equivalent

| NTFSSecurity feature | Decision | Use instead |
| --- | --- | --- |
| The `*-Item2` commands, `Test-Path2`, the link commands, `Get-FileHash2`, `Get-DiskSpace`, and the `LengthOnDisk` and `GetHash()` members | General file system commands are a [non-goal](../specs/0001-vision-and-scope.md#non-goals), and [ADR 0002](../specs/decisions/0002-use-only-in-box-runtime-security-apis.md) rejects the AlphaFS dependency | The in-box commands in [File system commands](#file-system-commands) |
| Paths longer than 260 characters in Windows PowerShell 5.1 | [ADR 0029](../specs/decisions/0029-refuse-device-namespace-paths.md) refuses the `\\?\` prefix that would reach them | PowerShell 7 |
| `Get-NTFSSimpleAccess`, which reduces rights to read, write, and delete | Deferred, because composite rights, deny rules, and inheritance scopes cannot always be reduced without changing their meaning ([research](research.md#detailed-ntfssecurity-comparison)) | `AccessRightsDisplay` of `Get-NTFSAccessRule`, or `Get-NTFSItemEffectiveAccess` |
| Effective access evaluated by another computer, through `ServerName` or a UNC path | [ADR 0017](../specs/decisions/0017-defer-remote-and-combined-effective-access.md) keeps the evaluation local | `Get-NTFSItemEffectiveAccess` on the computer that stores the files |
| All four file system privileges enabled for every command, whether or not it needs them | [ADR 0008](../specs/decisions/0008-use-scoped-automatic-privilege-enablement.md) enables only the privilege an operation needs, restores it afterward, and reports an error when the token does not hold it | Nothing; `Enable-WindowsPrivilege` remains for deliberate token changes |
| Taking ownership and retrying after an access-denied error | [ADR 0008](../specs/decisions/0008-use-scoped-automatic-privilege-enablement.md) rejects it, because it changes an unrelated security boundary | `Set-NTFSItemOwner`, as a deliberate step |
| Public wrapper classes such as `IdentityReference2` | [ADR 0012](../specs/decisions/0012-use-object-specific-commands-and-dsc-resources.md) rejects public wrapper classes | Account names, SID strings, and `Resolve-WindowsIdentity` |

## Side-by-side examples

Each example shows the NTFSSecurity command first and the
`WindowsAccessControl` command after it.

### Grant access and deny one right

```powershell
Add-NTFSAccess -Path C:\Data -Account 'CONTOSO\Analysts' -AccessRights Read
Add-NTFSAccess -Path C:\Data -Account 'CONTOSO\Domain Users' `
    -AccessRights CreateFiles -AccessType Deny -AppliesTo ThisFolderOnly
```

```powershell
Add-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Analysts' `
    -AccessRights Read `
    -WhatIf

Add-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Domain Users' `
    -AccessRights CreateFiles `
    -AccessControlType Deny `
    -AppliesTo ThisFolderOnly `
    -WhatIf
```

### Take one right away from an entry

```powershell
Remove-NTFSAccess -Path C:\Data -Account 'CONTOSO\Domain Users' `
    -AccessRights DeleteSubdirectoriesAndFiles `
    -AppliesTo ThisFolderSubfoldersAndFiles
```

```powershell
Remove-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Domain Users' `
    -AccessRights DeleteSubdirectoriesAndFiles `
    -AppliesTo ThisFolderSubfoldersAndFiles `
    -RemovalMode Rights `
    -WhatIf
```

Without `-RemovalMode Rights`, the command looks for an identical entry, finds
none, and changes nothing.

### Report the explicit permissions of a folder tree

```powershell
Get-ChildItem2 -Path C:\Data -Recurse | Get-NTFSAccess -ExcludeInherited
```

```powershell
Get-ChildItem -LiteralPath 'C:\Data' -Recurse |
    Get-NTFSAccessRule -ExcludeInherited |
    Format-Table Path, Account, AccessRightsDisplay, AccessControlType, AppliesTo
```

### Back up and restore permissions

NTFSSecurity restores exported entries by piping them back to
`Add-NTFSAccess`:

```powershell
Get-ChildItem -Path C:\Data -Recurse | Get-NTFSAccess -ExcludeInherited |
    Export-Csv -Path C:\Backup\acl.csv -NoTypeInformation
Import-Csv -Path C:\Backup\acl.csv | Add-NTFSAccess
```

`WindowsAccessControl` writes a JSON backup with a SHA-256 digest for each
item, validates every record before the first write, and restores the recorded
DACL as it was rather than adding entries:

```powershell
Get-ChildItem -LiteralPath 'C:\Data' -Recurse |
    Backup-NTFSItemSecurityDescriptor `
        -DestinationPath 'C:\Backup\permissions.json' `
        -Sections Access

Restore-NTFSItemSecurityDescriptor `
    -BackupPath 'C:\Backup\permissions.json' `
    -WhatIf
```

See [Backup, restore, and copy](usage/backup-and-restore.md) for signing and
the restore boundaries.

### Rebuild a folder ACL in one write

```powershell
$sd = Get-NTFSSecurityDescriptor -Path C:\Data
Clear-NTFSAccess -SecurityDescriptor $sd -DisableInheritance
Add-NTFSAccess -SecurityDescriptor $sd -Account 'BUILTIN\Administrators' `
    -AccessRights FullControl -AppliesTo ThisFolderSubfoldersAndFiles
Set-NTFSSecurityDescriptor -SecurityDescriptor $sd
```

```powershell
Get-NTFSItemSecurityDescriptor -LiteralPath 'C:\Data' -Sections Access |
    Disable-NTFSItemInheritance -Section Access -PreserveInherited:$false |
    Clear-NTFSAccessRule |
    Add-NTFSAccessRule -Account 'BUILTIN\Administrators' `
        -AccessRights FullControl `
        -AppliesTo ThisFolderSubfoldersAndFiles |
    Set-NTFSItemSecurityDescriptor -WhatIf
```

Nothing is written until `Set-NTFSItemSecurityDescriptor`, which writes only
the access section. The result is a protected DACL with a single rule, so
preview it with `-WhatIf` before you run it.

## See also

- [Command reference](usage/command-reference.md)
- [File system](usage/file-system.md)
- [Safety, preview, and privileges](usage/safety-and-privileges.md)
- [Detailed NTFSSecurity comparison](research.md#detailed-ntfssecurity-comparison)
- [NTFSSecurity documentation](https://github.com/raandree/NTFSSecurity/tree/master/Docs)
