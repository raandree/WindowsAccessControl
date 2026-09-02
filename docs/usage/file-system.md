# File system

Files and directories are the largest command family in the module. Everything
on this page targets a local path; see
[Getting started](getting-started.md#targets-are-local).

## Inspect access

List every access rule on one directory:

```powershell
Get-NTFSAccessRule -LiteralPath 'C:\Data'
```

Focus on explicit rules for one account:

```powershell
Get-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Analysts' `
    -ExcludeInherited
```

Inspect a whole tree through the pipeline:

```powershell
Get-ChildItem -LiteralPath 'C:\Data' -Recurse |
    Get-NTFSAccessRule -ExcludeInherited
```

Useful filters:

| Parameter | Effect |
| --- | --- |
| `Account` | Returns rules for the named accounts or SIDs only |
| `ExcludeInherited` | Returns explicit rules only |
| `ExcludeExplicit` | Returns inherited rules only |
| `Orphaned` | Returns rules whose SID no longer translates to an account |

Treat `Orphaned` results carefully. A temporary domain connectivity failure
also prevents translation, so an unreachable domain controller can make a live
account look orphaned.

### Where an inherited rule comes from

Inherited results expose `InheritedFrom` when Windows can identify the original
ancestor:

```powershell
Get-NTFSAccessRule -LiteralPath 'C:\Data\Reports' -ExcludeExplicit |
    Format-Table Account, AccessRightsDisplay, InheritedFrom
```

The value is empty for an explicit rule and when Windows cannot resolve the
source. The module does not guess provenance by comparing parent ACLs.

## Grant or replace access

`Add-NTFSAccessRule` accumulates rights without replacing unrelated rules:

```powershell
Add-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Analysts' `
    -AccessRights ReadAndExecute `
    -AccessControlType Allow `
    -AppliesTo ThisFolderSubfoldersAndFiles `
    -WhatIf
```

Add the same rule for several accounts with one descriptor write per item:

```powershell
$accounts = 'CONTOSO\Analysts', 'CONTOSO\Auditors'

Add-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account $accounts `
    -AccessRights Read `
    -WhatIf
```

`Set-NTFSAccessRule` replaces the rules for the same SID and the same allow or
deny qualifier. It preserves the opposite qualifier and rules for other
accounts:

```powershell
Set-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Analysts' `
    -AccessRights Modify `
    -AccessControlType Allow `
    -AppliesTo ThisFolderSubfoldersAndFiles `
    -WhatIf
```

`AccessRights` also accepts a raw access mask as a decimal number or a
hexadecimal string, so bits the `FileSystemRights` enumeration cannot name,
such as the generic rights, remain reachable.

## Rule scope with AppliesTo

`AppliesTo` uses Windows Explorer's vocabulary rather than raw inheritance and
propagation flags:

| Value | Applies to |
| --- | --- |
| `ThisFolderOnly` | The current item only |
| `ThisFolderSubfoldersAndFiles` | Current directory and all children |
| `ThisFolderAndSubfolders` | Current directory and child directories |
| `ThisFolderAndFiles` | Current directory and child files |
| `SubfoldersAndFilesOnly` | Child directories and files only |
| `SubfoldersOnly` | Child directories only |
| `FilesOnly` | Child files only |
| `ThisFolderSubfoldersAndFilesOneLevel` | Current directory and one child level |
| `ThisFolderAndSubfoldersOneLevel` | Current directory and one directory level |
| `ThisFolderAndFilesOneLevel` | Current directory and one file level |
| `SubfoldersAndFilesOnlyOneLevel` | Immediate child directories and files only |
| `SubfoldersOnlyOneLevel` | Immediate child directories only |
| `FilesOnlyOneLevel` | Immediate child files only |

Files default to `ThisFolderOnly`. Directories default to
`ThisFolderSubfoldersAndFiles`.

## Build a rule without applying it

`New-NTFSAccessRule` and `New-NTFSAuditRule` create in-memory rules that change
nothing. Use them to inspect what a rule would look like, to export a standard
set of rules, or to keep a definition beside the code that applies it:

```powershell
$readOnFiles = New-NTFSAccessRule -Account 'CONTOSO\Analysts' `
    -AccessRights Read `
    -AppliesTo FilesOnly

$readOnFiles | Format-List
```

A rule built this way is not bound to a path, so it carries no target. Use
`Add-NTFSAccessRule` with the same values to apply it.

## Remove access

The safest removal starts from a path-bound rule returned by the matching `Get`
command, which removes that exact explicit ACE:

```powershell
Get-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Analysts' `
    -ExcludeInherited |
    Remove-NTFSAccessRule -WhatIf
```

Path-based removal exposes the distinction explicitly through `RemovalMode`:

| Mode | Effect |
| --- | --- |
| `Exact` (default) | Removes an identical ACE |
| `Rights` | Subtracts the selected rights from matching ACEs |
| `All` | Removes every explicit ACE for the selected SID |

Subtract only write rights:

```powershell
Remove-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Analysts' `
    -AccessRights Write `
    -RemovalMode Rights `
    -WhatIf
```

Preview a complete purge for one account:

```powershell
Remove-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Analysts' `
    -RemovalMode All `
    -WhatIf
```

`Clear-NTFSAccessRule` removes every explicit DACL rule from each selected
item. Inherited rules remain, but this is still a high-impact operation:

```powershell
Clear-NTFSAccessRule -LiteralPath 'C:\Data' -WhatIf
```

Inherited ACEs cannot be removed from a child. Change the rule on its source
ancestor, or change inheritance on the child.

## Change inheritance

Inspect access and audit inheritance state:

```powershell
Get-NTFSItemInheritance -LiteralPath 'C:\Data' -Section All
```

Disabling inheritance preserves inherited rules as explicit rules by default,
so the effective permissions do not change at the moment you disable it:

```powershell
Disable-NTFSItemInheritance -LiteralPath 'C:\Data' `
    -Section Access `
    -WhatIf
```

Discard inherited rules only when that destructive behavior is intended:

```powershell
Disable-NTFSItemInheritance -LiteralPath 'C:\Data' `
    -Section Access `
    -PreserveInherited:$false `
    -WhatIf
```

Re-enable inheritance while retaining explicit rules:

```powershell
Enable-NTFSItemInheritance -LiteralPath 'C:\Data' -Section Access -WhatIf
```

Add `RemoveExplicitRules` only when the inherited ACL should become the whole
selected ACL:

```powershell
Enable-NTFSItemInheritance -LiteralPath 'C:\Data' `
    -Section Access `
    -RemoveExplicitRules `
    -WhatIf
```

## Change an owner

Read both the account and SID forms of the current owner:

```powershell
Get-NTFSItemOwner -LiteralPath 'C:\Data'
```

Preview an owner change:

```powershell
Set-NTFSItemOwner -LiteralPath 'C:\Data' `
    -Account 'BUILTIN\Administrators' `
    -WhatIf
```

Setting an arbitrary owner can require `SeRestorePrivilege`, and taking
ownership can require `SeTakeOwnershipPrivilege`. See
[Safety, preview, and privileges](safety-and-privileges.md#privileges).

## Check effective access and ACL health

`Get-NTFSItemEffectiveAccess` answers what an account can actually do, taking
group membership, deny rules, and ACE order into account:

```powershell
Get-NTFSItemEffectiveAccess -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Alice' `
    -AccessRights Modify
```

`Test-NTFSItemAcl` reports canonical ACE ordering problems without changing the
descriptor:

```powershell
Test-NTFSItemAcl -LiteralPath 'C:\Data' -Section All -PassThru
```

Both are covered in detail in
[Diagnostics, batching, and metrics](diagnostics.md).

## Audit rules

The audit-rule commands mirror the access-rule commands and are documented
together with the other families in [Auditing and SACLs](auditing.md).

## Copy, back up, and restore

Copy only selected sections from a template directory:

```powershell
Get-ChildItem -LiteralPath 'C:\Target' |
    Copy-NTFSItemSecurityDescriptor `
        -SourceLiteralPath 'C:\Template' `
        -Sections Access `
        -WhatIf
```

Back up and restore one tree:

```powershell
Get-ChildItem -LiteralPath 'C:\Data' -Recurse |
    Backup-NTFSItemSecurityDescriptor `
        -DestinationPath 'C:\Backup\permissions.json' `
        -Sections Access

Restore-NTFSItemSecurityDescriptor `
    -BackupPath 'C:\Backup\permissions.json' `
    -WhatIf
```

See [Backup, restore, and copy](backup-and-restore.md) for the unified
multi-family envelope, signing, and the restore boundaries.

## Stage several edits into one write

Retrieving the descriptor once, editing it in memory, and persisting it once
avoids a read-modify-write cycle per rule:

```powershell
Get-NTFSItemSecurityDescriptor -LiteralPath 'C:\Data' -Sections Access |
    Add-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Read |
    Set-NTFSAccessRule -Account 'CONTOSO\Auditors' -AccessRights Modify |
    Disable-NTFSItemInheritance -Section Access |
    Set-NTFSItemSecurityDescriptor -Confirm:$false
```

See [Descriptor editing and concurrency](descriptor-editing.md).

## Commands on this page

| Area | Commands |
| --- | --- |
| Access rules | `New-NTFSAccessRule`, `Get-NTFSAccessRule`, `Add-NTFSAccessRule`, `Set-NTFSAccessRule`, `Remove-NTFSAccessRule`, `Clear-NTFSAccessRule` |
| Audit rules | `New-NTFSAuditRule`, `Get-NTFSAuditRule`, `Add-NTFSAuditRule`, `Set-NTFSAuditRule`, `Remove-NTFSAuditRule`, `Clear-NTFSAuditRule` |
| Owner | `Get-NTFSItemOwner`, `Set-NTFSItemOwner` |
| Inheritance | `Get-NTFSItemInheritance`, `Enable-NTFSItemInheritance`, `Disable-NTFSItemInheritance` |
| Descriptors | `Get-NTFSItemSecurityDescriptor`, `Edit-NTFSItemSecurityDescriptor`, `Set-NTFSItemSecurityDescriptor`, `Copy-NTFSItemSecurityDescriptor` |
| Portability | `Backup-NTFSItemSecurityDescriptor`, `Restore-NTFSItemSecurityDescriptor` |
| Diagnostics | `Get-NTFSItemEffectiveAccess`, `Test-NTFSItemAcl` |

## See also

- [Registry keys](registry.md)
- [Auditing and SACLs](auditing.md)
- [Descriptor editing and concurrency](descriptor-editing.md)
- [Troubleshooting](troubleshooting.md)
