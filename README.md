# NTFSPermission

`NTFSPermission` is a Windows PowerShell module for pipeline-first management of
file and directory security. It turns common DACL, SACL, owner, inheritance,
backup, and effective-access operations into composable commands without
requiring callers to manipulate .NET access-control objects directly.

The module has no third-party runtime dependency. It supports Windows
PowerShell 5.1 and PowerShell 7 on Windows.

## Quick start

Build the module, then import the generated manifest:

```powershell
.\build.ps1 -ResolveDependency

$manifest = Get-ChildItem -Path '.\output\module\NTFSPermission\*\NTFSPermission.psd1' |
    Sort-Object -Property { [version]$_.Directory.Name } -Descending |
    Select-Object -First 1
Import-Module -Name $manifest.FullName
```

Inspect explicit access rules across a directory tree:

```powershell
Get-ChildItem -LiteralPath 'C:\Data' -Recurse |
    Get-NTFSAccessRule -ExcludeInherited
```

Add an inheritable rule to several directories:

```powershell
Get-ChildItem -LiteralPath 'C:\Data' -Directory |
    Add-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Modify
```

Preview any mutation before applying it:

```powershell
Get-ChildItem -LiteralPath 'C:\Data' -Recurse |
    Clear-NTFSAccessRule -WhatIf
```

## Access rules

`Add-NTFSAccessRule` accumulates rights. `Set-NTFSAccessRule` replaces rules for
the same SID and the same allow or deny qualifier, preserving the opposite
qualifier and other accounts.

```powershell
Add-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Analysts' `
    -AccessRights ReadAndExecute `
    -AccessControlType Allow

Set-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Analysts' `
    -AccessRights Modify `
    -AccessControlType Allow
```

Exact removal is the default for a rule received from the pipeline:

```powershell
Get-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Analysts' -ExcludeInherited |
    Remove-NTFSAccessRule -Confirm:$false
```

Path-based removal exposes the underlying distinctions explicitly:

- `-RemovalMode Exact` removes an identical ACE.
- `-RemovalMode Rights` subtracts the selected rights from matching ACEs.
- `-RemovalMode All` purges every ACE for the selected SID.

Use `Get-NTFSAccessRule -Orphaned` to find SIDs that no longer translate to an
account. Treat those results carefully because a temporary domain connectivity
failure can also prevent translation.

## Rule scope

The `AppliesTo` parameter uses Windows Explorer-style values:

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

Files default to `ThisFolderOnly`. Directories default to
`ThisFolderSubfoldersAndFiles`.

## Inheritance and ownership

Disabling inheritance preserves inherited rules as explicit rules by default:

```powershell
Disable-NTFSItemInheritance -LiteralPath 'C:\Data'
Enable-NTFSItemInheritance -LiteralPath 'C:\Data'
```

Discard inherited rules only when that destructive behavior is intended:

```powershell
Disable-NTFSItemInheritance -LiteralPath 'C:\Data' `
    -PreserveInherited:$false
```

Owner commands emit both account and SID forms:

```powershell
Get-NTFSItemOwner -LiteralPath 'C:\Data'
Set-NTFSItemOwner -LiteralPath 'C:\Data' `
    -Account 'BUILTIN\Administrators' -Confirm:$false
```

Setting an arbitrary owner can require `SeRestorePrivilege`. Taking ownership
can require `SeTakeOwnershipPrivilege`.

## Audit rules and privileges

SACL operations require `SeSecurityPrivilege`, and Windows audit policy must
enable object access auditing before events are produced.

```powershell
Enable-NTFSPrivilege -Name SeSecurityPrivilege -Confirm:$false

Add-NTFSAuditRule -LiteralPath 'C:\Data' `
    -Account 'S-1-1-0' `
    -AccessRights Write `
    -AuditFlags Failure
```

`Enable-NTFSPrivilege` can enable only privileges already present in the current
process token. It fails explicitly when Windows reports
`ERROR_NOT_ALL_ASSIGNED`.

## Backup, restore, and copy

Backups use a versioned, non-executable JSON format containing path, item type,
selected section bitmask, and SDDL:

```powershell
Get-ChildItem -LiteralPath 'C:\Data' -Recurse |
    Backup-NTFSItemSecurityDescriptor `
        -DestinationPath 'C:\Backup\permissions.json'

Restore-NTFSItemSecurityDescriptor `
    -BackupPath 'C:\Backup\permissions.json' `
    -Confirm:$false
```

Restore validates every record and changes only the sections recorded in the
backup. It validates and prepares all records before the first descriptor is
persisted, so malformed later records cannot cause a partial restore. A later
filesystem I/O failure can still stop a restore after earlier records were
written; rerun the same validated backup after correcting the I/O failure.

Backups refuse to overwrite an existing file unless `-Force` is supplied. A
backup controls the target paths it restores, so review backup files from
outside trusted administrative workflows before applying them.

Copy follows the same selected-section rule:

```powershell
Get-ChildItem -LiteralPath 'C:\Target' |
    Copy-NTFSItemSecurityDescriptor `
        -SourceLiteralPath 'C:\Template' `
        -Sections Access `
        -Confirm:$false
```

## Effective access

`Get-NTFSItemEffectiveAccess` calls the Windows Authz API with
`MAXIMUM_ALLOWED`. It expands groups for a valid user SID and returns both the
raw access mask and `FileSystemRights`.

```powershell
Get-NTFSItemEffectiveAccess -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Alice' `
    -AccessRights Modify
```

A context created from a SID can omit logon-specific groups such as Interactive
or Network, and it is less complete than evaluation from a live logon token.
Share permissions are outside this module's scope and are not intersected with
the NTFS result.

## Commands

| Area | Commands |
| --- | --- |
| Access rules | `New-NTFSAccessRule`, `Get-NTFSAccessRule`, `Add-NTFSAccessRule`, `Set-NTFSAccessRule`, `Remove-NTFSAccessRule`, `Clear-NTFSAccessRule` |
| Audit rules | `New-NTFSAuditRule`, `Get-NTFSAuditRule`, `Add-NTFSAuditRule`, `Set-NTFSAuditRule`, `Remove-NTFSAuditRule`, `Clear-NTFSAuditRule` |
| Owner | `Get-NTFSItemOwner`, `Set-NTFSItemOwner` |
| Inheritance | `Get-NTFSItemInheritance`, `Enable-NTFSItemInheritance`, `Disable-NTFSItemInheritance` |
| Descriptor portability | `Get-NTFSItemSecurityDescriptor`, `Copy-NTFSItemSecurityDescriptor`, `Backup-NTFSItemSecurityDescriptor`, `Restore-NTFSItemSecurityDescriptor` |
| Diagnostics | `Resolve-NTFSIdentity`, `Get-NTFSItemEffectiveAccess`, `Test-NTFSItemAcl` |
| Privileges | `Test-NTFSPrivilege`, `Enable-NTFSPrivilege`, `Disable-NTFSPrivilege` |

Use `Get-Help <command> -Full` for parameter semantics and examples.

## Safety model

- Every mutator supports `WhatIf` and `Confirm`.
- High-impact clear, remove, owner, copy, restore, and privilege commands prompt
  according to PowerShell's confirmation preferences.
- Mutators are silent by default and expose `PassThru` where output is useful.
- DACL-only operations persist only modified DACL state and do not request SACL
  privileges.
- Inherited ACEs cannot be removed directly from a child; change inheritance or
  the parent rule instead.
- SACL operations and arbitrary ownership changes can require elevated token
  privileges.
- FileSystem provider resolution follows reparse points such as symbolic links
    and junctions. A path can change between resolution and descriptor
    persistence, so do not accept untrusted path input for privileged operations.
- Extended `\\?\` and `\\?\UNC\` paths are passed to the host runtime; support
    depends on the active PowerShell and Windows long-path configuration.

## Build and test

The repository uses Sampler, ModuleBuilder, InvokeBuild, Pester 5.7.1, and
PSScriptAnalyzer.

```powershell
.\build.ps1 -ResolveDependency
.\build.ps1 -Tasks test
.\build.ps1 -Tasks pack
```

The test matrix covers PowerShell 7 and Windows PowerShell 5.1 on Windows.
Builds and Pester runs should be launched from a clean process when developing
in VS Code. Sampler enforces at least 80% executable coverage for the merged
module.

## Design research

See [docs/research.md](docs/research.md) for the source review, API semantics,
scope decisions, and dependency analysis that informed this implementation.
