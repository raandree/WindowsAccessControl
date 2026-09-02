# Getting started

This page installs the module, verifies the import, and runs a first read and a
first change. It also explains the target model that every other page assumes.

## Requirements

| Item | Requirement |
| --- | --- |
| Operating system | Windows |
| Shell | Windows PowerShell 5.1 or PowerShell 7 |
| Runtime | .NET Framework 4.6 or later for Windows PowerShell 5.1 |
| Dependencies | None at run time |
| Elevation | Not required to read; required for most writes and for every SACL operation |

## Install

Install from the PowerShell Gallery:

```powershell
Install-PSResource -Name WindowsAccessControl
```

Or with the older client:

```powershell
Install-Module -Name WindowsAccessControl -Scope CurrentUser
```

To run an unreleased change, build and import from the repository instead:

```powershell
.\build.ps1 -ResolveDependency

$manifest = Get-ChildItem -Path '.\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1' |
    Sort-Object -Property { [version]$_.Directory.Name } -Descending |
    Select-Object -First 1
Import-Module -Name $manifest.FullName
```

A build output path is visible only to the shell that imports it. Desired State
Configuration needs the module in a machine-wide path instead; see
[Desired State Configuration](dsc.md#make-the-module-visible-to-the-lcm).

## Verify the installation

```powershell
Get-Module -Name WindowsAccessControl
Get-Command -Module WindowsAccessControl
Get-DscResource -Module WindowsAccessControl
```

Read the help for any command, including its examples:

```powershell
Get-Help Get-NTFSAccessRule -Full
Get-Help Get-NTFSAccessRule -Examples
```

## Sample values used in this guide

Every page uses the same placeholders:

```powershell
$path = 'C:\Data'
$account = 'CONTOSO\Analysts'
$backupPath = 'C:\Backup\windows-permissions.json'
```

Replace them with test targets from your own environment before applying a
mutation.

## Your first read

Reading is always safe. List the access rules on one directory:

```powershell
Get-NTFSAccessRule -LiteralPath $path
```

Narrow the result to explicit rules for one account:

```powershell
Get-NTFSAccessRule -LiteralPath $path -Account $account -ExcludeInherited
```

Prefer `LiteralPath` over `Path` whenever a path can contain a character that
PowerShell treats as a wildcard, such as `[` or `]`.

## Your first change

Every mutating command supports `WhatIf`. Preview first, then repeat the same
command without it:

```powershell
$grantParameters = @{
    LiteralPath  = $path
    Account      = $account
    AccessRights = 'Modify'
    AppliesTo    = 'ThisFolderSubfoldersAndFiles'
}

Add-NTFSAccessRule @grantParameters -WhatIf
Add-NTFSAccessRule @grantParameters -Confirm:$false -PassThru
```

[Safety, preview, and privileges](safety-and-privileges.md) explains when
`Confirm:$false` is appropriate and which operations need a privilege.

## Targets are local

The module accepts local targets only. There is no `ComputerName` parameter on
any command, and passing a remote form is rejected rather than silently
retried:

| Rejected input | Family |
| --- | --- |
| UNC paths | File system |
| Native remote registry paths and remote `RegistryKey` objects | Registry |
| Remote `ServiceController` objects and qualified remote names | Services |
| Remote process objects | Processes |
| Qualified remote share names | SMB shares |

To manage another computer, open a remoting session and run the module there:

```powershell
Invoke-Command -ComputerName 'Server01' -ScriptBlock {
    Import-Module WindowsAccessControl
    Get-NTFSAccessRule -LiteralPath 'C:\Data' -ExcludeInherited
}
```

Active Directory is the one family that crosses a machine boundary by design.
Its commands bind LDAP directly to a domain controller you name or one they
locate; see [Active Directory objects](active-directory.md).

## Pipe commands together

Module commands are built to compose. A `Get` command emits path-bound rule
objects that the matching `Remove` command consumes, which is the most precise
way to delete one exact rule:

```powershell
Get-NTFSAccessRule -LiteralPath $path -Account $account -ExcludeInherited |
    Remove-NTFSAccessRule -WhatIf
```

Native objects work as input as well:

```powershell
Get-ChildItem -LiteralPath $path -Recurse | Get-NTFSAccessRule -ExcludeInherited
Get-Service -Name BITS | Get-ServiceAccessRule
Get-Item -LiteralPath 'HKLM:\Software\Contoso' | Get-RegistryKeyAccessRule
```

## Where to go next

| Next step | Page |
| --- | --- |
| Understand preview, confirmation, and privileges | [Safety, preview, and privileges](safety-and-privileges.md) |
| Work through the file system family in full | [File system](file-system.md) |
| Make several edits with one write | [Descriptor editing and concurrency](descriptor-editing.md) |
| Look up a command | [Command reference](command-reference.md) |

## See also

- [Usage guide overview](../usage-guide.md)
- [Migration from NTFSPermission](../migration-from-ntfspermission.md)
