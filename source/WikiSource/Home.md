# WindowsAccessControl

<sup>*WindowsAccessControl v#.#.#*</sup>

`WindowsAccessControl` is a Windows PowerShell module for pipeline-first
management of Windows security descriptors. Its filesystem, registry-key,
service/SCM, live-process, SMB-share, Active Directory, Task Scheduler, and
certificate private-key commands turn common DACL, SACL, owner, inheritance,
backup, and effective-access operations into composable commands without
requiring callers to manipulate .NET access-control objects directly.

The command and DSC resource pages in this wiki are generated from the module
itself on every release. They come from the comment-based help in the source, so
they describe the version that is published rather than a separately maintained
copy.

Please leave comments, feature requests, and bug reports in the
[issues section](https://github.com/raandree/WindowsAccessControl/issues) for
this module.

## Getting started

Install from the [PowerShell Gallery](https://www.powershellgallery.com/packages/WindowsAccessControl/):

```powershell
Install-Module -Name WindowsAccessControl -Scope CurrentUser
```

Confirm the installation and list the commands:

```powershell
Get-Command -Module WindowsAccessControl
```

List the DSC resources the module exports:

```powershell
Get-DscResource -Module WindowsAccessControl
```

## Where to look next

- The command pages in the sidebar document every public command, its
  parameters, and its examples.
- The DSC resource pages in the sidebar document every resource and its
  properties. The `Desired State Configuration` section of the
  [README](https://github.com/raandree/WindowsAccessControl/blob/main/README.md)
  explains how the resources are meant to be used together.
- [`docs/usage-guide.md`](https://github.com/raandree/WindowsAccessControl/blob/main/docs/usage-guide.md)
  walks through the common tasks and links to a page for each object family.
- The [`docs/`](https://github.com/raandree/WindowsAccessControl/tree/main/docs)
  index lists every guide, including the migration map from `NTFSSecurity`.
- The [`specs/`](https://github.com/raandree/WindowsAccessControl/tree/main/specs)
  folder records the accepted behavior, including the cases the module
  deliberately refuses.

## Requirements

The module has no third-party runtime dependency. It supports Windows
PowerShell 5.1 and PowerShell 7, on Windows only.

## Change log

A full list of changes in each version can be found in the
[change log](https://github.com/raandree/WindowsAccessControl/blob/main/CHANGELOG.md).
