# WindowsAccessControl

<sup>*WindowsAccessControl v#.#.#*</sup>

`WindowsAccessControl` is a Windows PowerShell module for pipeline-first
management of Windows security descriptors. Its filesystem, registry-key,
service/SCM, live-process, SMB-share, Active Directory, Task Scheduler, and
certificate private-key commands turn common DACL, SACL, owner, inheritance,
backup, and effective-access operations into composable commands without
requiring callers to manipulate .NET access-control objects directly.

The command pages in this wiki are generated from the module itself on every
release. They come from each command's comment-based help, so they describe the
version that is published rather than a separately maintained copy.

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
- [`docs/usage-guide.md`](https://github.com/raandree/WindowsAccessControl/blob/main/docs/usage-guide.md)
  walks through the common tasks end to end.
- The migration guide in
  [`docs/`](https://github.com/raandree/WindowsAccessControl/tree/main/docs)
  maps the `NTFSSecurity` commands onto this module.
- The DSC resources are documented in the `Desired State Configuration` section
  of the
  [README](https://github.com/raandree/WindowsAccessControl/blob/main/README.md).
- The [`specs/`](https://github.com/raandree/WindowsAccessControl/tree/main/specs)
  folder records the accepted behavior, including the cases the module
  deliberately refuses.

## Requirements

The module has no third-party runtime dependency. It supports Windows
PowerShell 5.1 and PowerShell 7, on Windows only.

## Change log

A full list of changes in each version can be found in the
[change log](https://github.com/raandree/WindowsAccessControl/blob/main/CHANGELOG.md).
