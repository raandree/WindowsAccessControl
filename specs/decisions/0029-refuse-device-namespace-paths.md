# Refuse a device-namespace path and a bare drive specification

- Status: Accepted
- Date: 2026-08-11
- Deciders: user, software-engineer agent

## Context and problem statement

Every NTFS command reaches the file system through `Resolve-NTFSPath`, a thin
`Get-Item` wrapper. The FileSystem provider accepts an extended-length path
(`\\?\C:\…`, `\\?\UNC\server\share\…`) and a device path (`\\.\C:`), and
measured on this host both editions resolve `\\?\C:\…` and return a working
descriptor from `Get-Acl`. `\\.\C:` is not resolvable and already fails.

That acceptance is not a feature. The prefix tells Windows to pass the string to
the file system unparsed:

- No normalization happens. `.`, `..`, a trailing separator, and a trailing
  space or period are no longer resolved or trimmed, so two spellings of the
  same object are two different targets.
- The resolved `FullName` keeps the prefix. The module uses that string as the
  canonical target key for batch serialization, records it in backup records,
  and compares it in desired-state resources, so the same object under two
  spellings would take two locks and produce two records.
- The provider was never designed for it.
  <https://github.com/PowerShell/PowerShell/issues/10805> reports a `\\?\`
  path silently retargeting an operation and destroying a system.

A bare drive specification is a second silent retarget. Measured in both
editions, `Get-Item C:` returns the current location of the `C` drive, not the
volume root: after `Set-Location C:\Windows\System32`, `C:` resolves to
`C:\Windows\System32` even while the session is on another drive. A caller who
writes `Get-NTFSAccessRule -LiteralPath C:` means the volume, and would silently
read and write a directory deep inside it
(<https://github.com/raandree/NTFSSecurity/issues/44>).

`Get-NTFSItemEffectiveAccess` already refused `\\?\UNC\` and plain UNC targets,
but only for itself, and only because Authz cannot evaluate a remote target. The
rest of the family had no equivalent handling and no test.

## Decision

`Resolve-NTFSPath` refuses two shapes before they reach the provider, each with a
terminating error that names the shape and says what to supply instead:

- any supplied path beginning with `\\?\` or `\\.\`, as
  `WindowsAccessControl.DeviceNamespacePathNotSupported`
- a supplied path that is exactly a drive specification such as `C:`, as
  `WindowsAccessControl.AmbiguousDriveSpecification`

A drive-relative path such as `C:tmp\child` keeps working, because it names a
child rather than the drive itself and the resolved `FullName` is canonical.

A plain universal naming convention path stays supported. It normalizes, it
produces a canonical `FullName`, and it reads and writes the same descriptor as
the equivalent local path. Only `Get-NTFSItemEffectiveAccess` continues to
refuse it, for the unrelated reason recorded in
[0017](0017-defer-remote-and-combined-effective-access.md).

## Consequences

- A caller with a target longer than `MAX_PATH` cannot reach it by prefixing the
  path. In PowerShell 7 the target is reachable without a prefix because the
  runtime opts into long paths itself; in Windows PowerShell it is not
  reachable, and the command reports the provider's path-not-found error rather
  than resolving something else.
- A name that only exists in its untrimmed form, such as one ending in a space
  or a period, cannot be addressed. Windows itself cannot open it through a
  normalized path, so the alternative is not a working command but an
  unnormalized target key.
- `C:` must be written as `C:\`. The refusal is deterministic and its message
  names the replacement.
- The refusals are two comparisons per supplied path.

## See also

- [Naming a file](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
- [Maximum path length limitation](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation)
- [0017 Defer remote and combined effective access](0017-defer-remote-and-combined-effective-access.md)
