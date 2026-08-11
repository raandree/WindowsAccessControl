# Address the link object, not the destination of a reparse point

- Status: Accepted
- Date: 2026-08-11
- Deciders: user, software-engineer agent

## Context and problem statement

A junction, a directory symbolic link, and a file symbolic link are file system
objects that carry a reparse point. A file data operation on such a path
reparses to the destination, which is why "operate on the link" versus "operate
on the destination" is a real axis and why `icacls` exposes `/L`.

A security descriptor operation is not a file data operation. Measured on this
host, in both supported editions, with the module, `Get-Acl`, `Set-Acl`, and
`icacls`:

| Fixture | Write target | Link explicit entries | Destination explicit entries |
| --- | --- | --- | --- |
| Junction | link | 1 | 0 |
| Junction | destination | 0 | 1 |
| Directory symbolic link | link | 1 | 0 |
| File symbolic link | link | 1 | 0 |
| Hard link | either name | 1 | 1 |

`icacls` and `icacls /L` print the identical list for a junction, so the flag
changes nothing for a descriptor read either.

A hard link is not a reparse point. Two names refer to one file record, so the
descriptor is one object under both names by construction, and a change made
through one name is visible through the other.

## Decision

A descriptor read and a descriptor write address the **object the caller
named**. A junction, a symbolic link, and a volume mount point each carry their
own descriptor, and the module neither follows nor rewrites the destination.

No opt-out switch is added: there is nothing to opt out of. The behavior is now
stated in the module help and in the description of the commands that resolve a
file system path, and it is covered by tests on real junctions, symbolic links,
and hard links, cross-checked against `icacls` and `icacls /L`.

## Consequences

- Naming a link never silently changes a different object. That is the safe
  default and it matches every in-box tool.
- Securing a destination requires naming the destination. A caller who wants the
  destination reads `Target` or `LinkType` from `Get-Item -Force` and acts on
  that path.
- A hard link cannot be secured independently of its other names, because there
  is only one file record. A test records that.

## See also

- [Reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points)
- [Hard links and junctions](https://learn.microsoft.com/en-us/windows/win32/fileio/hard-links-and-junctions)
- [icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [0031 Never expand a supplied target set](0031-never-expand-a-supplied-target-set.md)
