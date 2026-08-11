# Never expand a supplied target set

- Status: Accepted
- Date: 2026-08-11
- Deciders: user, software-engineer agent

## Context and problem statement

Recursion across a reparse point does not terminate. A junction that points at
one of its own ancestors is a cycle, and the predecessor module hit exactly that
on `C:\Users` and `AppData`
(<https://github.com/raandree/NTFSSecurity/issues/81>).

No command in this module takes `-Recurse`, and the FileSystem provider's
wildcard expansion descends exactly one level. The property was true but
undocumented and untested, so a future `-Recurse` parameter could have
reintroduced the cycle without anything failing.

## Decision

A command operates on exactly the targets the caller supplies, plus one level of
FileSystem-provider wildcard expansion. The module never walks a directory tree
and therefore never crosses a junction, a symbolic link, or a volume mount point
on its own. Traversal stays with the caller, who chooses `Get-ChildItem`
`-Recurse` and its `-FollowSymlink` behavior deliberately.

Adding a traversal parameter later requires cycle detection keyed on the
volume serial number and file index, and a superseding decision record.

## Consequences

- A batch terminates by construction: the input set is finite and the dispatcher
  deduplicates identical canonical targets before it dispatches.
- A self-referential junction is one ordinary target. It is reported once, and a
  wildcard over its parent reports it once.
- A caller who recurses into a cycle observes the cycle in `Get-ChildItem`, not
  in this module.

## See also

- [Reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points)
- [0013 Use bounded parallel target execution](0013-use-bounded-parallel-target-execution.md)
- [0030 Address the link object, not the destination of a reparse point](0030-address-the-link-object.md)
