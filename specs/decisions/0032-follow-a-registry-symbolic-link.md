# Follow a registry symbolic link to its target

- Status: Accepted
- Date: 2026-08-11
- Deciders: user, software-engineer agent

## Context and problem statement

A registry key created with `REG_OPTION_CREATE_LINK` is a `REG_LINK`: opening it
without `REG_OPTION_OPEN_LINK` opens the key it names instead. Windows itself
ships one on every installation, `HKLM\SYSTEM\CurrentControlSet`, which points at
the active `ControlSet00n`.

Neither the registry provider nor `RegGetKeySecurity` through a normally opened
handle exposes the link's own descriptor: `REG_OPTION_OPEN_LINK` has to be passed
at open time, and no in-box managed API offers it.

This differs from the file system, where a junction and a symbolic link each
carry their own descriptor and are addressed as themselves
([0030](0030-address-the-link-object.md)). The registry is the opposite case, and
the difference has to be recorded rather than assumed to be symmetric.

## Decision

A registry descriptor read and write addresses the **target** of a registry
symbolic link. `HKLM:\SYSTEM\CurrentControlSet` therefore reports the descriptor
of the control set it currently names, and a write through the link changes that
control set.

No opt-out is added. Reaching the link key itself would need a new native open
path taking `REG_OPTION_OPEN_LINK`, and there is no reported need for it.

## Consequences

- A caller who secures `HKLM:\SYSTEM\CurrentControlSet` secures the active
  control set, and the change moves with the link if the active set changes.
- The file system and the registry deliberately differ: a file system link is
  addressed as itself, a registry link as its target. Both are stated in the
  module help.
- A test pins the behavior against the system-provided link, so a regression in
  the open path is caught without creating a link.

## See also

- [Registry key security and access rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)
- [Accessing an alternate registry view](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view)
- [0030 Address the link object, not the destination of a reparse point](0030-address-the-link-object.md)
