# SMB share-only effective access

Status: Accepted. This specification defines a bounded local-on-target
effective-access result for an SMB share DACL only.

## Scope

`Get-SmbShareEffectiveAccess` accepts ordinary unqualified local share names,
an optional account name or SID, optional `WindowsSmbShareRights`, and bounded
target-array execution. It returns the Authz-granted mask, typed share rights,
an optional requested-rights decision, and explicit context metadata.

## Authorization boundary

The command executes on the computer that owns the share. It reuses the
accepted SMB resolver, so UNC syntax, server-qualified targets, administrative
shares, clustered shares, and unsupported provider topology are rejected before
descriptor access.

Authz receives the share owner, group, and DACL plus a SID-derived local
context. The result sets:

- `AuthorizationContext = LocalSidDerived`
- `IncludesBackingNtfs = false`

The SID-derived context can omit network-logon and other logon-specific groups.
Context initialization can also fail when the executing process cannot contact
the selected SID's account authority; the command surfaces that Authz failure
instead of inventing a partial result.
The command does not query a remote resource manager, create a network logon
token, inspect the backing path, or intersect the share and NTFS masks. It must
never be presented as remote or combined effective access. ADR 0017 continues
to defer those claims.

## Data and resource safety

The command is read-only. It reads owner, group, and DACL because Windows
`AuthzAccessCheck` rejects an incomplete share descriptor, but it emits no
owner or group data beyond the normal structured target identity. Native Authz
resource managers, contexts, and buffers use the existing `finally`-guarded
interop boundary.

## Verification

Unit tests cover the public contract, complete descriptor-section request,
typed output, requested-rights decision, context label, and explicit NTFS
exclusion. Delegated live acceptance proves canonical deduplication and a real
nonzero share Authz result while retaining the original share DACL and
description. PowerShell 7.6.3 live acceptance runs the same read on the member
server with the local SYSTEM SID. Cleanup leaves no temporary user or module
copy and the complete lab ready.

## See also

- [SMB and AD DACL management](0009-smb-share-and-active-directory-dacl-management.md)
- [Security and persistence](0004-security-and-persistence.md)
- [Effective-access deferral decision](decisions/0017-defer-remote-and-combined-effective-access.md)
