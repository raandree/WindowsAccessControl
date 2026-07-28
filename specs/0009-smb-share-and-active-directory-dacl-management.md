# SMB share and Active Directory DACL management

Status: Accepted. This specification defines the first implemented enterprise
access-control increment: DACL descriptor and explicit access-rule management
for local SMB shares and Active Directory objects in one explicitly selected
domain partition.

## Scope

The increment exports five commands per object family:

| SMB share | Active Directory object |
| --- | --- |
| `Get-SmbShareSecurityDescriptor` | `Get-ADObjectSecurityDescriptor` |
| `Set-SmbShareSecurityDescriptor` | `Set-ADObjectSecurityDescriptor` |
| `Get-SmbShareAccessRule` | `Get-ADObjectAccessRule` |
| `Add-SmbShareAccessRule` | `Add-ADObjectAccessRule` |
| `Remove-SmbShareAccessRule` | `Remove-ADObjectAccessRule` |

The descriptor commands operate on the DACL only. Rule additions are explicit
allow or deny ACEs. Rule removal accepts only a path-bound rule emitted by the
matching query command and removes one exact native ACE. Mutators preserve
owner, group, SACL, every unrelated ACE, and object-specific ACE metadata.

This increment does not include SACL operations, owner/group mutation,
inheritance mutation, account purge, clear, replacement-rule semantics,
effective access, backup/restore, DSC, replication convergence, cross-domain
or cross-forest targets, or combined SMB-plus-NTFS authorization claims.

## SMB share contract

SMB commands execute on the computer that owns the share. `Name` is an
unqualified local share name; UNC paths, server-qualified names, and remote
objects are rejected. Administrators manage another computer by entering an
approved secure session and running the command on that computer.

The resolver verifies that the share exists and rejects administrative or
special shares: `ADMIN$`, drive-letter shares, `IPC$`, and `print$`. An
accepted target must report a filesystem-directory share, default SMB
instance, nonclustered availability, and no continuously-available,
infrastructure, shadow-copy, scoped, or temporary flags. Hidden ordinary shares
such as the disposable lab share remain valid. DFS namespaces and cloud-backed
storage that present indistinguishable ordinary provider flags are not a
verified target contract in this increment.

`WindowsSmbShareRights` exposes the Windows share masks `Read`, `Change`, and
`Full`. Query output preserves the unsigned native mask and native ACE even
when a descriptor contains another valid mask. Share ACLs have no inheritance
contract; every managed share ACE is explicit.

The implementation uses the shared binary descriptor engine with
`SE_LMSHARE`. It does not flatten a share DACL through a friendly access-level
projection.

## Active Directory contract

Every AD command requires `Server` and `DistinguishedName`. `Server` names the
final writable domain controller directly. IP literals, URLs, local aliases,
and implicit DC discovery are rejected by the public adapter. The connection
uses LDAP v3 with Kerberos authentication, signing, sealing, no referral
chasing, and a bounded timeout. An optional `PSCredential` binds directly to
that DC; credentials are never forwarded through another machine or retained
in output, logs, metrics, or backup data.

Targets must resolve inside the selected DC's default domain naming context.
Output binds the current distinguished name to immutable `objectGUID` and
server authority. Before every write, the adapter resolves the same DN again
and rejects deletion, rename, move, or GUID mismatch.

Every AD mutation also requires `AllowedBaseDistinguishedName`. The base must
resolve to an organizational unit in the default domain partition. The target
must be that OU or one of its descendants. Domain root, `AdminSDHolder`, the
Domain Controllers OU, the System container, Group Policy objects,
configuration partition, and schema partition are rejected regardless of the
supplied base.

`WindowsActiveDirectoryRights` mirrors the in-box AD rights mask.
`WindowsActiveDirectoryInheritance` exposes `None`, `All`, `Descendents`,
`SelfAndChildren`, and `Children`. Optional `ObjectType` and
`InheritedObjectType` GUIDs create an object ACE without flattening native
metadata. Query output preserves unknown GUIDs and the exact native ACE.

## Mutation and failure behavior

- All accounts are translated to SIDs and deduplicated before the first read
  for mutation.
- `ShouldProcess` gates every write. Mutators emit nothing unless `PassThru`
  is requested.
- A descriptor setter accepts SDDL as data, requires a non-null DACL, and
  persists only the access section.
- Add is idempotent for an exact SID, qualifier, mask, inheritance, and object
  GUID tuple.
- Exact removal rejects output from another family, server, share, DN, or
  object instance.
- Exact removal is idempotent when the path-bound ACE is already absent.
- AD writes revalidate server authority, allowed base, protected-target rules,
  and object GUID immediately before LDAP modification.
- Runtime write failure is nontransactional. Live tests restore the original
  DACL in `finally` and prove no disposable resource leaks.

## Threat model and authority matrix

| Boundary | Read authority | Write authority | Channel | Containment |
| --- | --- | --- | --- | --- |
| SMB share DACL | Target token with `READ_CONTROL` | Target token with `WRITE_DAC` | Local API only | Reject remote syntax and special shares; use a non-Domain-Admin local administrator in acceptance |
| AD object DACL | Directory principal with `READ_CONTROL` | Delegated principal with `WRITE_DAC` inside the allowed OU | Direct signed and sealed LDAP to explicit DC | Reject downgrade, referrals, protected targets, moves, and GUID mismatch |

Private directory data consists of DNs, SIDs, schema GUIDs, and descriptors.
The commands have no arbitrary outbound channel and emit only requested
structured results. No untrusted remote content is executed. Account and SDDL
input is validated as data before persistence. Ordinary live mutation evidence
uses a delegated identity that is not a Domain Admin; RID-500 remains recovery
authority and is never a test target.

## Backup and later work

ADR 0016 requires backup schema version 2 before either family enters unified
backup/restore. Version 1 cannot bind explicit server authority plus immutable
directory object identity without changing its replay and canonical-target
contract. This increment therefore exports no backup integration.

Specification 0011 later admits bounded local share-only effective access. SMB
remote APIs, combined share/NTFS effective access, AD schema-name resolution,
broader mutation modes, replication, DSC, and SACL workflows remain tracked by
specification 0008 and focused open issues OI-11 and OI-14 through OI-18. ADR
0017 explicitly defers remote and combined effective access.

## Verification

- Unit tests cover target rejection, rights typing, object GUID preservation,
  signed/sealed connection construction, protected-target rejection,
  `WhatIf`, idempotent add, and exact removal.
- Disposable live tests prove SMB DACL round trip and unrelated-ACE
  preservation on the member server.
- Disposable live tests prove AD DACL round trip, object-specific ACE
  preservation, delegated mutation, GUID revalidation, and rollback in the
  test OU.
- Both adapters parse and import in PowerShell 7 and Windows PowerShell 5.1.
- PSScriptAnalyzer, manifest/help QA, specification conformance, package
  inspection, and independent security review have no unresolved Blocker or
  Major findings before completion is claimed.

## See also

- [Enterprise access-control expansion](0008-enterprise-access-control-expansion.md)
- [Requirements](0002-requirements.md)
- [Public API](0003-public-api.md)
- [Security and persistence](0004-security-and-persistence.md)
- [Verification and traceability](0005-verification-and-traceability.md)
- [Enterprise authority decision](decisions/0015-use-local-smb-and-signed-sealed-ldap.md)
- [Enterprise backup schema decision](decisions/0016-require-schema-v2-for-enterprise-targets.md)
