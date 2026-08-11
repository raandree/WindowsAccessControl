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

Every AD command requires `DistinguishedName`. `Server` names the final writable
domain controller directly and is optional. When it is omitted, one writable
domain controller is located in the calling computer's domain, validated by the
same explicit-name rules, resolved once per invocation, and pinned for every
target so one command never spans two consistency points. IP literals, URLs,
local aliases, and remote syntax are rejected in both cases. The connection
uses LDAP v3 with Kerberos authentication, signing, sealing, no referral
chasing, and a bounded timeout. An optional `PSCredential` binds directly to
that DC; credentials are never forwarded through another machine or retained
in output, logs, metrics, or backup data. Discovery itself does not use the
credential and never searches another domain or forest.

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
`InheritedObjectType` create an object ACE without flattening native metadata,
and accept either the GUID or the schema class, attribute, property set,
validated write, or extended right name that identifies it. A name is resolved
once per invocation over the pinned connection and is rejected when it matches
nothing or resolves ambiguously, because falling back to the empty GUID would
turn an entry scoped to one property into one that applies to every property.
Query output preserves unknown GUIDs and the exact native ACE.

`Get-ADObjectSchemaDefaultAccessRule` reads `defaultSecurityDescriptor` from a
schema class and returns the entries Active Directory applies when it creates an
object of that class. The stored SDDL names domain-relative aliases, and the
platform parser resolves those against the calling computer's domain and fails
outright on a computer that has none, so the aliases are expanded against the
SID of the domain the pinned controller serves and, for forest-wide aliases,
against the forest root domain SID. A child domain controller does not hold the
forest root partition and referral chasing is disabled, so that SID is read from
the global catalog port of the same pinned server, which carries every domain's
`objectSid` without a referral. A forest-wide alias whose root domain SID cannot
be read from either source is refused rather than expanded against the wrong
domain.

Query output additionally reports where an inherited ACE came from and what its
GUIDs mean. `InheritedFrom` names the nearest ancestor object that holds the
originating explicit inheritable ACE, resolved over the same bound connection
rather than through a separately located domain controller. `ObjectTypeName`
and `InheritedObjectTypeName` report the schema class, attribute, property set,
validated write, or extended right that each GUID identifies. Both enrichments
are best effort: an unreadable ancestor, an unresolved GUID, or a lookup failure
reports null for that property and never removes a rule from the result. ADR
0020 records the inference rules and their evidence.

## Mutation and failure behavior

- All accounts are translated to SIDs and deduplicated before the first read
  for mutation.
- `ShouldProcess` gates every write. Mutators emit nothing unless `PassThru`
  is requested.
- A descriptor setter accepts SDDL as data, requires a non-null DACL, and
  persists only the access section.
- Add is idempotent for an exact SID, qualifier, mask, inheritance, and object
  GUID tuple.
- AD set, rights removal, account purge, and clear match on account, qualifier,
  and both object GUIDs, so an ACE scoped to a different GUID pair is preserved
  rather than flattened. Clear and account purge never remove an inherited ACE,
  remove allow and deny alike, and warn when an explicit deny is removed.
- AD rights removal expands a stored native `GENERIC_*` bit into the rights it
  confers before subtracting, so a revoked right cannot survive inside a
  generic grant.
- Every AD rule mutator rejects a candidate DACL that grants no principal
  `WriteDacl` or `WriteOwner` on the object itself. The check is a lockout guard
  for the common case, not a proof of recoverability: it performs no group
  expansion and no grantee resolution, and it warns instead of failing when the
  object was already unmanageable. `Set-ADObjectSecurityDescriptor` remains the
  explicit escape hatch.
- Every AD rule mutator re-reads the target at the write boundary and rejects
  the write when the DACL changed after the descriptor was staged.
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
contract. This increment therefore exported no backup integration;
specification 0013 later added it together with the server-qualified SMB
canonical identity and the four enterprise DSC resources.

Specification 0011 later admits bounded local share-only effective access.
ADR 0022 defers Active Directory effective access on measured evidence. SMB
remote APIs, combined share/NTFS effective access, and SACL workflows remain
tracked by specification 0008. ADR 0017 explicitly defers remote and combined
effective access.

Replication convergence is no longer deferred. Specification 0016 records the
multi-controller behavior this contract left open, and closes open issue OI-18.

## Verification

- Unit tests cover target rejection, rights typing, object GUID preservation,
  signed/sealed connection construction, protected-target rejection,
  `WhatIf`, idempotent add, exact removal, distinguished-name parent parsing,
  ancestor provenance matching, and pinned domain-controller discovery.
- Disposable live tests prove SMB DACL round trip and unrelated-ACE
  preservation on the member server.
- Disposable live tests prove AD DACL round trip, object-specific ACE
  preservation, delegated mutation, GUID revalidation, and rollback in the
  test OU.
- Disposable live tests prove that set replaces only the matching object scope,
  that rights removal subtracts without dropping a still-granted ACE, that an
  account purge leaves unrelated rules intact, that a clear which would make the
  object unmanageable is rejected without writing, and that a staged write whose
  target changed after the read is rejected. The last two use a disposable child
  organizational unit so a rejected write can never strand the shared fixture.
- A live probe compares inferred inheritance sources with the native
  `GetInheritanceSourceW` result for the same object and records that the
  native call cannot honor an explicit server.
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
- [Directory rule enrichment decision](decisions/0020-enrich-directory-rules-over-the-bound-connection.md)
- [Domain-controller discovery decision](decisions/0021-discover-and-pin-a-domain-controller.md)
