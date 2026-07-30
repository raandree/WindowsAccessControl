# Enterprise portability and desired state

Status: Accepted. This specification defines schema-version-2 descriptor
portability, server-qualified SMB canonical identity, and object-specific
desired-state resources for the accepted SMB share and Active Directory
increments. It also records the accepted Active Directory effective-access
boundary.

## Scope

The increment adds no new command noun. It extends three existing surfaces:

| Surface | Change |
| --- | --- |
| SMB canonical identity | The canonical target and lock key are qualified by the owning computer name |
| `Backup-WindowsSecurityDescriptor` | Emits schema-version-2 records for SMB share and Active Directory descriptors |
| `Restore-WindowsSecurityDescriptor` | Accepts schema version 1 or 2 and gains `Server`, `AllowedBaseDistinguishedName`, `Credential`, and `TimeoutSeconds` |
| DSC | Adds four class-based resources for SMB share and Active Directory DACLs |

SACL operations, owner and group mutation, directory inheritance mutation,
replication convergence, cross-domain and cross-forest targets, direct remote
SMB APIs, and Active Directory effective access remain outside this contract.

## Server-qualified SMB identity

An SMB share canonical target is `SmbShare:<SERVER>:<SHARE>`, where `<SERVER>`
is the uppercase name of the computer that owns the share and `<SHARE>` is the
uppercase provider share name. The resolved target additionally reports
`Server`, so descriptors, rules, metrics, and the process-wide canonical write
lock all carry the owning computer.

The change does not admit a remote target. ADR 0015 still requires every SMB
command to execute on the computer that owns the share. The qualification
exists so a portability record cannot be replayed against a different computer
and so evidence names the machine that produced it.

## Backup schema version 2

Record version is a property of the object family, not of the caller:

| Object family | Record version |
| --- | ---: |
| `FileSystem`, `RegistryKey`, `Service`, `ServiceControlManager`, `Process` | 1 |
| `SmbShare`, `ADObject` | 2 |

A record whose family and version disagree is rejected in both directions, so a
version-2 record can never be replayed as a local target and a version-1 record
can never claim server authority it does not carry.

Version-2 records add `Server`, plus `ShareName` for a share and
`DistinguishedName`, `ObjectGuid`, and `DomainNamingContext` for a directory
object. Those fields are covered by the SHA-256 record digest and therefore by
the optional RSA signature. Version-1 records keep their original hashed field
set, so every existing backup still validates.

The envelope `SchemaVersion` is the highest record version the document
contains. Restore rejects a document that declares a lower schema version than
one of its records.

Both enterprise families select the access section only. A version-2 record
that selects any other section is rejected at backup time as well as at restore
time, so an unrestorable record is never persisted.

## Portability restore boundary

- An SMB record restores only on the computer named in the record. A record
  captured elsewhere is rejected before any share is opened. Share identity is
  the share name, not the directory behind it, so a share deleted and recreated
  over a different path receives the recorded DACL.
- A directory record requires `AllowedBaseDistinguishedName`. Every target is
  resolved for write during preparation, so the allowed base, base object
  class, protected-target, excluded-partition, and immutable object-GUID rules
  from specification 0009 all reject a bad record before the first write. The
  write then passes through `Set-ADObjectSecurityDescriptor`, which revalidates
  them.
- A directory record binds one explicit or discovered writable domain
  controller for the whole restore. That controller may differ from the one
  that produced the backup, so identity is matched on the immutable
  `objectGUID` and the recorded domain naming context rather than on the
  canonical target. For the same reason, duplicate detection keys a directory
  record on its domain naming context plus object GUID, so the same object
  captured through two controllers is rejected instead of restored twice.
- Restoring a version-2 record without a verification certificate warns. The
  SHA-256 digest is unkeyed, so it detects accidental damage rather than
  deliberate modification.
- Every record is validated, and every target prepared, before the first write.
  A runtime write failure remains nontransactional and is recoverable by
  rerunning the validated backup.

## Desired-state resources

| Resource | Composite keys | State |
| --- | --- | --- |
| `WindowsAccessControlSmbShareSecurityDescriptor` | `Name`, `Sections` | `Sddl` |
| `WindowsAccessControlADObjectSecurityDescriptor` | `DistinguishedName`, `Sections` | `AllowedBaseDistinguishedName`, `Sddl`, `Server`, `ObjectGuid`, `TimeoutSeconds` |
| `WindowsAccessControlSmbShareAccessRule` | `Name`, `Account`, `AccessRights`, `AccessControlType` | `Ensure` |
| `WindowsAccessControlADObjectAccessRule` | `DistinguishedName`, `Account`, `AccessRights`, `AccessControlType`, `InheritanceType`, `ObjectType`, `InheritedObjectType` | `AllowedBaseDistinguishedName`, `Ensure`, `Server`, `TimeoutSeconds` |

- `Sections` must be `Access`. Any other selection fails closed rather than
  silently managing a section the family does not expose.
- Directory resources require `AllowedBaseDistinguishedName` before any write.
  A configuration therefore states its own destructive boundary.
- `WindowsAccessControlADObjectSecurityDescriptor` accepts an optional
  `ObjectGuid`. When it is supplied, `Get()` fails if the distinguished name
  now resolves to a different directory object, because a name can be reused
  after a delete and recreate. `Set()` re-asserts the same pin against the
  pinned domain controller immediately before the write, so a direct
  `Invoke-DscResource -Method Set` cannot bypass it.
- Each directory resource resolves one domain controller per `Set()` and uses
  it for both the compliance read and the write, so replication lag cannot make
  a resource read one controller and write another.
- Directory rule identity includes both object GUIDs and the directory
  inheritance type, so a rule scoped to one attribute or class never converges
  by flattening an unrelated object ACE. `ObjectType` and
  `InheritedObjectType` are empty strings for an unscoped ACE; any other value
  must parse as a GUID.
- The resources take no credential. The Local Configuration Manager binds LDAP
  as the node's own identity, so a MOF never carries directory credentials.
- `Absent` removes every duplicate exact ACE and preserves partial rights,
  inherited ACEs, opposite qualifiers, other object scopes, and unrelated
  accounts.

## Active Directory effective access

ADR 0022 defers Active Directory effective access on measured evidence. The
module does not evaluate a directory descriptor through a locally constructed
Authz context and does not present a `tokenGroups`-derived reconstruction as an
access decision.

The supported alternatives remain `Get-ADObjectAccessRule`, which reports the
explicit and inherited rules with provenance and resolved GUID names, and the
domain controller's own caller-scoped constructed attributes
(`allowedAttributesEffective`, `allowedChildClassesEffective`,
`sDRightsEffective`) read with the in-box directory tooling.

## Verification

- Unit tests cover the server-qualified canonical target, version-2 record
  construction for both families, version and family pairing in both
  directions, digest detection of a tampered server identity, a directory
  record outside its recorded domain, envelope version selection, rejection of
  a version-2 record inside a version-1 envelope, the required allowed base,
  and the foreign-computer share rejection.
- Unit tests cover DSC routing for both new families, the access-section gate,
  the required allowed base, and directory rule matching on both object GUIDs
  and the inheritance type.
- Contract tests assert the exported resource names, composite keys, property
  sets, mandatory `Sddl`, and non-configurable `Reasons`.
- The fixed version-1 record-hash test proves existing local backups still
  validate after the hashed field set was extended for version 2.
- Live domain-lab evidence proves an SMB descriptor round trip on the member
  server and a directory descriptor round trip inside the disposable test
  organizational unit, each restoring the original DACL afterwards.

## See also

- [Enterprise access-control expansion](0008-enterprise-access-control-expansion.md)
- [SMB share and Active Directory DACL management](0009-smb-share-and-active-directory-dacl-management.md)
- [Public API](0003-public-api.md)
- [Security and persistence](0004-security-and-persistence.md)
- [Enterprise backup schema decision](decisions/0016-require-schema-v2-for-enterprise-targets.md)
- [Directory effective-access decision](decisions/0022-defer-active-directory-effective-access.md)
