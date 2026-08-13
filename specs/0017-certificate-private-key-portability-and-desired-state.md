# Certificate private-key portability and desired state

Status: Accepted. This specification defines schema-version-2 descriptor
portability and object-specific desired-state resources for the fail-closed CNG
private-key DACL mutation of specification 0015. It adds no capability to that
write boundary and removes none of its gates.

## Scope

The increment adds no new command noun. It extends four existing surfaces:

| Surface | Change |
| --- | --- |
| Certificate private-key commands | Gain a key-addressed parameter set that selects the key by provider, persisted key name, and key scope |
| Certificate private-key targets | Report the owning computer as `Server` |
| `Backup-WindowsSecurityDescriptor` | Emits schema-version-2 records for certificate private-key descriptors |
| `Restore-WindowsSecurityDescriptor` | Restores certificate private-key records on their originating computer |
| DSC | Adds two class-based resources for the private-key DACL |

Audit rules, SACL, owner and group mutation, key creation, key deletion, key
export, hardware and removable providers, and Certificate Application
Programming Interface providers remain outside this contract, as
specifications 0012 and 0015 and ADR 0024 already state.

## Key-addressed identity

A portability record cannot carry a certificate, so a restore has to relocate
the key it describes. The only stable selector is the CNG provider name plus the
persisted key name, qualified by the machine or current-user key scope. The
certificate thumbprint is never a selector: a renewal that reuses the key
produces a new thumbprint over the same key, so a thumbprint lookup would fail
on exactly the key the record still describes.

Every private-key command therefore accepts two selectors:

| Parameter set | Selector |
| --- | --- |
| `Certificate` | An exact caller-owned `X509Certificate2` plus `ProviderName` and `KeyName` |
| `Key` | `ProviderName`, `KeyName`, and `KeyScope` |

Both forms resolve the same `CngKey`, compute the same canonical target, take
the same process-wide write lock, and pass through the same gates. The
key-addressed form additionally verifies that the opened key is an RSA key and
that its machine or user scope matches the requested scope, because
`CngKey.Open` would otherwise silently answer from the other key store.

The canonical target is unchanged at
`CertificatePrivateKey:Cng:<Machine|User>:<64 hex characters>`, where the hash
covers the provider name, the key scope, and the provider's unique name. The
unique name is a per-machine container file name, so the canonical target is
already computer-scoped. The resolved target additionally reports `Server`, so
descriptors, rules, and evidence name the machine that produced them.

## Computer-scoped write boundary

The binding gate of specification 0015 is keyed on the private key rather than
on a certificate, so it must be evaluable without one. The write target's public
key is read from the key itself and compared with the public key of every
certificate a critical binding names. Two certificates share a private key
exactly when they carry the same public key, and a key exposes that same public
key without exporting private material. A public key that cannot be read throws,
because a gate input that cannot be evaluated must not default to permit.

This replaces the certificate-to-certificate comparison inside the write
boundary. `Test-CertificatePrivateKeyCriticalBinding` keeps the
certificate-to-certificate comparison, because a caller that holds a certificate
asks that question about the certificate it holds.

## Backup schema version 2

Record version stays a property of the object family:

| Object family | Record version |
| --- | ---: |
| `FileSystem`, `RegistryKey`, `Service`, `ServiceControlManager`, `Process` | 1 |
| `SmbShare`, `ADObject`, `TaskFolder`, `ScheduledTask`, `CertificatePrivateKey` | 2 |

A record whose family and version disagree is rejected in both directions, so a
version-2 record can never be replayed as a local target and a version-1 record
can never claim computer authority.

A certificate private-key record reuses the version-2 `Server` field, stores the
persisted key name in `Target`, and adds four hashed fields: `ProviderName`,
`KeyName`, `KeyScope`, and `CertificateThumbprint`. Those four are hashed only
for this object family. Adding them to every version-2 record would change the
digest of every SMB share, Active Directory, and Task Scheduler record written
before this increment; `ObjectFamily` is itself the first hashed field, so the
field set a record uses is covered by its own digest.

`CertificateThumbprint` is evidence, not a selector. It records which
certificate the descriptor was captured through, is empty when the descriptor
was read through the key-addressed form, and is never used to find a key.

**A portability record never contains certificate or private-key material.** It
carries the DACL in SDDL form and the selector that relocates the key, and
nothing else.

The family selects the access section only. A record that selects any other
section is rejected at backup time as well as at restore time, so an
unrestorable record is never persisted.

## Portability restore boundary

- A certificate private-key record restores only on the computer named in the
  record. Every computer-scoped record in the document is checked before any
  target is opened, so a foreign record cannot be reached after an earlier
  record was already written.
- Preparation reopens the key by provider, key name, and key scope and compares
  the recomputed canonical target with the record. Because the canonical target
  hashes the provider's per-machine container name, that comparison rejects both
  a different key and the same key name on a different machine. The prepared
  identity is then passed to the write as `ExpectedCanonicalTarget` and
  reasserted against the handle the write holds, so a key deleted and recreated
  under the same name between preparation and the write is refused rather than
  written to.
- The candidate descriptor is rebuilt from its access section alone before it
  reaches the provider, so an owner, group, or SACL in a record's `Sddl` is
  dropped rather than carried into the binary form.
- The write passes through `Set-CertificatePrivateKeySecurityDescriptor`, which
  applies every specification 0015 gate without exception: the provider
  allow-list and software-only implementation probe, key identity, plain-ACE
  support, the no-new-deny rule, the critical-binding refusal, recovery
  preservation for `S-1-5-18` and `S-1-5-32-544`, service-grant preservation,
  the DACL protection gate, null-DACL rejection, post-write verification, and
  verified rollback. There is no override switch and no restore-only exemption.
- A restore therefore fails closed on a key that serves an HTTP.sys, WinRM
  HTTPS, Remote Desktop, or Active Directory LDAPS binding, exactly as a direct
  write does. The refusal names the binding and the bound certificate so the
  operator can rebind or remove the binding first.
- `Restore-WindowsSecurityDescriptor` gains no new parameter for this family.
  The other families need a caller-stated containment boundary because their
  targets are named by caller-chosen paths; a private-key target is pinned by
  the hash of the key's own container identity, and the write gates are the
  containment.
- Restoring a version-2 record without a verification certificate warns. The
  SHA-256 digest is unkeyed, so it detects accidental damage rather than
  deliberate modification. Sign any backup that leaves the computer that
  produced it.

## Desired-state resources

| Resource | Composite keys | State |
| --- | --- | --- |
| `WindowsAccessControlCertificatePrivateKeySecurityDescriptor` | `ProviderName`, `KeyName`, `KeyScope`, `Sections` | `Sddl` |
| `WindowsAccessControlCertificatePrivateKeyAccessRule` | `ProviderName`, `KeyName`, `KeyScope`, `Account`, `AccessRights`, `AccessControlType` | `Ensure` |

- `Sections` must be `Access`. Any other selection fails closed rather than
  silently managing a section the family does not expose.
- Both resources address the key without a certificate, so a MOF never carries a
  thumbprint that a renewal would invalidate, and never carries key material.
- Descriptor compliance expands each generic bit through the file generic
  mapping before comparing, because the provider stores a candidate ACE with the
  matching generic bit added and a requested `0x00120089` reads back as
  `0x80120089`. Exact SDDL equality would therefore report drift on every
  consistency run. Protection state and the duplicate-sensitive ACE multiset are
  compared exactly; ACE order is ignored for the same reason the write boundary
  treats an allow-only reordering as already converged. Windows evaluates a DACL
  in order, so these resources cannot detect a reordering that moves an allow
  ACE ahead of a deny ACE.
- `Ensure = Present` with `AccessControlType = Deny` is refused. A deny ACE
  naming a group that contains SYSTEM or Administrators locks the key while
  every per-account grant check still passes, so specification 0015 admits no
  way to create one. `Ensure = Absent` with `Deny` removes a deny ACE that
  already exists.
- `Absent` removes every duplicate exact ACE and preserves partial rights,
  inherited ACEs, opposite qualifiers, and unrelated accounts. Rights are
  matched on the effective mask on both sides, so a resource that names a
  generic right such as `GenericRead` matches the ACE it created rather than
  reporting the grant absent, and a resource that names `Read` never removes an
  account that holds `FullControl`. One removal clears every duplicate.
- Compliance matches on ACE type rather than ACE qualifier, so a conditional
  allow ACE never reports a grant as present. That is the same rule the write
  boundary applies.
- The resources take no credential. The Local Configuration Manager runs on the
  computer that owns the key, which is the only supported authority under
  ADR 0018.

## Verification

- Unit tests cover the key-addressed parameter set on every private-key command,
  the reported `Server`, version-2 record construction, the family and version
  pairing in both directions, the access-section gate at backup time, the
  canonical-target and key-scope agreement check, a malformed evidence
  thumbprint, digest detection of a tampered provider name and of a tampered key
  name, and the foreign-computer rejection.
- Unit tests prove that the key-derived public-key identity equals the identity
  of a certificate over the same key and differs from an unrelated key, and that
  a bound certificate resolved from a store is matched through the key-addressed
  gate.
- Unit tests prove that a restore is refused for each specification 0015 gate it
  could otherwise bypass: an unsupported provider, a key that serves a critical
  binding, a candidate that adds a deny ACE, a non-plain ACE, a candidate that
  removes the SYSTEM or Administrators grant, a candidate that removes an
  existing service grant, a protection-state change, and a null DACL.
- Unit tests cover DSC routing for both resources, the access-section gate, the
  generic-bit-tolerant compliance comparison in both directions, the refusal of
  a conditional allow ACE, the single removal of duplicate ACEs, and the refusal
  to create a deny rule.
- Unit tests cover the canonical-identity pin, and that a caller-supplied owner,
  group, or SACL never reaches the provider.
- Contract tests assert the exported resource names, composite keys, property
  sets, mandatory `Sddl`, and non-configurable `Reasons`.
- The fixed version-1 record-hash test proves existing local backups still
  validate, and the existing version-2 families gained no hashed field.
- Domain-lab acceptance executes the backup round trip on the disposable machine
  key, proves the restore reasserts the original DACL byte for byte, proves that
  a record whose recorded computer is another machine is rejected, proves that a
  restore of a bound key is refused while the binding is live and succeeds once
  it is released, and converges both desired-state resources with a repeated
  consistency pass that reports no drift.
- Domain-lab acceptance enrolls a machine certificate from an enterprise
  template that requires the same key on renewal, renews it, and proves the
  thumbprint claim on a real issued key: the renewal produces a different
  thumbprint over the same key container, the canonical target is unchanged,
  and a record captured before the renewal still relocates the key and restores
  its DACL although the thumbprint it recorded now matches no certificate. Both
  requests run as the machine account, because enrollment reads the enrollment
  policy from the directory.

## See also

- [CNG private-key DACL mutation](0015-cng-private-key-dacl-mutation.md)
- [CNG private-key DACL inspection](0012-cng-private-key-dacl-inspection.md)
- [Enterprise portability and desired state](0013-enterprise-portability-and-desired-state.md)
- [Task Scheduler portability and desired state](0014-task-scheduler-portability-and-desired-state.md)
- [Public API](0003-public-api.md)
- [Enterprise backup schema decision](decisions/0016-require-schema-v2-for-enterprise-targets.md)
- [Private-key portability decision](decisions/0026-address-private-key-writes-by-key-identity.md)
