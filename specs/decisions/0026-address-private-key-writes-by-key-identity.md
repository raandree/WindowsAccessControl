# Address private-key writes by key identity, not by certificate

- Status: Accepted
- Date: 2026-08-01
- Deciders: user, software-engineer agent

## Context and problem statement

Specification 0015 admits a fail-closed private-key DACL write, but every entry
point requires an exact `X509Certificate2`. A portability record must not carry
certificate or private-key material, and a desired-state resource is a MOF that
cannot carry one either, so neither can address the key the way the existing
commands do.

The obvious substitute is the certificate thumbprint. It is not usable: a
renewal that reuses the key produces a new certificate over the same key, so a
thumbprint recorded at backup time no longer names the certificate that carries
the key at restore time, while the key itself is unchanged.

The critical-binding gate compounds the problem. It compares the write target's
public key with the public key of every certificate a binding names, and it took
that target public key from the caller's certificate. Without a certificate the
gate had no input, and a gate with no input is a gate that cannot run.

## Decision

- Add a `Key` parameter set to every certificate private-key command that
  selects the key by CNG provider name, persisted key name, and `Machine` or
  `User` key scope. Keep the existing `Certificate` parameter set as the
  default.
- Verify, on the key-addressed path, that the opened key is an RSA key and that
  its scope matches the requested scope, because `CngKey.Open` would otherwise
  answer from the other key store.
- Read the write target's public key from the `CngKey` itself and key the
  critical-binding gate on that value for every write, whichever selector the
  caller used. Throw when the public key cannot be read.
- Keep `Test-CertificatePrivateKeyCriticalBinding` comparing certificate to
  certificate, because a caller holding a certificate asks about that
  certificate.
- Encode the family as a schema-version-2 record carrying `Server`,
  `ProviderName`, `KeyName`, `KeyScope`, and `CertificateThumbprint`, and hash
  the four new fields for this object family only.
- Record `CertificateThumbprint` as evidence and never use it to find a key.
- Add no restore-only or resource-only parameter that could bypass a
  specification 0015 gate, and add no override switch.

## Consequences

- A restore and a desired-state resource reach the key through the same boundary
  a direct write uses, so the gates cannot be bypassed by construction rather
  than by review.
- The binding gate has one implementation for every write, so the two selectors
  cannot drift apart.
- A restore of a key that serves a critical binding is refused. That is the
  intended behavior: a bound key is exactly the key whose DACL must not change
  under an automated replay.
- Existing version-1 and version-2 backups keep validating, because the four new
  hashed fields are appended only for the new object family and `ObjectFamily`
  is itself hashed.
- `Set-WindowsCngKeySecurityDescriptor` no longer takes a certificate. The
  module is unpublished, and the parameter was private.

## Alternatives considered

- Look the key up by certificate thumbprint: rejected because a renewal with key
  reuse changes the thumbprint while the key stays the same, so the record would
  fail on the key it correctly describes.
- Search every certificate store at restore time for a certificate whose private
  key has the recorded unique name: rejected because it opens a key handle per
  candidate, is slower on every write, and fails for a key that has no
  certificate at all.
- Store the certificate, or its public key, in the record: rejected because a
  portability record must stay descriptor-only, and because the public key is
  already available from the key the record relocates.
- Skip the binding gate on a restore because the record was produced from a
  state that already passed it: rejected outright. The binding can be created
  after the backup, which is precisely when refusing matters.
- Add the four fields to the version-2 hashed set for every family: rejected
  because it would invalidate the digest of every enterprise record written
  before this increment while adding nothing to those families.
- Introduce record version 3: rejected because the family carries exactly the
  authority version 2 already defines, and a third version would fork the
  envelope rules for no behavioral difference.

## See also

- [Certificate private-key portability and desired state](../0017-certificate-private-key-portability-and-desired-state.md)
- [CNG private-key DACL mutation](../0015-cng-private-key-dacl-mutation.md)
- [Require backup schema version 2 for enterprise targets](0016-require-schema-v2-for-enterprise-targets.md)
- [Use local Task Scheduler and software-key authority](0018-use-local-task-and-software-key-authority.md)
- [Reject CAPI private keys at the provider boundary](0024-reject-capi-private-keys-at-the-provider-boundary.md)
