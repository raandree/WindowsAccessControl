# CNG private-key DACL inspection

Status: Accepted. This specification defines read-only DACL inspection for an
exact persisted RSA private key in Microsoft Software Key Storage Provider.

## Scope

`Get-CertificatePrivateKeySecurityDescriptor` requires:

- one caller-owned `X509Certificate2` with an accessible private key
- the exact expected provider name
- the exact expected persisted key name

The command supports only `RSACng` keys whose provider is exactly Microsoft
Software Key Storage Provider, whose certificate-selected key name matches the
expected name, and whose identity is persistent and has a stable unique name.
It exposes no store search, subject/friendly-name selection, wildcard, remote,
credential, write, access-rule, SACL, owner/group, backup, or DSC surface.

## Identity and lifetime

The certificate is a selector and remains caller-owned. The command obtains one
module-owned RSA object, operates on its associated `CngKey`, and disposes only
the RSA object in `finally`. It never disposes the caller certificate, reopens
the key by a separate name, exports key bytes, or serializes private-key
material.

Canonical identity hashes a domain tag, key scope, normalized provider, and
unique provider key name using length-prefixed UTF-8 and SHA-256:

```text
CertificatePrivateKey:Cng:<Machine|User>:<64 hex characters>
```

Raw provider/container values remain separate diagnostic fields and are not
embedded in the canonical lock identity.

## Descriptor boundary

The adapter reads CNG property `Security Descr` with DACL and silent flags. It
parses the returned bytes as a `RawSecurityDescriptor` and emits only DACL SDDL,
descriptor bytes, identity metadata, and the native descriptor object. The
silent flag prevents UI-protected providers from prompting in automation.

This increment is read-only. A no-op managed `CngKey.SetProperty` capability
probe succeeded on the disposable fixture, but write support is not admitted
until focused issues close fail-closed critical-service binding detection,
provider implementation/hardware rejection, recovery-ACE preservation,
negative fixtures, rollback, typed mutation, and cryptographic review.

Specification 0015 closes those conditions and supersedes this read-only
boundary. Every identity, lifetime, no-export, and canonical-identity rule
above still applies to the mutation surface.

## Verification

Unit tests cover the exact public parameter contract, private adapter routing,
and opaque deterministic canonical identity. Live acceptance reads the
non-exportable machine CNG fixture in Windows PowerShell 5.1 and PowerShell
7.6.3, verifies the exact provider/key identity, stable canonical target,
nonempty DACL descriptor, caller-certificate lifetime, and absence of private-
key output. The complete lab remains ready afterward.

## See also

- [CNG private-key DACL mutation](0015-cng-private-key-dacl-mutation.md)
- [Enterprise expansion](0008-enterprise-access-control-expansion.md)
- [Security and persistence](0004-security-and-persistence.md)
- [Task and software-key authority decision](decisions/0018-use-local-task-and-software-key-authority.md)
- [Open issues](open-issues.md)
