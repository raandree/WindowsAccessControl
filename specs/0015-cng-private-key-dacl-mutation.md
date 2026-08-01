# CNG private-key DACL mutation

Status: Accepted. This specification defines fail-closed typed mutation of the
DACL of an exact persisted RSA private key in Microsoft Software Key Storage
Provider. It supersedes the read-only boundary of specification 0012 and keeps
every identity, lifetime, and no-export rule that specification states.

## Scope

| Surface | Change |
| --- | --- |
| `Get-CertificatePrivateKeyAccessRule` | New. Emits typed private-key access rules |
| `Add-CertificatePrivateKeyAccessRule` | New. Adds typed allow rules |
| `Remove-CertificatePrivateKeyAccessRule` | New. Removes exact typed allow or deny rules |
| `Set-CertificatePrivateKeySecurityDescriptor` | New. Writes one complete desired DACL |
| `Test-CertificatePrivateKeyCriticalBinding` | New. Reports the bindings that refuse a write |
| `Get-CertificatePrivateKeySecurityDescriptor` | Unchanged behavior, stricter provider gate |

Certificate Application Programming Interface (CAPI) providers, hardware and
removable providers, audit rules, SACL, owner and group mutation, key creation,
key deletion, key export, portability, and desired-state resources remain
outside this contract.

## Rights model

Microsoft Software Key Storage Provider persists a key as a file, so the
`NCRYPT_SECURITY_DESCR_PROPERTY` descriptor carries the file access mask.
`WindowsCryptoKeyRights` therefore mirrors the file rights and adds the four
generic bits.

A live probe established two facts that the contract depends on:

- A freshly created machine key carries
  `D:P(A;;0xd01f01ff;;;CO)(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)`, which is
  `FILE_ALL_ACCESS` plus `GENERIC_ALL`, `GENERIC_WRITE`, and `GENERIC_READ`.
- The provider stores a candidate ACE with the matching generic bit added. A
  requested `0x00120089` reads back as `0x80120089`.

A requested mask and the stored mask are therefore never bit-identical.
Every comparison expands each generic bit through the file generic mapping and
discards the generic bits before comparing, so duplicate detection, exact
removal, write verification, and rollback verification all converge. Raw and
effective masks stay separate fields on a rule so a caller can still see what
the provider stored.

## Fail-closed write gates

A write proceeds only when every gate passes. A gate that cannot be evaluated
throws rather than defaulting to permit.

| Gate | Rule |
| --- | --- |
| Provider allow-list | The provider name must be exactly `Microsoft Software Key Storage Provider` |
| Provider implementation | `NCryptGetProperty('Impl Type')` on the provider must report the software flag with the hardware, removable, and hardware-random flags clear |
| Key identity | The key must be persistent, non-ephemeral, have a stable unique name, and match the expected provider and key name |
| ACE support | Every candidate ACE must be a plain `AccessAllowed` or `AccessDenied` ACE. A callback, conditional, object, or custom ACE is rejected |
| No new deny | The candidate must not add a deny ACE that the stored DACL does not already contain |
| Critical binding | No HTTP.sys, WinRM HTTPS, Remote Desktop, or Active Directory LDAPS binding may use the same private key |
| Recovery preservation | The candidate must contain a plain allow ACE granting full control to `S-1-5-18` and to `S-1-5-32-544`, and must deny neither |
| Service preservation | Every access the candidate removes or denies must not belong to an identity the current DACL grants and that is `S-1-5-19`, `S-1-5-20`, `S-1-5-80-*`, or `S-1-5-82-*` |
| Optimistic concurrency | With `ConcurrencyToken`, the stored DACL must still match the token the caller received from an earlier read |
| Null DACL | A null DACL is rejected because it grants unrestricted access |

The provider allow-list alone would trust a substituted provider registration,
so the implementation type is confirmed against the provider itself. The
implementation probe was calibrated against live values: the software provider
reports `0x00000022` and the smart card provider reports `0x0000000B`, which
carries the hardware and removable flags.

Two gates exist because a per-account check cannot see them. A deny ACE naming
a group that contains SYSTEM or Administrators locks the key while every
per-SID grant check still passes, so a new deny ACE is refused outright and
`Add-CertificatePrivateKeyAccessRule` exposes no way to create one;
`Remove-CertificatePrivateKeyAccessRule` can still remove a deny ACE that
already exists. A conditional allow ACE parses with an `AccessAllowed`
qualifier but grants nothing when its condition is false, so ACE type rather
than ACE qualifier decides whether an ACE satisfies a required grant, and a
non-plain ACE is refused before that question arises.

## Critical-binding detection

A private-key DACL change can break a running service in a way this module
cannot observe, so a key that serves one of four bindings is refused.

The gate is keyed on the private key, not on the certificate. A renewal that
reuses the key produces a second certificate over the same key while the
binding still names the previous thumbprint, so a thumbprint comparison would
pass while the live key is rewritten. Detection therefore enumerates every
bound thumbprint, resolves each one to its certificate in the local machine
`My`, `WebHosting`, `Remote Desktop`, and `NTDS\My` stores, and compares the
subject public key with the write target's. Two certificates carry the same
public key exactly when they share a private key, and that comparison needs no
key handle. A bound thumbprint that resolves to no stored certificate throws,
because its key cannot be compared.

| Binding | Source |
| --- | --- |
| `HttpSys` | Any 40-character hexadecimal token in `netsh http show sslcert` output. The label text is localized, so the hash is matched by shape rather than by a named field. This covers Internet Information Services, WinRM HTTPS, and self-hosted listeners. A nonzero exit code throws |
| `WinRm` | `CertificateThumbprint` of any listener under `WSMan:\localhost\Listener`, evaluated only while the WinRM service runs because a stopped service cannot serve a listener. A service query that fails for any reason other than the service not existing throws |
| `RemoteDesktop` | `SSLCertificateSHA1Hash` of any `Win32_TSGeneralSetting` instance |
| `DirectoryServices` | A server-authentication certificate in `NTDS\My` or `My` on a machine whose `ProductType` is 2. Active Directory selects an LDAPS certificate itself, so every eligible certificate on a domain controller counts. A certificate without an enhanced key usage extension is valid for every purpose and therefore also counts. Both stores are opened through the .NET store API and must open, because the certificate PSDrive is not present in every runspace |

`Test-CertificatePrivateKeyCriticalBinding` exposes the same detection as a
read-only command, and takes the same certificate the gate takes, so a refusal
can be explained without changing state. There is no override switch; a caller
that must change such a key rebinds or removes the binding first.

## Write boundary

Every mutation resolves one key, acquires the process-wide canonical write lock
for `CertificatePrivateKey:Cng:<Machine|User>:<64 hex characters>`, reads the
current DACL, stages the candidate in memory, runs the gates, writes once, and
reads the stored DACL back. When the stored DACL is not equivalent to the
candidate, or when the write throws, the original descriptor is written back and
the restored DACL is verified. A rollback that cannot be verified raises an
aggregate error that names both failures and states that the stored descriptor
is indeterminate.

A candidate that is already equivalent to the stored DACL is a no-op. It
returns before the critical-binding probe, so reading and reasserting the
current state never fails on a bound certificate. Equivalence compares each ACE
by security identifier, ACE type, effective mask, ACE flags, a digest of any
conditional or callback payload, and any object ACE scope, so a conditional ACE
is never equated with the plain ACE that shares its qualifier and a custom ACE
is never equated with anything.

`Set-CertificatePrivateKeySecurityDescriptor` manages only the access section.
The provider is read and written with `DACL_SECURITY_INFORMATION` alone, so an
owner or group supplied in `Sddl` is dropped before the write rather than
applied. Key ownership cannot be reassigned through this command.

## Verification

Unit tests cover generic-bit expansion, order-insensitive DACL equivalence,
protection-state sensitivity, conditional-ACE distinctness in both the
equivalence test and the recovery gate, rejection of a new deny ACE and
acceptance of an existing one, every recovery and service preservation rule,
service-identity classification, add idempotency across the stored generic
form, deny-ACE ordering, staging a generic right whose mask exceeds a signed
integer, exact removal across the stored generic form, null-DACL rejection, the
live provider implementation values for the software and smart card providers,
rejection of every legacy CAPI provider name and of a case-differing provider
name, server-authentication classification with and without an enhanced key
usage extension, and that two certificates over the same key material are
recognized as one private key while a third is not.

Live acceptance on the disposable machine key covers typed read, add, add
idempotency, exact removal restoring the original SDDL byte for byte, refusal
to remove SYSTEM, refusal of an unsupported provider, `WhatIf` writing nothing,
an exact descriptor set followed by an exact restore, refusal of a new
deny ACE, refusal of a conditional ACE, rejection of a stale concurrency token,
and the absence of a binding for the disposable fixture. Detection of a live
Remote Desktop binding is covered against the machine's own Remote Desktop
certificate.

## See also

- [CNG private-key DACL inspection](0012-cng-private-key-dacl-inspection.md)
- [Enterprise access-control expansion](0008-enterprise-access-control-expansion.md)
- [Security and persistence](0004-security-and-persistence.md)
- [Task and software-key authority decision](decisions/0018-use-local-task-and-software-key-authority.md)
- [Open issues](open-issues.md)
