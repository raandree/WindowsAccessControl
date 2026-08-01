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
| Service preservation | Every access the candidate removes or denies must not belong to an identity the current DACL grants and that is `S-1-5-19`, `S-1-5-20`, `S-1-5-80-*`, or `S-1-5-82-*`. An inherit-only ACE grants nothing and is ignored on both sides |
| DACL protection | The candidate's protected state must match the stored DACL, because the provider writes `DACL_SECURITY_INFORMATION` alone and cannot change it |
| Optimistic concurrency | The stored DACL must still match a concurrency token. `Add` and `Remove` derive one from their own read, so a change made between that read and the write is rejected rather than overwritten. `ConcurrencyToken` replaces it with the caller's earlier read |
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
bound thumbprint, resolves each one to its certificate, and compares the
subject public key with the write target's. Two certificates carry the same
public key exactly when they share a private key, and that comparison needs no
key handle.

Resolution searches every local machine certificate store that exists, which is
discovered from the three registry roots the local machine store location is
composed from, plus the `NTDS` service store. The stores a binding names in
practice are searched first and the search stops once every bound thumbprint is
resolved. A fixed store list would leave a binding created against any other
machine store unresolvable, and an unresolvable bound thumbprint throws, because
its key cannot be compared. That refusal is global: it blocks every private-key
write on the machine until the stale binding is removed or the certificate is
restored. Failing closed is deliberate, so the resolution set is kept wide
enough that a certificate in a machine store is always found. A certificate held
only in a user store, or in a service store other than `NTDS`, is outside the
set and reaches the refusal.

| Binding | Source |
| --- | --- |
| `HttpSys` | Any 40-character hexadecimal token in `netsh http show sslcert` output. The label text is localized, so the hash is matched by shape rather than by a named field, which over-matches rather than missing a binding. This covers Internet Information Services, WinRM HTTPS, and self-hosted listeners. A nonzero exit code throws |
| `WinRm` | `CertificateThumbprint` of any listener under `WSMan:\localhost\Listener`, evaluated only while the WinRM service runs because a stopped service cannot serve a listener. Only a `ServiceCommandException` from the service query skips the branch; every other failure throws. A WinRM HTTPS listener also appears under `HttpSys`, so the branch is corroborating rather than sole coverage |
| `RemoteDesktop` | `SSLCertificateSHA1Hash` of any `Win32_TSGeneralSetting` instance |
| `DirectoryServices` | A server-authentication certificate in the `NTDS` service store or the local machine `My` store on a machine whose `ProductType` is 2. Active Directory selects an LDAPS certificate itself, so every eligible certificate on a domain controller counts. A certificate without an enhanced key usage extension is valid for every purpose and therefore also counts. The `My` store is opened through the .NET store API and must open. The `NTDS` store is a service store, which `StoreLocation` cannot address, so it is opened natively under `CERT_SYSTEM_STORE_SERVICES`; it is absent on a domain controller that keeps its certificate in `My`, and an absent store yields nothing while a store that exists and cannot be opened, or cannot be enumerated to completion, throws rather than returning a truncated list |

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
current state never fails on a bound certificate. Allow ACEs are additive, so a
DACL of allow ACEs written in a different order is the same state and is also a
no-op. A candidate that reorders the stored ACEs while a deny ACE is present is
neither a no-op nor a write: it is refused, because order then decides the
access check, the provider decides the stored order, and the write could not be
verified. ACE order is therefore not a property this contract manages.
Verification after a write and after a rollback compares the ACE keys as an
unordered multiset. An ACE key covers the security identifier, ACE type,
effective mask, ACE flags, a digest of any conditional or callback payload, and
any object ACE scope, so a conditional ACE is never equated with the plain ACE
that shares its qualifier and a custom ACE is never equated with anything.

`Remove-CertificatePrivateKeyAccessRule` matches rights exactly, so removing
`Read` from an account that holds `FullControl` matches nothing. Every account
the request did not match is named in a warning, including when the same request
matched another account, because a revocation that removed nothing must not look
like one that succeeded.

`Set-CertificatePrivateKeySecurityDescriptor` manages only the access section.
The provider is read and written with `DACL_SECURITY_INFORMATION` alone, so an
owner or group supplied in `Sddl` is dropped before the write rather than
applied. Key ownership cannot be reassigned through this command.

## Verification

Unit tests cover generic-bit expansion, order-insensitive DACL equivalence and
the ordered desired-state comparison, protection-state sensitivity,
conditional-ACE distinctness in both the equivalence test and the recovery
gate, rejection of a new deny ACE and acceptance of an existing one, every
recovery and service preservation rule including a denied SYSTEM, a denied
service identity, and an inherit-only service ACE that must not block an exact
reassert, service-identity classification, add idempotency across the stored
generic form, deny-ACE ordering, staging a generic right whose mask exceeds a
signed integer, exact removal across the stored generic form, the warning a
removal raises naming every account it did not match, the concurrency token
`Add` and `Remove` derive from their own read, null-DACL rejection, rejection of
a protection-state change before any provider write, refusal of a candidate that
reorders the stored ACEs while a deny ACE is present, acceptance of an
allow-only reordering as already converged, the no-op short circuit reaching
neither the binding gate nor the provider, the live provider implementation
values for the software and smart card providers, rejection of every legacy CAPI
provider name and of a case-differing provider name, server-authentication
classification with and without an enhanced key usage extension, that two
certificates over the same key material are recognized as one private key while
a third is not, discovery of the local machine stores that exist and their
search order, a service store that cannot be opened yielding nothing, an empty
service store yielding nothing rather than an error, reading every certificate
from a service store that does exist, no store being enumerated when no binding
exists, the refusal raised by an unresolvable bound thumbprint, a store-root
failure not being swallowed while resolving a binding, and resolution of a bound
thumbprint through the `NTDS` service store. A forced enumeration failure is
deliberately not tested, because the only way to force one would be a
fault-injection seam in the native code of a fail-closed gate.

Live acceptance on the disposable machine key covers typed read, add, add
idempotency, exact removal restoring the original SDDL byte for byte, refusal
to remove SYSTEM, refusal of an unsupported provider, `WhatIf` writing nothing,
an exact descriptor set followed by an exact restore, refusal of a new
deny ACE, refusal of a conditional ACE, rejection of a stale concurrency token,
and the absence of a binding for the disposable fixture. Binding detection is
proven by a deterministic HTTP.sys cycle that binds a disposable certificate,
refuses the write while the binding is live, releases the binding, and then
permits the write. The Remote Desktop, WinRM, and directory-service sources are
not exercised live, because each depends on machine state the fixture cannot
create without changing a running listener; the suite asserts only that the
Remote Desktop source is readable. On a domain controller the live suite proves
that the `NTDS` service store enumerates without error, reports how many
certificates each directory store holds, and confirms that the read-only binding
command reports a directory-service binding naming the store it came from, which
is the same detection the write gate uses. Which of the two stores holds the
certificate depends on how it was enrolled, so that is reported rather than
asserted.

## See also

- [CNG private-key DACL inspection](0012-cng-private-key-dacl-inspection.md)
- [Enterprise access-control expansion](0008-enterprise-access-control-expansion.md)
- [Security and persistence](0004-security-and-persistence.md)
- [Task and software-key authority decision](decisions/0018-use-local-task-and-software-key-authority.md)
- [Open issues](open-issues.md)
