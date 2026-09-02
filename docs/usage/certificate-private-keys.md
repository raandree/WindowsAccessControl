# Certificate private keys

A certificate is public. What actually needs protecting is the private key
behind it, and the usual failure mode is a service account that cannot read the
key it was issued. This family reads and changes the DACL on a persisted CNG
private key without ever touching key material.

Supported today: an RSA key persisted in **Microsoft Software Key Storage
Provider**. Hardware providers, removable providers, CAPI providers, and
ephemeral keys are outside the contract, as are audit rules, SACLs, owner and
group mutation, and key creation, deletion, or export.

## Two ways to name a key

Every command in this family accepts two selectors:

| Parameter set | Selector | Use it when |
| --- | --- | --- |
| `Certificate` | An exact `X509Certificate2` plus `ProviderName` and `KeyName` | You already hold the certificate |
| `Key` | `ProviderName`, `KeyName`, and `KeyScope` | No certificate is available, as in a restore or a DSC resource |

Both forms resolve the same key, compute the same canonical identity, take the
same write lock, and pass through the same gates.

A certificate thumbprint is **never** a selector. A renewal that reuses the key
produces a new thumbprint over the same key, so a thumbprint lookup would fail
on exactly the key you still mean.

Discover the provider and key name from a certificate you hold:

```powershell
$certificate = Get-Item 'Cert:\LocalMachine\My\0123456789ABCDEF'
$privateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
    GetRSAPrivateKey($certificate)
try {
    $providerName = $privateKey.Key.Provider.Provider
    $keyName      = $privateKey.Key.KeyName
}
finally {
    $privateKey.Dispose()
}
```

The module never disposes a caller-owned certificate, so dispose what you
opened yourself.

## Inspect a key DACL

```powershell
Get-CertificatePrivateKeySecurityDescriptor `
    -Certificate $certificate `
    -ProviderName $providerName `
    -KeyName $keyName

Get-CertificatePrivateKeyAccessRule `
    -ProviderName $providerName `
    -KeyName $keyName `
    -KeyScope Machine
```

The module cross-checks provider and key identity, verifies that a
key-addressed target is an RSA key in the requested machine or user scope, and
reads only the DACL with a silent provider query. No private-key bytes are
returned.

The canonical target is
`CertificatePrivateKey:Cng:<Machine|User>:<64 hex characters>`, where the hash
covers the provider name, the key scope, and the provider's per-machine
container name. It is therefore already computer-scoped, and the resolved
target additionally reports `Server`.

## Grant a service account access

This is the common task: let a workload identity read the key its service
presents.

```powershell
Add-CertificatePrivateKeyAccessRule `
    -Certificate $certificate `
    -ProviderName $providerName `
    -KeyName $keyName `
    -Account 'CONTOSO\WebService' `
    -AccessRights Read `
    -WhatIf
```

Only **allow** rules can be added. Removing an existing rule, including an
existing deny rule, is supported:

```powershell
Remove-CertificatePrivateKeyAccessRule `
    -Certificate $certificate `
    -ProviderName $providerName `
    -KeyName $keyName `
    -Account 'CONTOSO\WebService' `
    -AccessRights Read `
    -WhatIf
```

Write a complete desired DACL when a rule command is too granular:

```powershell
Set-CertificatePrivateKeySecurityDescriptor `
    -ProviderName $providerName `
    -KeyName $keyName `
    -KeyScope Machine `
    -Sddl 'D:P(A;;FA;;;SY)(A;;FA;;;BA)' `
    -WhatIf
```

Only the access section is written. An owner or group in `Sddl` is ignored
rather than applied, because the key's owner and group are never read or
changed.

## Private-key rights

The provider persists a key as a file, so `WindowsCryptoKeyRights` carries the
file access mask:

| Right | Grants |
| --- | --- |
| `Read` | Reading and using the key |
| `Write` | Writing key data and attributes |
| `ReadAndExecute` | Read plus execute |
| `FullControl` | Every right, including permission changes |
| `ReadPermissions`, `ChangePermissions`, `TakeOwnership`, `Delete` | Standard descriptor rights |
| `GenericRead`, `GenericWrite`, `GenericExecute`, `GenericAll` | Generic rights |

`Read` is what a TLS or signing workload needs. Granting `FullControl` lets the
account change the key's permissions, which is rarely intended.

Compare rights after expanding the generic bits. The provider stores a
candidate ACE with the matching generic bit added, so a requested `0x00120089`
reads back as `0x80120089`.

## What a write refuses

The write boundary fails closed. Every one of these refuses the operation, with
no override switch and no restore-only exemption:

| Gate | Refuses when |
| --- | --- |
| Provider allow-list | The provider is not a software-only key storage provider |
| Critical binding | The key serves an HTTP.sys TLS, WinRM HTTPS, Remote Desktop, or Active Directory LDAPS binding |
| Plain-ACE rule | The candidate contains an ACE that is not a plain allow or deny |
| No new deny | The candidate adds a deny ACE |
| Recovery preservation | The result would remove `S-1-5-18` (SYSTEM) or `S-1-5-32-544` (Administrators) |
| Service-grant preservation | The result would remove an existing service grant |
| DACL protection | The candidate's protection state is not acceptable |
| Null DACL | The candidate has no DACL |
| Post-write verification | The stored result does not match what was written; the key is rolled back exactly |

The no-new-deny rule exists because a deny ACE naming a group that contains
SYSTEM or Administrators would lock the key while every per-account grant check
still passed.

## Explain a refusal

`Test-CertificatePrivateKeyCriticalBinding` reports the bindings that would
block a write, without changing anything:

```powershell
Test-CertificatePrivateKeyCriticalBinding -Certificate $certificate
```

It enumerates certificates bound to an HTTP.sys TLS endpoint, a WinRM HTTPS
listener, a Remote Desktop listener, or eligible for Active Directory LDAPS,
and reports those that share a private key with the supplied certificate. The
comparison is by **public key**, not by thumbprint, because a renewal that
reuses the key produces a second certificate over the same key.

If a binding is reported, rebind or remove the binding before changing the
key's DACL.

## Concurrency

The mutators accept the `ConcurrencyToken` from an earlier
`Get-CertificatePrivateKeySecurityDescriptor` result, and reject the write when
the stored DACL changed after that read:

```powershell
$descriptor = Get-CertificatePrivateKeySecurityDescriptor `
    -ProviderName $providerName -KeyName $keyName -KeyScope Machine

Add-CertificatePrivateKeyAccessRule `
    -ProviderName $providerName `
    -KeyName $keyName `
    -KeyScope Machine `
    -Account 'CONTOSO\WebService' `
    -AccessRights Read `
    -ConcurrencyToken $descriptor.ConcurrencyToken `
    -Confirm:$false
```

`Set-CertificatePrivateKeySecurityDescriptor` additionally accepts
`ExpectedCanonicalTarget`, which rejects the write when the provider and key
name now resolve to a different container. That is what a delete and recreate
under the same key name produces.

## Portability

Private-key descriptors join the unified backup as record version 2:

```powershell
Get-CertificatePrivateKeySecurityDescriptor `
    -ProviderName $providerName -KeyName $keyName -KeyScope Machine |
    Backup-WindowsSecurityDescriptor -DestinationPath 'C:\Backup\key.json'

Restore-WindowsSecurityDescriptor `
    -BackupPath 'C:\Backup\key.json' `
    -Confirm:$false
```

Facts worth knowing before you rely on it:

- A record carries the DACL in SDDL form and the selector that relocates the
  key. It never contains certificate or private-key material.
- `CertificateThumbprint` is stored as evidence of which certificate the
  descriptor was captured through. It is empty for a key-addressed read and is
  never used to find a key. A renewal therefore does not invalidate the record.
- A record restores only on the computer named in it. Every computer-scoped
  record is checked before any target is opened.
- The restore needs no extra boundary parameter. Unlike a path-named family, a
  private-key target is pinned by the hash of its own container identity, and
  the write gates are the containment.
- The restore passes through `Set-CertificatePrivateKeySecurityDescriptor`, so
  it fails closed on a key that serves a critical binding, exactly as a direct
  write does.
- Restoring a version-2 record without a verification certificate warns. Sign
  any backup that leaves the computer that produced it.

## Desired state

Two resources manage the private-key DACL. Both address the key without a
certificate, so a MOF never carries a thumbprint that a renewal would
invalidate:

```powershell
WindowsAccessControlCertificatePrivateKeyAccessRule WebServiceRead {
    ProviderName      = 'Microsoft Software Key Storage Provider'
    KeyName           = 'WorkloadKey'
    KeyScope          = 'Machine'
    Account           = 'CONTOSO\WebService'
    AccessRights      = 'Read'
    AccessControlType = 'Allow'
    Ensure            = 'Present'
}
```

`Sections` must be `Access` on the descriptor resource, and
`Ensure = 'Present'` with `AccessControlType = 'Deny'` is refused for the same
reason the write boundary refuses a new deny ACE. See
[Desired State Configuration](dsc.md#certificate-private-key-resources).

## Commands on this page

| Area | Commands |
| --- | --- |
| Descriptors | `Get-CertificatePrivateKeySecurityDescriptor`, `Set-CertificatePrivateKeySecurityDescriptor` |
| Access rules | `Get-CertificatePrivateKeyAccessRule`, `Add-CertificatePrivateKeyAccessRule`, `Remove-CertificatePrivateKeyAccessRule` |
| Diagnostics | `Test-CertificatePrivateKeyCriticalBinding` |

## See also

- [CNG private-key DACL inspection](../../specs/0012-cng-private-key-dacl-inspection.md)
- [CNG private-key DACL mutation](../../specs/0015-cng-private-key-dacl-mutation.md)
- [Certificate private-key portability and desired state](../../specs/0017-certificate-private-key-portability-and-desired-state.md)
