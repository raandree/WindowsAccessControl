# Reject CAPI private keys at the provider boundary

- Status: Accepted
- Date: 2026-08-01
- Deciders: user, software-engineer agent

## Context and problem statement

Open issue `OI-23` assumed that a Certificate Application Programming Interface
(CAPI) private key exposes a separate identity, handle, and descriptor surface
that the module must probe and then implement, in both PowerShell editions.
`KEY-1` requires a cross-edition capability matrix before any of that is built.

Live probes were run against a machine key created through `certreq` with
`ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"` and
`ProviderType = 1`, in Windows PowerShell 5.1 and PowerShell 7.6.3 on the same
host.

| Observation | Windows PowerShell 5.1 | PowerShell 7.6.3 |
| --- | --- | --- |
| `RSACertificateExtensions.GetRSAPrivateKey` returns | `RSACng` | `RSACng` |
| `CngKey.Provider.Provider` | `Microsoft Enhanced Cryptographic Provider v1.0` | same |
| `CngKey.KeyName` | the CAPI container name | same |
| `CngKey.UniqueName` | the same container file name in both editions | same |
| `CngKey.GetProperty('Security Descr')` | `Key not valid for use in specified state` | same |
| `Get-CertificatePrivateKeySecurityDescriptor` with the reported provider | `NotSupportedException` | same |
| The same call with the CNG provider name substituted | `InvalidOperationException` | same |
| `Add-CertificatePrivateKeyAccessRule` | `NotSupportedException` | same |

Four facts follow.

1. The premise of a separate managed CAPI object is wrong on current Windows.
   Both editions route a legacy CSP key through the CNG legacy bridge and hand
   back `RSACng`. `RSACryptoServiceProvider` and its `CspKeyContainerInfo` and
   `CryptoKeySecurity` members were never reached.
2. The bridge does not hide the provider. `CngKey.Provider.Provider` reports
   the CAPI provider name faithfully, so the existing allow-list already
   separates a CAPI key from a CNG software key without any new detection.
3. The bridge cannot serve the descriptor. `NCryptGetProperty('Security Descr')`
   on a bridged CAPI key fails, so reusing the CNG descriptor path for CAPI is
   not merely unsupported, it does not function.
4. Substituting the CNG provider name to bypass the allow-list fails on the
   subsequent identity check, so the boundary is not name-dependent.

Reading or writing a CAPI key descriptor therefore requires the separate legacy
surface (`CryptAcquireContext` plus `CryptGetProvParam`/`CryptSetProvParam` with
`PP_KEYSET_SEC_DESCR`). That is a second native provider, a second handle
lifetime, a second rights model, and a second set of fail-closed gates, none of
which the current probes justify.

## Decision

- Reject CAPI private keys at the provider boundary and keep the rejection in
  both supported PowerShell editions.
- Do not implement CAPI identity, handle, descriptor, or mutation support in
  this roadmap, and do not infer a CAPI key-file path from a CNG unique name.
- Retain the cross-edition probe result above as the capability matrix that
  `KEY-1` requires for CAPI.
- Keep a regression test that a certificate whose key reports a CAPI provider is
  refused, and that substituting the supported provider name is refused by the
  identity check rather than admitted.

## Consequences

- `OI-23` narrows to the closed and tested rejection boundary. Its
  implementation half is withdrawn rather than left open, because the surface it
  assumed does not exist.
- A caller that must manage a CAPI key uses the in-box tooling for that provider.
  The module states the boundary instead of partially emulating it.
- If a future Windows release stops bridging CSP keys through CNG, the
  rejection still holds: an unrecognized provider name is refused before any
  key operation.

## See also

- [CNG private-key DACL mutation](../0015-cng-private-key-dacl-mutation.md)
- [CNG private-key DACL inspection](../0012-cng-private-key-dacl-inspection.md)
- [Enterprise access-control expansion](../0008-enterprise-access-control-expansion.md)
