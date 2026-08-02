# Open issues

This register tracks agreed validation gaps and deferred extensions to the
accepted specifications. When an item ships, remove it here and record the
change in `CHANGELOG.md`. Rejected out-of-scope ideas remain in the research
note rather than this list.

## OI-23: Add CAPI private-key capability and mutation

Specification: 0008. Tasks: KEY-1 to KEY-4 and KEY-7.

`KEY-1` is complete for CAPI and the rejection boundary is closed and tested in
both PowerShell editions. ADR 0024 records the cross-edition probe: current
Windows routes a legacy CSP key through the CNG legacy bridge, so the separate
managed CAPI object this issue assumed is never returned, the bridge still
reports the CAPI provider name, and the bridged key cannot serve a descriptor at
all. The implementation half is withdrawn.

Only reopen this issue with a concrete requirement for the legacy
`CryptAcquireContext` plus `PP_KEYSET_SEC_DESCR` surface, which needs its own
handle lifetime, rights model, and fail-closed gates. Do not infer CAPI key-file
paths or reuse CNG assumptions.

## See also

- [Specification index](README.md)
- [NTFSSecurity comparison](../docs/research.md#detailed-ntfssecurity-comparison)
