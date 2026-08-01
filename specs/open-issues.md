# Open issues

This register tracks agreed validation gaps and deferred extensions to the
accepted specifications. When an item ships, remove it here and record the
change in `CHANGELOG.md`. Rejected out-of-scope ideas remain in the research
note rather than this list.

## OI-27: Merge domain-lab coverage into the threshold gate

Specification: 0005. Decision: ADR 0025.

The 80 percent threshold is red at 78.61 percent because the default Pester
profile cannot execute the Active Directory, certificate private-key, and SMB
share families; those three account for 48.3 percent of all missed commands,
and the measurable surface is at 85.7 percent. Excluding them is not possible
because ModuleBuilder emits one merged file.

Make `Invoke-WindowsAccessControlDomainLabAcceptance` collect code coverage,
carry the JaCoCo file back to the repository host, and enable Sampler's
`Merge_CodeCoverage_Files` task so the threshold is asserted over the merged
result. Do not lower the threshold and do not add synthetic unit tests over code
the live suites already exercise.

## OI-23: Add CAPI private-key capability and mutation

Specification: 0008. Tasks: KEY-1 to KEY-4 and KEY-7.

`KEY-1` is complete for CAPI and the rejection boundary is closed and tested in
both PowerShell editions. ADR 0024 records the cross-edition probe: current
Windows routes a legacy CSP key through the CNG legacy bridge, so the separate
managed CAPI object this issue assumed is never returned, the bridge still
reports the CAPI provider name, and the bridged key cannot serve a descriptor at
all. The implementation half is withdrawn.

What remains is a deliberate non-goal rather than open work. Reopen this issue
only with a concrete requirement for the legacy `CryptAcquireContext` plus
`PP_KEYSET_SEC_DESCR` surface, which needs its own handle lifetime, rights
model, and fail-closed gates. Do not infer CAPI key-file paths or reuse CNG
assumptions.

## OI-24: Add private-key portability and desired state

Specification: 0008. Tasks: KEY-5 and KEY-6.

Specification 0015 delivered the safe typed mutation this issue waits for, so
the work is now unblocked. It has not started.

Three constraints are already established by evidence and must shape the design
rather than be rediscovered:

- The canonical key identity hashes the provider unique name, which is a
  per-machine container file name. A record is therefore computer-scoped like
  the Task Scheduler and SMB families, and must carry `Server` at record
  version 2.
- A record cannot carry the certificate, so restore has to relocate the key.
  The only stable selector is the provider name plus the persisted key name;
  the certificate thumbprint changes on renewal with key reuse, so it can be
  recorded as evidence but must not be the lookup key.
- Restore and any desired-state resource must pass through the specification
  0015 write boundary, so they inherit the software-only provider gate, the
  key-keyed critical-binding refusal, the plain-ACE and no-new-deny rules, and
  the recovery and service preservation gates. None of those may be bypassed
  for a restore.

Never store certificate or private-key material in portability records.

## See also

- [Specification index](README.md)
- [NTFSSecurity comparison](../docs/research.md#detailed-ntfssecurity-comparison)
