# Verification and traceability

Status: Accepted. This specification defines the evidence levels, requirement
mapping, command coverage, and remaining privileged release gate for
`WindowsAccessControl`.

## Evidence levels

| Level | Meaning |
| --- | --- |
| Unit descriptor | Real in-memory security objects; filesystem persistence is mocked |
| Live NTFS | Real files/directories and descriptor reads or writes on the host NTFS volume |
| Live registry | Disposable local keys and descriptor reads or writes in `HKCU` |
| Live service | Disposable local services plus read-only/no-op SCM descriptor workflows |
| Live process | Controlled child processes pinned by creation identity or caller handles |
| Token integration | Real current-process token inventory or mutation in an isolated process |
| Privilege-gated acceptance | Real SACL or arbitrary-owner workflow, run only when its privilege exists |
| QA | Export, help, analysis, manifest, formatting, specs, and changelog contracts |

An unavailable privilege produces a Pester skip with the exact reason. A skip
is not reported as a successful live write.

## Requirement traceability

| Requirement | Primary executable evidence |
| --- | --- |
| FR-1 | `Get-NTFSAccessRule.Tests.ps1` (Integration and Unit), including direct-parent, original-grandparent, mixed-rule, non-standard-ACE, and explicit-only provenance behavior |
| FR-2 | `New-NTFSAccessRule.Tests.ps1` |
| FR-3 | `Add-NTFSAccessRule.Tests.ps1` |
| FR-4 | `Set-NTFSAccessRule.Tests.ps1` |
| FR-5 | `Remove-NTFSAccessRule.Tests.ps1`, `Clear-NTFSAccessRule.Tests.ps1` |
| FR-6 | Audit-rule Unit tests and `Elevated-WindowsAccessControl.Tests.ps1` |
| FR-7 | Owner Integration tests and elevated arbitrary-owner acceptance |
| FR-8 | Inheritance Integration tests and elevated audit-inheritance acceptance |
| FR-9 | Security-descriptor Get and Copy Integration tests |
| FR-10 | NTFS Backup/Restore tests, cross-family portability tests, SHA-256 and recomputed-digest tamper rejection, X.509 verification, absent-SACL restore, and elevated SACL restore |
| FR-11 | `Resolve-WindowsIdentity.Tests.ps1` and orphan-rule tests |
| FR-12 | `Test-NTFSItemAcl.Tests.ps1` |
| FR-13 | `Get-NTFSItemEffectiveAccess.Tests.ps1` |
| FR-14 | Get/Test/Enable/Disable privilege Integration tests |
| FR-15 | Public command tests and pipeline cases across Integration tests |
| FR-16 | Path/LiteralPath help QA and filesystem-object pipeline tests |
| FR-17 | `MutatorSafety.Tests.ps1` |
| FR-18 | SMB command-contract Unit tests plus disposable share DACL round-trip, add, exact-remove, `WhatIf`, unrelated-ACE preservation, and rollback tests |
| FR-19 | AD command-contract and LDAP-adapter Unit tests plus disposable-OU signed/sealed read, delegated add, object-ACE exact-remove, `WhatIf`, GUID revalidation, and rollback tests |
| NFR-1 | Cross-edition behavior runs and module import QA |
| NFR-2 | Manifest/runtime dependency inspection and static QA |
| NFR-3 | DACL section-preservation and selected-section copy/restore tests |
| NFR-4 | Export/help QA and specification format-view conformance |
| NFR-5 | PSScriptAnalyzer QA and Sampler coverage threshold |
| NFR-6 | Whole-envelope integrity/target prevalidation and duplicate-identity regression tests |
| NFR-7 | `Elevated-WindowsAccessControl.Tests.ps1` explicit skip behavior |
| NFR-8 | Backup schema, no-clobber, malformed-document, and restore tests |
| NFR-9 | Token inventory test and mutator `WhatIf` safety tests |
| NFR-10 | Sampler build, package inspection, changelog QA, and GitVersion config |
| NFR-11 | SMB remote-syntax rejection, explicit Kerberos remoting acceptance, and AD signed/sealed LDAP connection/downgrade tests |
| NFR-12 | SMB special-share rejection, AD allowed-OU/protected-target/GUID mismatch tests, live rollback, cleanup ledger, and independent security review |
| ADR-0013 | Dispatcher Unit tests, family command contracts, live canonical deduplication and metric tests, cross-edition focused runs, and the repeatable NTFS benchmark |
| ADR-0012 | Exact resource schema/orchestration/adapter Unit tests, live five-target convergence, Desktop MOF compilation, and `Invoke-DscResource` acceptance |
| ADR-0012 rule presence | Rule schema/orchestration/adapter Unit tests, live five-target Present/Absent convergence, ten-resource MOF compilation, and Desktop LCM invocation |

## Public command evidence

| Command | Direct specs | Primary boundary | Privilege-gated evidence |
| --- | ---: | --- | --- |
| `Add-NTFSAccessRule` | 5 | Live NTFS | Not required |
| `Add-NTFSAuditRule` | 3 | Unit descriptor | Live SACL add/query |
| `Backup-NTFSItemSecurityDescriptor` | 4 | Live NTFS DACL and aggregate bounded reads | Live SACL backup |
| `Backup-WindowsSecurityDescriptor` | 6 | Live NTFS, registry, service/SCM, and process | SHA-256, X.509, atomic replacement, duplicate rejection, and absent SACL |
| `Clear-NTFSAccessRule` | 1 | Live NTFS | Not required |
| `Clear-NTFSAuditRule` | 1 | Unit descriptor | Live SACL clear |
| `Copy-NTFSItemSecurityDescriptor` | 1 | Live NTFS DACL | Live SACL copy and section preservation |
| `Disable-NTFSItemInheritance` | 1 | Live NTFS DACL | Audit inheritance workflow |
| `Disable-WindowsPrivilege` | 2 | Token integration | Not required |
| `Enable-NTFSItemInheritance` | 2 | Live NTFS DACL | Audit inheritance cleanup |
| `Enable-WindowsPrivilege` | 1 | Token integration | Not required |
| `Get-NTFSAccessRule` | 8 | Live NTFS and Unit | Not required |
| `Get-NTFSAuditRule` | 2 | Unit descriptor | Live SACL add/query |
| `Get-NTFSItemEffectiveAccess` | 1 | Live NTFS Authz | Not required |
| `Get-NTFSItemInheritance` | 1 | Live NTFS DACL | Audit inheritance workflow |
| `Get-NTFSItemOwner` | 3 | Live NTFS plus canonical batch deduplication and prevalidation | Not required; also read back by arbitrary-owner acceptance |
| `Get-NTFSItemSecurityDescriptor` | 1 | Live NTFS DACL | Live SACL backup |
| `Get-WindowsPrivilege` | 1 | Token integration | Not required |
| `New-NTFSAccessRule` | 1 | Unit descriptor | Not required |
| `New-NTFSAuditRule` | 1 | Unit descriptor | Not required |
| `Remove-NTFSAccessRule` | 4 | Live NTFS | Not required |
| `Remove-NTFSAuditRule` | 4 | Unit descriptor | Live SACL set/remove |
| `Resolve-WindowsIdentity` | 1 | Identity Unit | Not required |
| `Restore-NTFSItemSecurityDescriptor` | 5 | Live NTFS DACL and historical schema 1 | Live SACL restore and family isolation |
| `Restore-WindowsSecurityDescriptor` | 7 | Live NTFS, registry, service/SCM, and process | Whole-envelope validation, mixed-signature rejection, and X.509 verification |
| `Set-NTFSAccessRule` | 1 | Live NTFS | Not required |
| `Set-NTFSAuditRule` | 1 | Unit descriptor | Live SACL set/remove |
| `Set-NTFSItemOwner` | 1 | Live current owner | Arbitrary-owner workflow |
| `Test-NTFSItemAcl` | 2 | Live and synthetic DACL | Not required |
| `Test-WindowsPrivilege` | 1 | Token integration | Not required |
| `Get-RegistryKeySecurityDescriptor` | 3 | Live registry plus canonical batch deduplication and metrics | SACL path included in registry acceptance |
| `Set-RegistryKeySecurityDescriptor` | 1 | Live registry | SACL path included in registry acceptance |
| `Get-RegistryKeyAccessRule` | 1 | Live registry | Not required |
| `Add-RegistryKeyAccessRule` | 1 | Live registry | Not required |
| `Set-RegistryKeyAccessRule` | 1 | Live registry | Not required |
| `Remove-RegistryKeyAccessRule` | 1 | Live registry | Not required |
| `Clear-RegistryKeyAccessRule` | 1 | Live registry | Not required |
| `Get-RegistryKeyAuditRule` | 1 | Live registry SACL | Scoped `SeSecurityPrivilege` |
| `Add-RegistryKeyAuditRule` | 1 | Live registry SACL | Scoped `SeSecurityPrivilege` |
| `Set-RegistryKeyAuditRule` | 2 | Live registry SACL | Scoped `SeSecurityPrivilege` |
| `Remove-RegistryKeyAuditRule` | 1 | Live registry SACL | Scoped `SeSecurityPrivilege` |
| `Clear-RegistryKeyAuditRule` | 2 | Live registry SACL | Scoped `SeSecurityPrivilege` |
| `Get-RegistryKeyInheritance` | 1 | Live registry | Access and audit state |
| `Enable-RegistryKeyInheritance` | 1 | Live registry | Access and audit state |
| `Disable-RegistryKeyInheritance` | 1 | Live registry | Access and audit state |
| `Get-ServiceSecurityDescriptor` | 2 | Live service and SCM | Named service plus SCM handle reads |
| `Set-ServiceSecurityDescriptor` | 2 | Live service and SCM | DACL round trip and `WhatIf` |
| `Get-ServiceAccessRule` | 2 | Live service and SCM | Typed domain-right outputs |
| `Add-ServiceAccessRule` | 1 | Live service | Not required |
| `Set-ServiceAccessRule` | 1 | Live service | Opposite qualifier preservation |
| `Remove-ServiceAccessRule` | 1 | Live service | Not required |
| `Clear-ServiceAccessRule` | 1 | Live service | Not required |
| `Get-ServiceAuditRule` | 1 | Live service SACL | Scoped `SeSecurityPrivilege` |
| `Add-ServiceAuditRule` | 1 | Live service SACL | Scoped `SeSecurityPrivilege` |
| `Set-ServiceAuditRule` | 1 | Live service SACL | Audit-flag isolation |
| `Remove-ServiceAuditRule` | 1 | Live service SACL | Scoped `SeSecurityPrivilege` |
| `Clear-ServiceAuditRule` | 1 | Live service SACL | Scoped `SeSecurityPrivilege` |
| `Get-ProcessSecurityDescriptor` | 4 | Live process | Process, PID, module output, and handle targets |
| `Set-ProcessSecurityDescriptor` | 2 | Live process | Pinned and caller-handle no-op round trips |
| `Get-ProcessAccessRule` | 1 | Live process | Typed process rights |
| `Add-ProcessAccessRule` | 1 | Live process | Not required |
| `Set-ProcessAccessRule` | 1 | Live process | Opposite qualifier preservation |
| `Remove-ProcessAccessRule` | 1 | Live process | Exact native ACE removal |
| `Clear-ProcessAccessRule` | 1 | Live process | Account-scoped clear |
| `Get-ProcessAuditRule` | 1 | Live process SACL | Scoped `SeSecurityPrivilege` |
| `Add-ProcessAuditRule` | 1 | Live process SACL | Scoped `SeSecurityPrivilege` |
| `Set-ProcessAuditRule` | 1 | Live process SACL | Audit-flag isolation |
| `Remove-ProcessAuditRule` | 1 | Live process SACL | Exact native ACE removal |
| `Clear-ProcessAuditRule` | 1 | Live process SACL | Scoped `SeSecurityPrivilege` |
| `Get-WindowsAccessControlMetric` | 1 | Thread-safe aggregate snapshot Unit test | Redacted output contract |
| `Get-SmbShareSecurityDescriptor` | 1 | Disposable local share DACL plus canonical deduplication | Remote and special-share rejection |
| `Set-SmbShareSecurityDescriptor` | 1 | Disposable local share DACL no-op/rollback | `WhatIf`, section and description preservation |
| `Get-SmbShareAccessRule` | 1 | Disposable local share native ACE enumeration | Typed mask and unrelated-ACE preservation |
| `Add-SmbShareAccessRule` | 1 | Disposable local share delegated add | `WhatIf`, exact mask, metadata preservation |
| `Remove-SmbShareAccessRule` | 1 | Disposable local share exact native removal | Canonical target validation and rollback |
| `Get-ADObjectSecurityDescriptor` | 1 | Signed/sealed LDAP disposable-OU read | Explicit DC and immutable GUID binding |
| `Set-ADObjectSecurityDescriptor` | 1 | Delegated disposable-OU DACL round trip | `WhatIf`, allowed-OU and protected-target rejection |
| `Get-ADObjectAccessRule` | 1 | Common/object ACE enumeration in disposable OU | GUID and inheritance preservation |
| `Add-ADObjectAccessRule` | 1 | Delegated object-specific ACE add | Non-Domain-Admin, idempotence, prevalidation, rollback |
| `Remove-ADObjectAccessRule` | 1 | Exact object-ACE removal | GUID revalidation and stale-target rejection |

Cross-cutting checks add Unit-level mutator `WhatIf` specifications in
`tests/Unit/MutatorSafety.Tests.ps1` and the QA specification contract in
`tests/QA/Specifications.Tests.ps1`.

## Evidence records

The durable contract defines required evidence levels and release gates, not a
fixed test-run snapshot. Current run counts and review outcomes are recorded in
`.memory-bank/progress.md`, while executable artifacts are written under
`output/testResults`. The build enforces an 80 percent merged-module coverage
threshold.

`NtfsBatchPermissions.Tests.ps1` proves canonical wildcard/explicit-path
deduplication, metric deltas, complete prevalidation before dispatch, bounded
multi-target mutation, and parallel `WhatIf` safety.
`Invoke-WindowsAccessControlBatch.Tests.ps1` proves bounded overlap,
single-throttle ordering, independent target failure, canonical deduplication,
consistent nonterminating-error metrics, single-target behavior, and
cross-module write serialization. The same focused gate runs under PowerShell
7 and Windows PowerShell 5.1.

`tests/Performance/Measure-NtfsBatchPerformance.ps1` measures alternating
sequential and bounded-parallel NTFS owner reads over disposable targets. It
emits elapsed time and throughput plus optional JSON evidence without a flaky
hard timing assertion.

## Exact descriptor DSC evidence

`ExactSecurityDescriptorResourceContract.Tests.ps1` verifies five manifest
exports, `Get-DscResource` discovery, composite keys, mandatory SDDL, and
read-only prefixed reasons. `ExactSecurityDescriptorResource.Tests.ps1` covers
class orchestration and canonical mismatch reasons in PowerShell 7. Private
adapter tests cover every object-family route in both editions.

`ExactSecurityDescriptorDscResources.Tests.ps1` reconverges disposable NTFS
and HKCU DACLs, reconverges all NTFS sections including explicit absent-SACL
state, then exercises named-service, SCM, and pinned-process exact query paths
over real descriptors in both editions. Unit tests reject omitted selected
owner, group, DACL, and SACL data and cover present/absent combined protection.
Desktop-only LCM evidence compiles all five resources into one MOF and invokes
the all-section NTFS resource through `Invoke-DscResource`. The fixture installs
the discovered module version machine-wide only for the test, refuses
collisions, and removes the installation afterward.

## Access-rule presence DSC evidence

`AccessRulePresenceResourceContract.Tests.ps1` verifies the public Ensure enum,
five resource exports, typed composite keys, default `Present`, and read-only
reasons. Class tests cover compliance reasons and adapter routing. Adapter tests
cover all five families, exact mask/qualifier/scope matching, inherited-rule
rejection, idempotence, duplicate removal, and unsigned high-bit rights.

`AccessRulePresenceDscResources.Tests.ps1` converges `Present` and `Absent` on
disposable NTFS, HKCU, and named-service targets, then performs SCM and pinned
process convergence with exact DACL rollback in `finally`. The Desktop LCM gate
compiles all ten class resources into one MOF and invokes NTFS rule add/remove
through `Invoke-DscResource`, restoring the original DACL afterward.

## Privileged release evidence

The elevated acceptance suite enables privileges already present in its
isolated process token, restores their original state, and retains NUnit
evidence. Seven live scenarios cover:

1. Add and query a real SACL rule.
2. Replace and remove a real SACL rule.
3. Clear multiple real SACL rules.
4. Remove explicit SACL rules while enabling audit inheritance.
5. Back up and restore a real SACL.
6. Copy only a real SACL while preserving owner, group, and DACL state.
7. Assign an arbitrary owner with `SeRestorePrivilege`.

The complete suite passed with seven tests, zero failures, and zero skips in
separate elevated PowerShell 7 and Windows PowerShell 5.1 processes on
2026-07-25. Release validation must rerun the same file from a suitably
privileged isolated process rather than treating historical evidence as a
substitute for the current package.

## Registry evidence

`RegistryKeyPermissions.Tests.ps1` uses a disposable hierarchy under `HKCU`
and removes it after the run. Sixteen live scenarios cover selected descriptor
round trips, access and audit add/set/remove/clear, exact pipeline removal,
access and audit inheritance, explicit registry views, provider-object input,
native and object-based remote-target rejection, audit-flag isolation, and
absent-SACL preservation under a matchless clear, and `WhatIf`.

The registry suite and 15 exact-name command-contract tests passed with 31
tests, zero failures, and zero skips in separate PowerShell 7 and Windows
PowerShell 5.1 processes on 2026-07-25.

## Service evidence

`ServicePermissions.Tests.ps1` creates a unique local service for each live
case and deletes it in `AfterEach` plus a final leak-cleanup pass. Thirteen
scenarios cover named-service and SCM descriptors, ServiceController pipeline
input, display-name and remote-controller rejection, typed service/SCM rights,
access/audit add/set/remove/clear, qualifier isolation, audit-flag isolation,
`WhatIf`, and the explicit SCM target.

The service suite passed with 13 tests, zero failures, and zero skips in
separate PowerShell 7 and Windows PowerShell 5.1 processes on 2026-07-25.

## Process evidence

`ProcessPermissions.Tests.ps1` starts a controlled sleeping child process for
each live case and terminates it in `AfterEach` plus a final cleanup sweep.
Fourteen scenarios cover Process/PID/module/handle targeting, stale creation
identity rejection, caller-handle reuse, descriptor round trips, typed process
rights, access/audit add/set/remove/clear, qualifier isolation, audit-flag
isolation, and `WhatIf`.

The process suite passed with 14 tests, zero failures, and zero skips in
separate PowerShell 7 and Windows PowerShell 5.1 processes on 2026-07-25.

## See also

- [Requirements](0002-requirements.md)
- [Open issues](open-issues.md)
- [Elevated acceptance tests](../tests/Integration/Elevated-WindowsAccessControl.Tests.ps1)
