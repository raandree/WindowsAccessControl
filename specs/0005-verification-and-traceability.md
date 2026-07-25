# Verification and traceability

Status: Accepted. This specification defines the evidence levels, requirement
mapping, command coverage, and remaining privileged release gate for
`NTFSPermission`.

## Evidence levels

| Level | Meaning |
| --- | --- |
| Unit descriptor | Real in-memory security objects; filesystem persistence is mocked |
| Live NTFS | Real files/directories and descriptor reads or writes on the host NTFS volume |
| Token integration | Real current-process token inventory or mutation in an isolated process |
| Privilege-gated acceptance | Real SACL or arbitrary-owner workflow, run only when its privilege exists |
| QA | Export, help, analysis, manifest, formatting, specs, and changelog contracts |

An unavailable privilege produces a Pester skip with the exact reason. A skip
is not reported as a successful live write.

## Requirement traceability

| Requirement | Primary executable evidence |
| --- | --- |
| FR-1 | `Get-NTFSAccessRule.Tests.ps1` (Integration and Unit) |
| FR-2 | `New-NTFSAccessRule.Tests.ps1` |
| FR-3 | `Add-NTFSAccessRule.Tests.ps1` |
| FR-4 | `Set-NTFSAccessRule.Tests.ps1` |
| FR-5 | `Remove-NTFSAccessRule.Tests.ps1`, `Clear-NTFSAccessRule.Tests.ps1` |
| FR-6 | Audit-rule Unit tests and `Elevated-NTFSPermission.Tests.ps1` |
| FR-7 | Owner Integration tests and elevated arbitrary-owner acceptance |
| FR-8 | Inheritance Integration tests and elevated audit-inheritance acceptance |
| FR-9 | Security-descriptor Get and Copy Integration tests |
| FR-10 | Backup and Restore Integration tests plus elevated SACL restore |
| FR-11 | `Resolve-NTFSIdentity.Tests.ps1` and orphan-rule tests |
| FR-12 | `Test-NTFSItemAcl.Tests.ps1` |
| FR-13 | `Get-NTFSItemEffectiveAccess.Tests.ps1` |
| FR-14 | Get/Test/Enable/Disable privilege Integration tests |
| FR-15 | Public command tests and pipeline cases across Integration tests |
| FR-16 | Path/LiteralPath help QA and filesystem-object pipeline tests |
| FR-17 | `MutatorSafety.Tests.ps1` |
| NFR-1 | Cross-edition behavior runs and module import QA |
| NFR-2 | Manifest/runtime dependency inspection and static QA |
| NFR-3 | DACL section-preservation and selected-section copy/restore tests |
| NFR-4 | Export/help QA and specification format-view conformance |
| NFR-5 | PSScriptAnalyzer QA and Sampler coverage threshold |
| NFR-6 | Restore prevalidation and duplicate-identity regression tests |
| NFR-7 | `Elevated-NTFSPermission.Tests.ps1` explicit skip behavior |
| NFR-8 | Backup schema, no-clobber, malformed-document, and restore tests |
| NFR-9 | Token inventory test and mutator `WhatIf` safety tests |
| NFR-10 | Sampler build, package inspection, changelog QA, and GitVersion config |

## Public command evidence

| Command | Direct specs | Primary boundary | Privilege-gated evidence |
| --- | ---: | --- | --- |
| `Add-NTFSAccessRule` | 5 | Live NTFS | Not required |
| `Add-NTFSAuditRule` | 3 | Unit descriptor | Live SACL add/query |
| `Backup-NTFSItemSecurityDescriptor` | 3 | Live NTFS DACL | Live SACL backup |
| `Clear-NTFSAccessRule` | 1 | Live NTFS | Not required |
| `Clear-NTFSAuditRule` | 1 | Unit descriptor | Live SACL clear |
| `Copy-NTFSItemSecurityDescriptor` | 1 | Live NTFS DACL | Live SACL copy and section preservation |
| `Disable-NTFSItemInheritance` | 1 | Live NTFS DACL | Audit inheritance workflow |
| `Disable-NTFSPrivilege` | 2 | Token integration | Not required |
| `Enable-NTFSItemInheritance` | 2 | Live NTFS DACL | Audit inheritance cleanup |
| `Enable-NTFSPrivilege` | 1 | Token integration | Not required |
| `Get-NTFSAccessRule` | 2 | Live NTFS and Unit | Not required |
| `Get-NTFSAuditRule` | 2 | Unit descriptor | Live SACL add/query |
| `Get-NTFSItemEffectiveAccess` | 1 | Live NTFS Authz | Not required |
| `Get-NTFSItemInheritance` | 1 | Live NTFS DACL | Audit inheritance workflow |
| `Get-NTFSItemOwner` | 1 | Live NTFS | Not required; also read back by arbitrary-owner acceptance |
| `Get-NTFSItemSecurityDescriptor` | 1 | Live NTFS DACL | Live SACL backup |
| `Get-NTFSPrivilege` | 1 | Token integration | Not required |
| `New-NTFSAccessRule` | 1 | Unit descriptor | Not required |
| `New-NTFSAuditRule` | 1 | Unit descriptor | Not required |
| `Remove-NTFSAccessRule` | 4 | Live NTFS | Not required |
| `Remove-NTFSAuditRule` | 4 | Unit descriptor | Live SACL set/remove |
| `Resolve-NTFSIdentity` | 1 | Identity Unit | Not required |
| `Restore-NTFSItemSecurityDescriptor` | 4 | Live NTFS DACL | Live SACL restore |
| `Set-NTFSAccessRule` | 1 | Live NTFS | Not required |
| `Set-NTFSAuditRule` | 1 | Unit descriptor | Live SACL set/remove |
| `Set-NTFSItemOwner` | 1 | Live current owner | Arbitrary-owner workflow |
| `Test-NTFSItemAcl` | 2 | Live and synthetic DACL | Not required |
| `Test-NTFSPrivilege` | 1 | Token integration | Not required |

The direct command total is 50 specifications across 28 exported commands.
Cross-cutting checks add 17 Unit-level mutator `WhatIf` specifications in
`tests/Unit/MutatorSafety.Tests.ps1` and the QA specification contract in
`tests/QA/Specifications.Tests.ps1`.

## Evidence records

The durable contract defines required evidence levels and release gates, not a
fixed test-run snapshot. Current run counts and review outcomes are recorded in
`.memory-bank/progress.md`, while executable artifacts are written under
`output/testResults`. The build enforces an 80 percent merged-module coverage
threshold.

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

## See also

- [Requirements](0002-requirements.md)
- [Open issues](open-issues.md)
- [Elevated acceptance tests](../tests/Integration/Elevated-NTFSPermission.Tests.ps1)
