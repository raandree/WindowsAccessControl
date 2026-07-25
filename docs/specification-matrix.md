# Specification matrix

This matrix records the executable behavior specifications for the public
module contract. Counts are direct `It` blocks in test files named for each
command; cross-cutting quality and safety specifications are listed separately.

## Command specifications

| Command | Direct specs | Boundary | Privilege-gated coverage |
| --- | ---: | --- | --- |
| `Add-NTFSAccessRule` | 5 | Live NTFS | Not required |
| `Add-NTFSAuditRule` | 3 | Unit descriptor | Live SACL workflow |
| `Backup-NTFSItemSecurityDescriptor` | 3 | Live NTFS DACL | Live SACL backup |
| `Clear-NTFSAccessRule` | 1 | Live NTFS | Not required |
| `Clear-NTFSAuditRule` | 1 | Unit descriptor | Live SACL workflow |
| `Copy-NTFSItemSecurityDescriptor` | 1 | Live NTFS DACL | Not yet added for SACL copy |
| `Disable-NTFSItemInheritance` | 1 | Live NTFS DACL | Live audit inheritance |
| `Disable-NTFSPrivilege` | 2 | Live process token | Not required |
| `Enable-NTFSItemInheritance` | 2 | Live NTFS DACL | Live audit inheritance cleanup |
| `Enable-NTFSPrivilege` | 1 | Live process token | Not required |
| `Get-NTFSAccessRule` | 2 | Live NTFS and unit | Not required |
| `Get-NTFSAuditRule` | 2 | Unit descriptor | Live SACL workflow |
| `Get-NTFSItemEffectiveAccess` | 1 | Live NTFS Authz | Not required |
| `Get-NTFSItemInheritance` | 1 | Live NTFS DACL | Live audit inheritance |
| `Get-NTFSItemOwner` | 1 | Live NTFS | Not required |
| `Get-NTFSItemSecurityDescriptor` | 1 | Live NTFS DACL | Live SACL backup |
| `Get-NTFSPrivilege` | 1 | Live process token | Not required |
| `New-NTFSAccessRule` | 1 | In-memory unit | Not required |
| `New-NTFSAuditRule` | 1 | In-memory unit | Not required |
| `Remove-NTFSAccessRule` | 4 | Live NTFS | Not required |
| `Remove-NTFSAuditRule` | 4 | Unit descriptor | Live SACL workflow |
| `Resolve-NTFSIdentity` | 1 | Identity unit | Not required |
| `Restore-NTFSItemSecurityDescriptor` | 4 | Live NTFS DACL | Live SACL restore |
| `Set-NTFSAccessRule` | 1 | Live NTFS | Not required |
| `Set-NTFSAuditRule` | 1 | Unit descriptor | Live SACL workflow |
| `Set-NTFSItemOwner` | 1 | Live NTFS current owner | Arbitrary owner with `SeRestorePrivilege` |
| `Test-NTFSItemAcl` | 2 | Live and synthetic NTFS DACL | Not required |
| `Test-NTFSPrivilege` | 1 | Live process token | Not required |

The direct command total is 50 specifications across 28 exported commands.
Every export has at least one behavior specification.

## Cross-cutting specifications

- Public quality tests require a test file, clean PSScriptAnalyzer result,
  synopsis, description, example, and complete parameter help for every export.
- Seventeen mutator safety specifications verify that `WhatIf` performs no
  descriptor or token mutation.
- Restore specifications cover all-record prevalidation, schema rejection,
  missing and duplicate targets, item-type mismatch, and malformed SDDL.
- Six elevated acceptance specifications exercise real SACL CRUD, audit
  inheritance cleanup, SACL backup and restore, and arbitrary-owner assignment.

## Live-test interpretation

`Live NTFS` means the test creates files or directories on the host NTFS
volume and reads or persists their actual security descriptors. `Unit
descriptor` means Pester substitutes the persistence boundary while exercising
a real in-memory `FileSecurity` or `DirectorySecurity` object.

The elevated acceptance file is always discovered. Each scenario runs when
the isolated test process contains and can enable its required privilege;
otherwise Pester records a skip with the exact missing privilege. This avoids
claiming that mocked SACL behavior is a successful live SACL write.

## See also

- [Research and comparison](research.md)
- [Elevated acceptance specifications](../tests/Integration/Elevated-NTFSPermission.Tests.ps1)
