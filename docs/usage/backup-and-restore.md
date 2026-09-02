# Backup, restore, and copy

The module writes one versioned, non-executable JSON envelope that can hold
descriptors from every supported object family. Restore changes only the
sections each record captured.

## Copy a descriptor between items

Copy selected sections from a template directory to selected targets:

```powershell
Get-ChildItem -LiteralPath 'C:\Target' |
    Copy-NTFSItemSecurityDescriptor `
        -SourceLiteralPath 'C:\Template' `
        -Sections Access `
        -WhatIf
```

Only the selected sections are copied, so an access-only copy leaves the
target's owner, group, and SACL alone.

## Back up one NTFS tree

When no other object family is involved, the NTFS-specific commands are the
shortest path:

```powershell
Get-ChildItem -LiteralPath 'C:\Data' -Recurse |
    Backup-NTFSItemSecurityDescriptor `
        -DestinationPath 'C:\Backup\permissions.json' `
        -Sections Access

Restore-NTFSItemSecurityDescriptor `
    -BackupPath 'C:\Backup\permissions.json' `
    -WhatIf
```

The backup is written once, after every selected item has been read
successfully. `Backup-NTFSItemSecurityDescriptor` accepts `ThrottleLimit` for
bounded descriptor reads but still writes exactly one complete envelope.

## Back up several families at once

Pipe descriptor objects from any supported family into one envelope:

```powershell
@(
    Get-NTFSItemSecurityDescriptor -LiteralPath 'C:\Data' -Sections Access
    Get-RegistryKeySecurityDescriptor -Path 'HKCU:\Software\Contoso' -Sections Access
    Get-ServiceSecurityDescriptor -Name 'BITS' -Sections Access
    Get-ProcessSecurityDescriptor -ProcessId $PID -Sections Access
) | Backup-WindowsSecurityDescriptor -DestinationPath 'C:\Backup\windows-permissions.json'
```

Preview and then apply the restore:

```powershell
Restore-WindowsSecurityDescriptor -BackupPath 'C:\Backup\windows-permissions.json' -WhatIf
Restore-WindowsSecurityDescriptor -BackupPath 'C:\Backup\windows-permissions.json' -Confirm:$false
```

## What a record contains

Each record holds the object family, canonical target, selected native section
mask, SDDL, and a SHA-256 digest. Process records additionally hold the PID and
creation `FILETIME`.

Record version is a property of the object family, and the envelope's schema
version is the highest record version it contains:

| Object family | Record version | Additional binding |
| --- | ---: | --- |
| `FileSystem`, `RegistryKey`, `Service`, `ServiceControlManager`, `Process` | 1 | None |
| `SmbShare` | 2 | Server and immutable share name |
| `ADObject` | 2 | Server, distinguished name, `objectGUID`, domain naming context |
| `TaskFolder`, `ScheduledTask` | 2 | Owning computer and absolute task path |
| `CertificatePrivateKey` | 2 | Owning computer, provider, key name, key scope, and the thumbprint as evidence |

A record whose family and version disagree is rejected in both directions, so a
version-2 record can never be replayed as a local target and a version-1 record
can never claim computer authority.

A selected absent SACL is encoded explicitly as `S:NO_ACCESS_CONTROL`. Selected
DACLs must remain non-null.

## Restore boundaries

Version-2 records restore only where their identity still holds, and some
require you to state a boundary explicitly:

| Family | Restore requirement |
| --- | --- |
| SMB share | Runs only on the computer the record names |
| Task Scheduler | Runs only on the computer the record names, and requires `AllowedRootPath` |
| Active Directory | Requires `AllowedBaseDistinguishedName`; binds one writable domain controller for the whole restore |
| Certificate private key | Runs only on the computer the record names; needs no extra boundary parameter |
| Process | Succeeds only while the same pinned process instance is alive |

```powershell
Restore-WindowsSecurityDescriptor `
    -BackupPath 'C:\Backup\tasks.json' `
    -AllowedRootPath '\Operations' `
    -Confirm:$false

Restore-WindowsSecurityDescriptor `
    -BackupPath 'C:\Backup\directory.json' `
    -AllowedBaseDistinguishedName 'OU=Apps,DC=contoso,DC=com' `
    -Confirm:$false
```

An Active Directory restore can bind a different writable domain controller
than the backup did, because identity is matched on the immutable `objectGUID`
and the recorded domain rather than on the server name.

## What restore guarantees, and what it does not

- Every record's integrity proof is validated and every target is prepared
  before the first descriptor is persisted, so a malformed later record cannot
  cause a partial restore.
- Only the sections recorded in each record are changed.
- Independent writes are **not** transactionally rolled back. A runtime failure
  on a later target can still leave earlier targets written.

## Sign a backup

Each record carries a SHA-256 digest, which detects accidental damage only when
the expected digest is protected separately. Supply an RSA X.509 certificate
with a private key to sign every record, and the matching certificate to verify
on restore:

```powershell
$descriptor | Backup-WindowsSecurityDescriptor `
    -DestinationPath 'C:\Backup\signed-permissions.json' `
    -SigningCertificate $signingCertificate

Restore-WindowsSecurityDescriptor `
    -BackupPath 'C:\Backup\signed-permissions.json' `
    -VerificationCertificate $verificationCertificate `
    -Confirm:$false
```

Know the limits of that signature:

- It protects individual records, not the envelope's record set. Removing a
  signed record, or replaying an older record signed by the same certificate,
  is not detected.
- Verification requires the certificate to be within its validity period at
  restore time.
- The module does not infer trust from the certificate store. Restore is pinned
  to the certificate you supply.

Retain trusted backup manifests and certificate lifecycle records when
omission, replay, or long-term archival matters.

## Treat a backup file as executable input

A backup record controls the target it restores to. Review any backup file that
arrives from outside a trusted administrative workflow before applying it.

Backup validates every descriptor before file creation, rejects duplicate
canonical targets, signs only after `ShouldProcess` approves the operation, and
atomically moves or replaces the completed envelope. It refuses to overwrite an
existing file unless `Force` is supplied.

## Commands on this page

| Area | Commands |
| --- | --- |
| Unified portability | `Backup-WindowsSecurityDescriptor`, `Restore-WindowsSecurityDescriptor` |
| NTFS portability | `Backup-NTFSItemSecurityDescriptor`, `Restore-NTFSItemSecurityDescriptor` |
| Copy | `Copy-NTFSItemSecurityDescriptor` |

## See also

- [Descriptor editing and concurrency](descriptor-editing.md)
- [Desired State Configuration](dsc.md)
- [Security and persistence contract](../../specs/0004-security-and-persistence.md)
- [Enterprise portability and desired state](../../specs/0013-enterprise-portability-and-desired-state.md)
