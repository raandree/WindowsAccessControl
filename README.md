# WindowsAccessControl

`WindowsAccessControl` is a Windows PowerShell module for pipeline-first
management of Windows security descriptors. Its filesystem, registry-key,
service/SCM, live-process, SMB-share, Active Directory, and Task Scheduler
commands turn common DACL, SACL, owner, inheritance, backup, and
effective-access operations into composable commands without requiring callers
to manipulate .NET access-control objects directly.

The module has no third-party runtime dependency. It supports Windows
PowerShell 5.1 and PowerShell 7 on Windows.

The unpublished package was renamed from `NTFSPermission`. See the
[migration map](docs/migration-from-ntfspermission.md) for package, command, and
output type changes.

For task-oriented installation, safety, NTFS, registry, service, process,
backup, diagnostics, batching, impersonation, and DSC examples, see the
[usage guide](docs/usage-guide.md).

## Quick start

Build the module, then import the generated manifest:

```powershell
.\build.ps1 -ResolveDependency

$manifest = Get-ChildItem -Path '.\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1' |
    Sort-Object -Property { [version]$_.Directory.Name } -Descending |
    Select-Object -First 1
Import-Module -Name $manifest.FullName
```

Inspect explicit access rules across a directory tree:

```powershell
Get-ChildItem -LiteralPath 'C:\Data' -Recurse |
    Get-NTFSAccessRule -ExcludeInherited
```

Add an inheritable rule to several directories:

```powershell
Get-ChildItem -LiteralPath 'C:\Data' -Directory |
    Add-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Modify
```

Add the same rule for several accounts with one descriptor write per item:

```powershell
$accounts = 'CONTOSO\Analysts', 'CONTOSO\Auditors'
Add-NTFSAccessRule -LiteralPath 'C:\Data' -Account $accounts -AccessRights Read
```

Process independent target arrays with bounded parallelism:

```powershell
$paths = Get-ChildItem -LiteralPath 'C:\Data' -File | Select-Object -ExpandProperty FullName
Get-NTFSItemOwner -LiteralPath $paths -ThrottleLimit 8
```

Preview any mutation before applying it:

```powershell
Get-ChildItem -LiteralPath 'C:\Data' -Recurse |
    Clear-NTFSAccessRule -WhatIf
```

Run one or more local operations under an explicitly supplied Windows identity:

```powershell
$credential = Get-Credential

Invoke-WindowsAccessControl -Credential $credential -ScriptBlock {
    Get-NTFSAccessRule -LiteralPath 'C:\Data' -ExcludeInherited
}
```

The credential creates only a local interactive impersonation scope. It does
not enable remote target syntax. The caller identity is restored after success
or failure, and the credential password is never written to module output,
logs, metrics, or backup documents. The calling token must be permitted to
impersonate, and the supplied identity must be permitted to log on locally.
Windows PowerShell 5.1 requires .NET Framework 4.6 or later; every supported
Windows 11 and Windows Server 2025 installation meets that runtime floor.
Impersonation is scoped to the current thread. Work started in a job, runspace,
or another thread uses that execution context's identity.

Manage a local registry key with provider paths or `RegistryKey` pipeline
objects:

```powershell
Add-RegistryKeyAccessRule -Path 'HKLM:\Software\Contoso' `
    -Account 'BUILTIN\Users' `
    -AccessRights ReadKey `
    -AppliesTo ThisKeyAndSubkeys

Get-Item -LiteralPath 'HKLM:\Software\Contoso' |
    Get-RegistryKeyAccessRule -ExcludeInherited
```

## Bounded batches and metrics

Ordinary target-array commands across filesystem, registry, service/SCM, and
process families accept `ThrottleLimit` from 1 through 64. The default is the
smaller of eight and the logical processor count. A value of 1 requests
deterministic sequential execution; parallel output is emitted in completion
order.

Targets bound together in one array share a batch. PowerShell pipeline records
retain streaming semantics and are dispatched separately, so collect pipeline
output into an array before invoking a command when concurrency is required.

Each array is normalized and case-insensitively deduplicated by canonical
target before dispatch. Mutations of the same canonical target are serialized
across concurrent module instances in the hosting process. Interactive
confirmation also forces sequential execution so prompts do not overlap.

Inspect redacted, in-process aggregate counters without exposing descriptors:

```powershell
Get-WindowsAccessControlMetric -ObjectFamily FileSystem
Get-WindowsAccessControlMetric -CommandName Get-RegistryKeySecurityDescriptor
```

Metrics include operation, target, success, failure, and elapsed totals for the
current module instance. Run the repeatable NTFS read benchmark without a
flaky timing assertion:

```powershell
.\tests\Performance\Measure-NtfsBatchPerformance.ps1 `
    -TargetCount 512 `
    -Iterations 3 `
    -OutputPath .\output\testResults\NtfsBatchBenchmark.json
```

## Registry keys

Registry commands manage local keys only. `RegistryView` selects `Default`,
`Registry32`, or `Registry64`; native remote paths and remote `RegistryKey`
objects are rejected.
Registry values do not have independent security descriptors, so permissions
always apply to their containing key.

Access and audit mutations preserve inherited, unknown, and unrelated ACEs.
Exact removal consumes a path-bound rule from the matching `Get` command:

```powershell
Get-RegistryKeyAuditRule -Path 'HKLM:\Software\Contoso' `
    -Account 'S-1-1-0' -ExcludeInherited |
    Remove-RegistryKeyAuditRule -Confirm:$false
```

Use `Section Access`, `Audit`, or `All` when changing registry inheritance:

```powershell
Disable-RegistryKeyInheritance -Path 'HKLM:\Software\Contoso' `
    -Section All -PreserveInherited $true
Enable-RegistryKeyInheritance -Path 'HKLM:\Software\Contoso' -Section All
```

Registry SACL reads and writes temporarily enable `SeSecurityPrivilege` when
it is present in the process token, then restore its original state.

## SMB shares

SMB commands manage the share DACL independently from the backing NTFS DACL.
They accept unqualified local share names only; run them inside an approved
secure session when the share belongs to another computer.

```powershell
Get-SmbShareAccessRule -Name 'Data$'

Get-SmbShareEffectiveAccess -Name 'Data$' `
    -Account 'CONTOSO\Analysts' `
    -AccessRights Read

Add-SmbShareAccessRule -Name 'Data$' `
    -Account 'CONTOSO\Analysts' `
    -AccessRights Read `
    -WhatIf
```

Administrative, drive, IPC, print, clustered, and continuously available
shares are rejected. Share DACL writes preserve the share description and do
not claim effective access to files under the backing path. The share-only
effective-access result is labeled `LocalSidDerived`, excludes backing NTFS,
and can omit network-logon-specific groups.

## Active Directory objects

AD commands require an explicit DNS domain-controller name and use direct LDAP
Kerberos authentication with signing and sealing. Mutators additionally
require an allowed OU boundary and revalidate the immutable object GUID before
every write.

```powershell
$server = 'dc01.example.test'
$base = 'OU=Applications,DC=example,DC=test'
$target = 'OU=Database,$base'

Get-ADObjectAccessRule -Server $server -DistinguishedName $target

Add-ADObjectAccessRule -Server $server `
    -DistinguishedName $target `
    -AllowedBaseDistinguishedName $base `
    -Account 'CONTOSO\Analysts' `
    -AccessRights ReadProperty `
    -WhatIf
```

The first increment is DACL-only. It excludes SACLs, owner/group mutation,
backup/restore, DSC, effective access, and replication convergence.

## Task Scheduler folders and tasks

Task Scheduler commands run locally on the computer that owns the folder or
registered task. Every mutator requires an explicit non-system
`AllowedRootPath`, preserves current literal Local System ACEs, rejects a write
that newly denies the Task Scheduler service token, and rejects root or
`\Microsoft` writes:

```powershell
$taskPath = '\Operations'

$folderDescriptor = Get-TaskFolderSecurityDescriptor -Path $taskPath
Set-TaskFolderSecurityDescriptor -Path $taskPath `
    -AllowedRootPath $taskPath `
    -Sddl $folderDescriptor.Sddl `
    -WhatIf

Get-ScheduledTaskSecurityDescriptor `
    -TaskPath $taskPath `
    -TaskName 'Cleanup'

Add-TaskFolderAccessRule -Path $taskPath `
    -AllowedRootPath $taskPath `
    -Account 'CONTOSO\Operators' `
    -AccessRights ReadAndTraverse `
    -AppliesTo ThisFolderSubfoldersAndTasks `
    -WhatIf

Get-ScheduledTaskAccessRule -TaskPath $taskPath -TaskName 'Cleanup'
```

`WindowsTaskFolderRights` and `WindowsScheduledTaskRights` name the Task
Scheduler operation each mask authorizes rather than exposing filesystem
rights; folders and tasks get separate enums because the same mask bit means
different things on a directory and a file. The increment covers DACL
descriptors and typed access rules; it does not expose audit rules, SACLs,
backup/restore, DSC, or direct remote target parameters.

## Certificate private keys

The first private-key increment is read-only and supports exact persisted RSA
keys in Microsoft Software Key Storage Provider. Supply the certificate object,
provider, and key name so the module can cross-check identity without searching
stores or exporting key material:

```powershell
$certificate = Get-Item 'Cert:\LocalMachine\My\0123456789ABCDEF'

Get-CertificatePrivateKeySecurityDescriptor `
    -Certificate $certificate `
    -ProviderName 'Microsoft Software Key Storage Provider' `
    -KeyName 'WorkloadKey'
```

CAPI, hardware, ephemeral, mismatched, and mutation workflows are not part of
this increment. The command does not dispose the caller-owned certificate.

## Services and the SCM

Service commands accept local service names and `ServiceController` pipeline
objects. Names are service names, not display names. Remote controllers and
qualified remote names are rejected.

```powershell
Get-Service -Name BITS |
    Add-ServiceAccessRule -Account 'BUILTIN\Users' `
        -ServiceRights QueryStatus

Get-ServiceAccessRule -Name BITS -Account 'BUILTIN\Users'
```

The local Service Control Manager is a separate explicit parameter set and
uses its own rights enum:

```powershell
Get-ServiceAccessRule -ServiceControlManager

Add-ServiceAccessRule -ServiceControlManager `
    -Account 'BUILTIN\Administrators' `
    -ControlManagerRights Connect `
    -WhatIf
```

Service and SCM descriptors do not support ACL inheritance. Audit operations
scope `SeSecurityPrivilege`; owner/group writes scope `SeRestorePrivilege`
when it is present. SCM access uses a local `OpenSCManagerW` handle that is
closed by the module after each operation.

## Live processes

Process commands accept local PIDs, `System.Diagnostics.Process` objects,
module output, or explicit caller-owned handles. PID targets are pinned by PID
plus creation `FILETIME` before every descriptor read or write; stale PID reuse
fails closed.

```powershell
$process = Get-Process -Id $PID
$descriptor = $process | Get-ProcessSecurityDescriptor -Sections Access

Add-ProcessAccessRule -InputObject $descriptor `
    -Account 'BUILTIN\Users' `
    -ProcessRights QueryLimitedInformation
```

Caller-owned handles remain owned by the caller and are never closed:

```powershell
Get-ProcessSecurityDescriptor -Handle $process.Handle -Sections Access
```

The module opens PID targets once per operation, revalidates creation time, and
uses that handle for read/compare/write. `SeDebugPrivilege` is retried only
after access denial and only when already present in the token. Process desired
state is ephemeral and ends when that instance exits; process ACLs do not
support inheritance.

## Access rules

`Add-NTFSAccessRule` accumulates rights. `Set-NTFSAccessRule` replaces rules for
the same SID and the same allow or deny qualifier, preserving the opposite
qualifier and other accounts.

```powershell
Add-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Analysts' `
    -AccessRights ReadAndExecute `
    -AccessControlType Allow

Set-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Analysts' `
    -AccessRights Modify `
    -AccessControlType Allow
```

Exact removal is the default for a rule received from the pipeline:

```powershell
Get-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Analysts' -ExcludeInherited |
    Remove-NTFSAccessRule -Confirm:$false
```

Path-based removal exposes the underlying distinctions explicitly:

- `-RemovalMode Exact` removes an identical ACE.
- `-RemovalMode Rights` subtracts the selected rights from matching ACEs.
- `-RemovalMode All` purges every ACE for the selected SID.

Use `Get-NTFSAccessRule -Orphaned` to find SIDs that no longer translate to an
account. Treat those results carefully because a temporary domain connectivity
failure can also prevent translation.

When Windows can identify the source, inherited access-rule results expose
`InheritedFrom` with the original ancestor path. Explicit rules and inherited
rules with an unresolved native source leave `InheritedFrom` empty; the module
does not guess provenance by comparing parent ACLs.

## Rule scope

The `AppliesTo` parameter uses Windows Explorer-style values:

| Value | Applies to |
| --- | --- |
| `ThisFolderOnly` | The current item only |
| `ThisFolderSubfoldersAndFiles` | Current directory and all children |
| `ThisFolderAndSubfolders` | Current directory and child directories |
| `ThisFolderAndFiles` | Current directory and child files |
| `SubfoldersAndFilesOnly` | Child directories and files only |
| `SubfoldersOnly` | Child directories only |
| `FilesOnly` | Child files only |
| `ThisFolderSubfoldersAndFilesOneLevel` | Current directory and one child level |
| `ThisFolderAndSubfoldersOneLevel` | Current directory and one directory level |
| `ThisFolderAndFilesOneLevel` | Current directory and one file level |
| `SubfoldersAndFilesOnlyOneLevel` | Immediate child directories and files only |
| `SubfoldersOnlyOneLevel` | Immediate child directories only |
| `FilesOnlyOneLevel` | Immediate child files only |

Files default to `ThisFolderOnly`. Directories default to
`ThisFolderSubfoldersAndFiles`.

## Inheritance and ownership

Disabling inheritance preserves inherited rules as explicit rules by default:

```powershell
Disable-NTFSItemInheritance -LiteralPath 'C:\Data'
Enable-NTFSItemInheritance -LiteralPath 'C:\Data'
```

Discard inherited rules only when that destructive behavior is intended:

```powershell
Disable-NTFSItemInheritance -LiteralPath 'C:\Data' `
    -PreserveInherited:$false
```

When re-enabling inheritance, explicit rules can be removed in the same
operation:

```powershell
Enable-NTFSItemInheritance -LiteralPath 'C:\Data' -RemoveExplicitRules
```

Owner commands emit both account and SID forms:

```powershell
Get-NTFSItemOwner -LiteralPath 'C:\Data'
Set-NTFSItemOwner -LiteralPath 'C:\Data' `
    -Account 'BUILTIN\Administrators' -Confirm:$false
```

Setting an arbitrary owner can require `SeRestorePrivilege`. Taking ownership
can require `SeTakeOwnershipPrivilege`.

## Audit rules and privileges

SACL operations require `SeSecurityPrivilege`, and Windows audit policy must
enable object access auditing before events are produced.

```powershell
Get-WindowsPrivilege

Add-NTFSAuditRule -LiteralPath 'C:\Data' `
    -Account 'S-1-1-0' `
    -AccessRights Write `
    -AuditFlags Failure
```

SACL and arbitrary-owner commands temporarily enable only the required
privileges already present in the process token, reference-count nested use,
and restore the original state. `Enable-WindowsPrivilege` and
`Disable-WindowsPrivilege` remain available for deliberate token management.
They fail explicitly when Windows reports
`ERROR_NOT_ALL_ASSIGNED`. `Get-WindowsPrivilege` distinguishes privileges that are
present but disabled from privileges absent from the token.

## Backup, restore, and copy

Unified backups accept descriptor objects from every supported family and write
one versioned, non-executable JSON envelope. Each record contains the object
family, canonical target, selected native section mask, SDDL, and a SHA-256
digest. Process records also contain the PID and creation `FILETIME`:

```powershell
@(
    Get-NTFSItemSecurityDescriptor -LiteralPath 'C:\Data' -Sections Access
    Get-RegistryKeySecurityDescriptor -Path 'HKCU:\Software\Contoso' -Sections Access
    Get-ServiceSecurityDescriptor -Name 'BITS' -Sections Access
    Get-ProcessSecurityDescriptor -ProcessId $PID -Sections Access
) | Backup-WindowsSecurityDescriptor `
    -DestinationPath 'C:\Backup\windows-permissions.json'

Restore-WindowsSecurityDescriptor `
    -BackupPath 'C:\Backup\windows-permissions.json' `
    -Confirm:$false
```

Supplying an RSA X.509 certificate with a private key signs every record. A
signed backup requires the matching certificate during restore:

```powershell
$descriptor | Backup-WindowsSecurityDescriptor `
    -DestinationPath 'C:\Backup\signed-permissions.json' `
    -SigningCertificate $signingCertificate

Restore-WindowsSecurityDescriptor `
    -BackupPath 'C:\Backup\signed-permissions.json' `
    -VerificationCertificate $verificationCertificate `
    -Confirm:$false
```

SHA-256 detects accidental or untrusted modification only when the expected
digest is protected separately. X.509 signing adds authenticity by pinning
restore to the supplied certificate; the module does not infer trust from the
certificate store.

Signatures protect individual records, not the envelope's record set. Removing
a signed record or replaying an older record signed by the same certificate is
not detected. Verification also requires the certificate to be within its
validity period at restore time. Retain trusted backup manifests and certificate
lifecycle records when omission, replay, or long-term archival matters.

Backup validates every descriptor before file creation, rejects duplicate
canonical targets, signs only after `ShouldProcess` approves the operation, and
atomically moves or replaces the completed envelope. A selected absent SACL is
encoded explicitly as `S:NO_ACCESS_CONTROL`; selected DACLs must remain
non-null.

`Backup-NTFSItemSecurityDescriptor` accepts `ThrottleLimit` for bounded
descriptor reads, but still writes exactly one complete atomic envelope after
every selected target succeeds.

## Desired State Configuration

The module exports class-based exact-descriptor resources for every supported
target type:

- `WindowsAccessControlNtfsSecurityDescriptor`
- `WindowsAccessControlRegistryKeySecurityDescriptor`
- `WindowsAccessControlServiceSecurityDescriptor`
- `WindowsAccessControlServiceControlManagerSecurityDescriptor`
- `WindowsAccessControlProcessSecurityDescriptor`

It also exports exact access-rule presence resources:

- `WindowsAccessControlNtfsAccessRule`
- `WindowsAccessControlRegistryKeyAccessRule`
- `WindowsAccessControlServiceAccessRule`
- `WindowsAccessControlServiceControlManagerAccessRule`
- `WindowsAccessControlProcessAccessRule`

Each resource owns only its selected owner, group, DACL, or SACL sections.
System-maintained DACL/SACL `AUTO_INHERITED` flags are ignored during
comparison, while protection flags and every ACE remain exact. Registry view
is part of registry resource identity. Process resources require both PID and
creation `FILETIME`, so PID reuse fails closed.

Capture desired SDDL from the corresponding `Get-*SecurityDescriptor` command.
When a resource owns an access ACL, prefer a protected (`D:P`) descriptor so
parent inheritance cannot add ACEs after convergence. Declare at most one SCM
exact-descriptor resource per node. Process desired state is intentionally
ephemeral and is valid only while the pinned process instance remains alive.
Likewise, use a protected empty SACL (`S:P`) when audit inheritance must remain
empty; `S:NO_ACCESS_CONTROL` represents an absent SACL that can inherit later.

```powershell
Configuration ContosoFilePermissions {
    Import-DscResource -ModuleName WindowsAccessControl

    Node localhost {
        WindowsAccessControlNtfsSecurityDescriptor DataDacl {
            Path = 'C:\Data'
            Sections = 'Access'
            Sddl = 'D:P(A;;FA;;;SY)(A;;0x1301BF;;;BA)'
        }
    }
}
```

The module must be installed in a module path visible to the Windows LCM, such
as `C:\Program Files\WindowsPowerShell\Modules`. A workspace-only path visible
to the calling shell is not automatically visible to the SYSTEM LCM process.

Rule resources use `Ensure = Present` by default. Their composite keys identify
one exact explicit ACE by target, account, rights, allow/deny qualifier, and
inheritance scope where supported. `Absent` removes every duplicate exact ACE
without purging unrelated rights or the opposite qualifier. Account aliases are
normalized by SID and rights masks remain unsigned across both PowerShell
editions. For NTFS allow rules, comparison includes the `Synchronize` bit that
.NET adds when it materializes the ACE.

Windows can merge same-account, qualifier, and scope ACEs. If a broader
superset ACE already exists, a narrower exact `Present` rule cannot coexist and
will remain noncompliant; model the desired superset explicitly or manage the
whole DACL with an exact-descriptor resource. Process rule resources are
intended for long-lived pinned process instances.

```powershell
WindowsAccessControlNtfsAccessRule AnalystsRead {
    Path = 'C:\Data'
    Account = 'CONTOSO\Analysts'
    AccessRights = 'Read'
    AccessControlType = 'Allow'
    AppliesTo = 'ThisFolderSubfoldersAndFiles'
    Ensure = 'Present'
}
```

The NTFS-specific commands remain available and use the same unified envelope:

```powershell
Get-ChildItem -LiteralPath 'C:\Data' -Recurse |
    Backup-NTFSItemSecurityDescriptor `
        -DestinationPath 'C:\Backup\permissions.json'

Restore-NTFSItemSecurityDescriptor `
    -BackupPath 'C:\Backup\permissions.json' `
    -Confirm:$false
```

Restore validates every record and changes only the sections recorded in the
backup. It validates all integrity proofs and prepares every target before the
first descriptor is persisted, so a malformed later record cannot cause a
partial restore. A later runtime failure can still stop restore after earlier
independent targets were written. Process restore succeeds only while the same
pinned process instance remains alive.

Backups refuse to overwrite an existing file unless `-Force` is supplied. A
backup controls the target paths it restores, so review backup files from
outside trusted administrative workflows before applying them.

Copy follows the same selected-section rule:

```powershell
Get-ChildItem -LiteralPath 'C:\Target' |
    Copy-NTFSItemSecurityDescriptor `
        -SourceLiteralPath 'C:\Template' `
        -Sections Access `
        -Confirm:$false
```

## Effective access

`Get-NTFSItemEffectiveAccess` calls the Windows Authz API with
`MAXIMUM_ALLOWED`. It expands groups for a valid user SID and returns both the
raw access mask and `FileSystemRights`.

```powershell
Get-NTFSItemEffectiveAccess -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Alice' `
    -AccessRights Modify
```

A context created from a SID can omit logon-specific groups such as Interactive
or Network, and it is less complete than evaluation from a live logon token.
Share permissions are outside this module's scope and are not intersected with
the NTFS result.

## Commands

| Area | Commands |
| --- | --- |
| Access rules | `New-NTFSAccessRule`, `Get-NTFSAccessRule`, `Add-NTFSAccessRule`, `Set-NTFSAccessRule`, `Remove-NTFSAccessRule`, `Clear-NTFSAccessRule` |
| Audit rules | `New-NTFSAuditRule`, `Get-NTFSAuditRule`, `Add-NTFSAuditRule`, `Set-NTFSAuditRule`, `Remove-NTFSAuditRule`, `Clear-NTFSAuditRule` |
| Owner | `Get-NTFSItemOwner`, `Set-NTFSItemOwner` |
| Inheritance | `Get-NTFSItemInheritance`, `Enable-NTFSItemInheritance`, `Disable-NTFSItemInheritance` |
| Descriptor portability and editing | `Get-NTFSItemSecurityDescriptor`, `Edit-NTFSItemSecurityDescriptor`, `Set-NTFSItemSecurityDescriptor`, `Copy-NTFSItemSecurityDescriptor`, `Backup-NTFSItemSecurityDescriptor`, `Restore-NTFSItemSecurityDescriptor`, `Backup-WindowsSecurityDescriptor`, `Restore-WindowsSecurityDescriptor` |
| Registry descriptors | `Get-RegistryKeySecurityDescriptor`, `Edit-RegistryKeySecurityDescriptor`, `Set-RegistryKeySecurityDescriptor` |
| Registry access rules | `Get-RegistryKeyAccessRule`, `Add-RegistryKeyAccessRule`, `Set-RegistryKeyAccessRule`, `Remove-RegistryKeyAccessRule`, `Clear-RegistryKeyAccessRule` |
| Registry audit rules | `Get-RegistryKeyAuditRule`, `Add-RegistryKeyAuditRule`, `Set-RegistryKeyAuditRule`, `Remove-RegistryKeyAuditRule`, `Clear-RegistryKeyAuditRule` |
| Registry inheritance | `Get-RegistryKeyInheritance`, `Enable-RegistryKeyInheritance`, `Disable-RegistryKeyInheritance` |
| Service descriptors | `Get-ServiceSecurityDescriptor`, `Set-ServiceSecurityDescriptor` |
| Service/SCM access rules | `Get-ServiceAccessRule`, `Add-ServiceAccessRule`, `Set-ServiceAccessRule`, `Remove-ServiceAccessRule`, `Clear-ServiceAccessRule` |
| Service/SCM audit rules | `Get-ServiceAuditRule`, `Add-ServiceAuditRule`, `Set-ServiceAuditRule`, `Remove-ServiceAuditRule`, `Clear-ServiceAuditRule` |
| Process descriptors | `Get-ProcessSecurityDescriptor`, `Set-ProcessSecurityDescriptor` |
| Process access rules | `Get-ProcessAccessRule`, `Add-ProcessAccessRule`, `Set-ProcessAccessRule`, `Remove-ProcessAccessRule`, `Clear-ProcessAccessRule` |
| Process audit rules | `Get-ProcessAuditRule`, `Add-ProcessAuditRule`, `Set-ProcessAuditRule`, `Remove-ProcessAuditRule`, `Clear-ProcessAuditRule` |
| Diagnostics | `Resolve-WindowsIdentity`, `Get-NTFSItemEffectiveAccess`, `Test-NTFSItemAcl` |
| Privileges | `Get-WindowsPrivilege`, `Test-WindowsPrivilege`, `Enable-WindowsPrivilege`, `Disable-WindowsPrivilege` |
| Local impersonation | `Invoke-WindowsAccessControl` |
| Metrics | `Get-WindowsAccessControlMetric` |

Use `Get-Help <command> -Full` for parameter semantics and examples.

## Safety model

- Every mutator supports `WhatIf` and `Confirm`.
- High-impact clear, remove, owner, copy, restore, and privilege commands prompt
  according to PowerShell's confirmation preferences.
- Mutators are silent by default and expose `PassThru` where output is useful.
- DACL-only operations persist only modified DACL state and do not request SACL
  privileges.
- Inherited ACEs cannot be removed directly from a child; change inheritance or
  the parent rule instead.
- SACL operations and arbitrary ownership changes scope required privileges
    already present in the token and restore their original state.
- Local impersonation uses an explicit `PSCredential`, restores the caller
    identity in all paths, and does not expand the local-only target boundary.
- FileSystem provider resolution follows reparse points such as symbolic links
    and junctions. A path can change between resolution and descriptor
    persistence, so do not accept untrusted path input for privileged operations.
- Extended `\\?\` and `\\?\UNC\` paths are passed to the host runtime; support
    depends on the active PowerShell and Windows long-path configuration.

## Build and test

The repository uses Sampler, ModuleBuilder, InvokeBuild, Pester 5.7.1, and
PSScriptAnalyzer.

```powershell
.\build.ps1 -ResolveDependency
.\build.ps1 -Tasks test
.\build.ps1 -Tasks pack
```

The test matrix covers PowerShell 7 and Windows PowerShell 5.1 on Windows.
Builds and Pester runs should be launched from a clean process when developing
in VS Code. Sampler enforces at least 80% executable coverage for the merged
module.

Seven `RequiresElevation` acceptance specifications perform real SACL CRUD,
audit inheritance, SACL backup/restore/copy, and arbitrary-owner operations.
They run automatically when the test process contains the required privileges
and otherwise report explicit skips. Run the test workflow from an elevated
PowerShell process to exercise the available privileged paths.

Sixteen additional live scenarios exercise registry descriptor round trips,
access and audit rule CRUD, inheritance, view selection, pipeline input,
local-target validation, audit-flag isolation, absent-SACL preservation, and
`WhatIf`. The same registry scenarios pass in PowerShell 7 and Windows
PowerShell 5.1.

Thirteen disposable-service scenarios exercise service and SCM descriptor
reads, no-op descriptor sets, typed rights, access/audit CRUD, local target
validation, and `ServiceController` pipeline input. They pass unchanged in
PowerShell 7 and Windows PowerShell 5.1 and verify service cleanup after each
case.

Fourteen controlled-child-process scenarios exercise PID, `Process`, module
output, and caller-handle targets; creation identity mismatch; descriptor
round trips; typed access/audit CRUD; and caller-handle reuse. They pass in
PowerShell 7 and Windows PowerShell 5.1 with child cleanup after each case.

## Design research

The numbered [specifications](specs/README.md) are the source of truth for
scope, requirements, API shape, security boundaries, and verification
traceability. Exhaustive command details remain in comment-based help.

See [docs/research.md](docs/research.md) for the source review, platform API
semantics, and NTFSSecurity comparison that informed those specifications.
