# WindowsAccessControl usage guide

This guide shows the common workflows for inspecting, changing, validating,
and preserving Windows security descriptors with `WindowsAccessControl`. Use
the command help when you need every parameter or output property.

## Before you begin

`WindowsAccessControl` supports Windows PowerShell 5.1 and PowerShell 7 on
Windows. The current package is unpublished, so build and import it from the
repository:

```powershell
.\build.ps1 -ResolveDependency

$manifest = Get-ChildItem -Path '.\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1' |
    Sort-Object -Property { [version]$_.Directory.Name } -Descending |
    Select-Object -First 1
Import-Module -Name $manifest.FullName
```

Confirm the module and its commands are available:

```powershell
Get-Module -Name WindowsAccessControl
Get-Command -Module WindowsAccessControl
Get-Help Get-NTFSAccessRule -Full
Get-Help Get-NTFSAccessRule -Examples
```

The examples use these sample values:

```powershell
$path = 'C:\Data'
$account = 'CONTOSO\Analysts'
$backupPath = 'C:\Backup\windows-permissions.json'
```

Replace them with test targets from your environment before applying a
mutation. Prefer `LiteralPath` when a path can contain wildcard characters.

## Choose a workflow

| Goal | Start with |
| --- | --- |
| Inspect access or audit rules | `Get-NTFSAccessRule`, `Get-NTFSAuditRule` |
| Grant or replace access | `Add-NTFSAccessRule`, `Set-NTFSAccessRule` |
| Remove access precisely | `Get-NTFSAccessRule` piped to `Remove-NTFSAccessRule` |
| Change inheritance or ownership | `Disable-NTFSItemInheritance`, `Set-NTFSItemOwner` |
| Check effective access or ACL order | `Get-NTFSItemEffectiveAccess`, `Test-NTFSItemAcl` |
| Copy, back up, or restore descriptors | `Copy-NTFSItemSecurityDescriptor`, `Backup-WindowsSecurityDescriptor` |
| Manage another supported object family | `Get-RegistryKeyAccessRule`, `Get-ServiceAccessRule`, `Get-ProcessAccessRule` |
| Manage SMB share permissions | `Get-SmbShareAccessRule`, `Add-SmbShareAccessRule` |
| Evaluate a local SMB share DACL only | `Get-SmbShareEffectiveAccess` |
| Delegate Active Directory object access | `Get-ADObjectAccessRule`, `Add-ADObjectAccessRule`, `Set-ADObjectAccessRule`, `Remove-ADObjectAccessRule`, `Clear-ADObjectAccessRule` |
| Manage Task Scheduler DACLs | `Get-TaskFolderSecurityDescriptor`, `Get-ScheduledTaskSecurityDescriptor`, `Get-TaskFolderAccessRule`, `Get-ScheduledTaskAccessRule` |
| Inspect a supported private-key DACL | `Get-CertificatePrivateKeySecurityDescriptor` |
| Enforce desired state | The class-based DSC resources |

## Preview every mutation

Rule, descriptor, owner, inheritance, backup, restore, and privilege mutators
support `WhatIf` and `Confirm`. Preview a change, review the target and action,
and then run the same command without `WhatIf`:

```powershell
$grantParameters = @{
    LiteralPath = $path
    Account = $account
    AccessRights = 'Modify'
    AppliesTo = 'ThisFolderSubfoldersAndFiles'
}

Add-NTFSAccessRule @grantParameters -WhatIf
Add-NTFSAccessRule @grantParameters -Confirm:$false -PassThru
```

Use `Confirm:$false` only when the preview has been reviewed or when established
automation provides equivalent controls.

## Manage an SMB share DACL

Run SMB commands on the computer that owns the share. The share DACL and the
backing NTFS DACL are separate authorization layers:

```powershell
Get-SmbShareSecurityDescriptor -Name 'Data$'
Get-SmbShareAccessRule -Name 'Data$'

Add-SmbShareAccessRule -Name 'Data$' `
    -Account $account `
    -AccessRights Change `
    -WhatIf
```

Remove one exact rule by piping the path-bound query result:

```powershell
Get-SmbShareAccessRule -Name 'Data$' -Account $account |
    Remove-SmbShareAccessRule -WhatIf
```

Evaluate only the local share DACL with a SID-derived Authz context:

```powershell
Get-SmbShareEffectiveAccess -Name 'Data$' `
    -Account $account `
    -AccessRights Read
```

This result does not include the backing NTFS DACL and does not reproduce a
remote network logon token. Inspect `AuthorizationContext` and
`IncludesBackingNtfs` before consuming it in automation. Authz reports an error
instead of a partial result when the executing process cannot contact the
selected SID's account authority.

## Delegate Active Directory object access

Select the allowed OU explicitly. Kerberos, LDAP signing, and sealing are
mandatory. `Server` is optional; omit it to use one automatically located
writable domain controller, which is then pinned for every target of that
command:

```powershell
$baseDn = 'OU=Applications,DC=example,DC=test'
$targetDn = "OU=Database,$baseDn"

Get-ADObjectAccessRule -DistinguishedName $targetDn

Add-ADObjectAccessRule `
    -Server 'dc01.example.test' `
    -DistinguishedName $targetDn `
    -AllowedBaseDistinguishedName $baseDn `
    -Account $account `
    -AccessRights ReadProperty `
    -InheritanceType Children `
    -WhatIf
```

Use `ObjectType` and `InheritedObjectType` GUIDs for property, extended-right,
or child-object-specific ACEs. The output retains those GUIDs for exact removal.

To replace, subtract, or purge rules, use the remaining mutators. Each one
matches on account, qualifier, and both object GUIDs, so an ACE scoped to a
different GUID pair is preserved rather than folded into a common ACE:

```powershell
Set-ADObjectAccessRule `
    -DistinguishedName $targetDn `
    -AllowedBaseDistinguishedName $baseDn `
    -Account $account `
    -AccessRights 'ReadProperty, WriteProperty'

Remove-ADObjectAccessRule `
    -DistinguishedName $targetDn `
    -AllowedBaseDistinguishedName $baseDn `
    -Account $account `
    -AccessRights WriteProperty `
    -RemovalMode Rights

Remove-ADObjectAccessRule `
    -DistinguishedName $targetDn `
    -AllowedBaseDistinguishedName $baseDn `
    -Account $account `
    -RemovalMode All

Clear-ADObjectAccessRule `
    -DistinguishedName $targetDn `
    -AllowedBaseDistinguishedName $baseDn
```

`Clear-ADObjectAccessRule` removes every explicit ACE, or only the selected
accounts when `Account` is supplied, and never touches an inherited ACE. Every
rule mutator refuses to write a DACL that would grant no principal `WriteDacl`
on the object, because only its owner could then manage it. Apply such a
descriptor deliberately with `Set-ADObjectSecurityDescriptor`.

To find out where an inherited rule comes from and what its GUIDs mean, read
`InheritedFrom`, `ObjectTypeName`, and `InheritedObjectTypeName`:

```powershell
Get-ADObjectAccessRule -DistinguishedName $targetDn -ExcludeExplicit |
    Format-Table Account, AccessRightsDisplay, ObjectTypeName,
        InheritedObjectTypeName, InheritedFrom
```

`InheritedFrom` names the nearest ancestor object that holds the originating
explicit inheritable ACE. It stays empty when an ancestor in the chain cannot be
read, so an unreadable parent costs the column rather than the rules. The name
properties resolve schema classes, attributes, property sets, validated writes,
and extended rights, and stay empty for a GUID that resolves to none of those.

The module has no directory effective-access command. A domain controller
decides directory access with the token it builds for a specific inbound
authentication plus directory-only rules such as confidential attributes,
property sets, validated writes, and list-object mode, none of which a locally
constructed access check reproduces. Use `Get-ADObjectAccessRule` to see who is
granted what, and read the domain controller's own caller-scoped constructed
attributes when an authoritative answer for the calling identity is needed:

```powershell
Get-ADObject -Identity $targetDn -Properties `
    allowedAttributesEffective, allowedChildClassesEffective, sDRightsEffective
```

## Manage Task Scheduler DACLs

Run these commands on the computer that owns the task folder. Use absolute
Task Scheduler paths, and select the allowed write boundary explicitly:

```powershell
$taskPath = '\Operations'
$folder = Get-TaskFolderSecurityDescriptor -Path $taskPath
$task = Get-ScheduledTaskSecurityDescriptor `
    -TaskPath $taskPath `
    -TaskName 'Cleanup'

Set-TaskFolderSecurityDescriptor `
    -Path $taskPath `
    -AllowedRootPath $taskPath `
    -Sddl $folder.Sddl `
    -WhatIf

Set-ScheduledTaskSecurityDescriptor `
    -TaskPath $taskPath `
    -TaskName 'Cleanup' `
    -AllowedRootPath $taskPath `
    -Sddl $task.Sddl `
    -WhatIf
```

Writes to the scheduler root and `\Microsoft` tree are rejected. Candidate
DACLs must retain the current literal Local System ACEs and cannot add an
explicit Local System deny ACE. A write is also rejected when it newly denies
any identity in the Task Scheduler service token, or when it contains an object
or compound ACE that the store would silently re-revision. Task Scheduler may
reorder ACEs and add its derived auto-inherited flag; the module verifies the
native ACE set and caller-controlled protection state after persistence.

Typed access rules use the same boundary and object-specific rights models:

```powershell
Get-TaskFolderAccessRule -Path $taskPath -ExcludeInherited

Add-TaskFolderAccessRule `
    -Path $taskPath `
    -AllowedRootPath $taskPath `
    -Account 'CONTOSO\Operators' `
    -AccessRights ReadAndTraverse `
    -AppliesTo ThisFolderSubfoldersAndTasks `
    -WhatIf

Get-ScheduledTaskAccessRule -TaskPath $taskPath -TaskName 'Cleanup' -ExcludeInherited |
    Where-Object SID -EQ 'S-1-1-0' |
    Remove-ScheduledTaskAccessRule -AllowedRootPath $taskPath -WhatIf
```

A task folder is a directory and a registered task is a file, so each has its
own enum: `WindowsTaskFolderRights` names `ListTasks`, `CreateTask`,
`CreateSubfolder`, and `Traverse`, while `WindowsScheduledTaskRights` names
`ReadTaskDefinition`, `WriteTaskDefinition`, and `RunTask`. Both share
`ChangePermissions`, `TakeOwnership`, and the `Read`, `Write`, `Modify`, and
`FullControl` composites. `AppliesTo` applies to task folders only; a
registered task is a leaf object. Removal is exact, idempotent when the ACE is
already absent, and refuses an inherited rule, which must be removed on the
folder that defines it. Audit rules, SACLs, and direct remote targets are not
part of this increment.

Task Scheduler descriptors join the unified backup as record version 2, bound to
the owning computer. A restore requires the same `AllowedRootPath` boundary as a
direct write:

```powershell
Get-TaskFolderSecurityDescriptor -Path $taskPath |
    Backup-WindowsSecurityDescriptor -DestinationPath 'C:\Backup\tasks.json'

Restore-WindowsSecurityDescriptor `
    -BackupPath 'C:\Backup\tasks.json' `
    -AllowedRootPath $taskPath `
    -Confirm:$false
```

## Inspect a supported private-key DACL

Use an exact certificate object plus the expected persisted CNG provider and
key name. The first increment is read-only and supports RSA keys in Microsoft
Software Key Storage Provider:

```powershell
$certificate = Get-Item 'Cert:\LocalMachine\My\0123456789ABCDEF'
$privateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
    GetRSAPrivateKey($certificate)
try {
    Get-CertificatePrivateKeySecurityDescriptor `
        -Certificate $certificate `
        -ProviderName $privateKey.Key.Provider.Provider `
        -KeyName $privateKey.Key.KeyName
}
finally {
    $privateKey.Dispose()
}
```

The module cross-checks provider and key identity, reads only the DACL with a
silent provider query, and does not dispose the caller-owned certificate.
Ephemeral, CAPI, hardware, mismatched, mutation, backup/restore, and DSC
workflows remain outside this increment. No private-key bytes are returned.

## Inspect file and directory access

List all access rules on one directory:

```powershell
Get-NTFSAccessRule -LiteralPath $path
```

Focus on explicit rules for one account:

```powershell
Get-NTFSAccessRule -LiteralPath $path `
    -Account $account `
    -ExcludeInherited
```

Inspect a tree through the pipeline:

```powershell
Get-ChildItem -LiteralPath $path -Recurse |
    Get-NTFSAccessRule -ExcludeInherited
```

Inherited rules expose `InheritedFrom` when Windows can identify the original
ancestor. The value is empty for explicit rules and when Windows cannot resolve
the source. `Get-RegistryKeyAccessRule` reports the same provenance for the
default registry view; the `Registry32` and `Registry64` views leave the value
empty because Windows does not resolve inheritance sources for them.
`Get-ADObjectAccessRule` also reports `InheritedFrom`, but infers it from the
ancestor chain because no directory API can honor the selected domain
controller.

## Grant or replace NTFS access

`Add-NTFSAccessRule` accumulates rights without replacing unrelated rules:

```powershell
Add-NTFSAccessRule -LiteralPath $path `
    -Account $account `
    -AccessRights ReadAndExecute `
    -AccessControlType Allow `
    -AppliesTo ThisFolderSubfoldersAndFiles `
    -WhatIf
```

Add the same rule for several accounts with one descriptor write:

```powershell
$accounts = 'CONTOSO\Analysts', 'CONTOSO\Auditors'
Add-NTFSAccessRule -LiteralPath $path `
    -Account $accounts `
    -AccessRights Read `
    -WhatIf
```

`Set-NTFSAccessRule` replaces rules for the same SID and allow or deny
qualifier. It preserves the opposite qualifier and rules for other accounts:

```powershell
Set-NTFSAccessRule -LiteralPath $path `
    -Account $account `
    -AccessRights Modify `
    -AccessControlType Allow `
    -AppliesTo ThisFolderSubfoldersAndFiles `
    -WhatIf
```

Use an explicit deny rule only after checking inherited and group-based access;
Windows evaluates deny ACEs before corresponding allow ACEs.

## Remove NTFS access

The safest removal starts from a path-bound rule returned by the matching
`Get` command. This removes that exact explicit ACE:

```powershell
Get-NTFSAccessRule -LiteralPath $path `
    -Account $account `
    -ExcludeInherited |
    Remove-NTFSAccessRule -WhatIf
```

Path-based removal supports three modes:

- `Exact` removes an identical ACE.
- `Rights` subtracts selected rights from matching ACEs.
- `All` removes every explicit ACE for the selected SID.

Subtract only write rights:

```powershell
Remove-NTFSAccessRule -LiteralPath $path `
    -Account $account `
    -AccessRights Write `
    -RemovalMode Rights `
    -WhatIf
```

Preview a complete purge for one account:

```powershell
Remove-NTFSAccessRule -LiteralPath $path `
    -Account $account `
    -RemovalMode All `
    -WhatIf
```

`Clear-NTFSAccessRule` removes every explicit DACL rule from each selected
item. Inherited rules remain, but this is still a high-impact operation:

```powershell
Clear-NTFSAccessRule -LiteralPath $path -WhatIf
```

Inherited ACEs cannot be removed directly from a child. Change the rule on its
source ancestor or change inheritance on the child.

## Change inheritance

Inspect access and audit inheritance state:

```powershell
Get-NTFSItemInheritance -LiteralPath $path -Section All
```

Disabling inheritance preserves inherited rules as explicit rules by default:

```powershell
Disable-NTFSItemInheritance -LiteralPath $path `
    -Section Access `
    -WhatIf
```

Discard inherited rules only when that destructive behavior is intended:

```powershell
Disable-NTFSItemInheritance -LiteralPath $path `
    -Section Access `
    -PreserveInherited:$false `
    -WhatIf
```

Re-enable inheritance while retaining explicit rules:

```powershell
Enable-NTFSItemInheritance -LiteralPath $path -Section Access -WhatIf
```

Add `RemoveExplicitRules` only when the inherited ACL should become the whole
selected ACL.

## Change an owner

Read both the account and SID forms of the current owner:

```powershell
Get-NTFSItemOwner -LiteralPath $path
```

Preview an owner change:

```powershell
Set-NTFSItemOwner -LiteralPath $path `
    -Account 'BUILTIN\Administrators' `
    -WhatIf
```

Setting an arbitrary owner can require `SeRestorePrivilege`; taking ownership
can require `SeTakeOwnershipPrivilege`. The module can temporarily enable a
required privilege only when it is already present in the process token.

## Stage one NTFS descriptor write

For several access-rule additions on one item, retrieve the DACL once, stage
the changes in memory, and persist it once:

```powershell
$descriptor = Get-NTFSItemSecurityDescriptor `
    -LiteralPath $path `
    -Sections Access

$descriptor = $descriptor |
    Add-NTFSAccessRule `
        -Account 'CONTOSO\Analysts', 'CONTOSO\Auditors' `
        -AccessRights Read

$descriptor | Set-NTFSItemSecurityDescriptor -WhatIf
$descriptor | Set-NTFSItemSecurityDescriptor -Confirm:$false
```

The descriptor records its selected sections, and only those sections are
written. Every filesystem access, audit, owner, and inheritance mutator accepts
a descriptor through its `SecurityDescriptor` parameter set, so several
different edits can share one write:

```powershell
Get-NTFSItemSecurityDescriptor -LiteralPath $path -Sections Access |
    Add-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Read |
    Set-NTFSAccessRule -Account 'CONTOSO\Auditors' -AccessRights Modify |
    Disable-NTFSItemInheritance -Section Access |
    Set-NTFSItemSecurityDescriptor -Confirm:$false
```

A descriptor-bound mutation fails when the section it would edit was not
loaded, because persisting an unloaded section would replace a live ACL with an
empty one. Read the sections you intend to edit.

Keep the read, in-memory callback, and write in one same-target lock with the
bounded scope:

```powershell
Edit-NTFSItemSecurityDescriptor `
    -LiteralPath $path `
    -Sections Access `
    -ScriptBlock {
        param($descriptor, $identity)
        $descriptor | Add-NTFSAccessRule `
            -Account $identity `
            -AccessRights Read | Out-Null
    } `
    -ArgumentList $account `
    -WhatIf
```

The callback runs against a detached descriptor even under `WhatIf`; only the
final descriptor persistence is skipped. Raw side effects performed directly
inside the trusted callback are not covered by this `WhatIf` guarantee. Callback
output is suppressed, and errors or an attempt to add an unloaded section
prevent the descriptor write. Use `PassThru` to receive the edited descriptor.
Targets run sequentially so one caller script block is never invoked
concurrently across runspaces; pass explicit values through `ArgumentList`.

## Stage one registry descriptor write

The registry-key family uses the same model:

```powershell
Get-RegistryKeySecurityDescriptor -Path 'HKLM:\SOFTWARE\Contoso' -Sections Access |
    Add-RegistryKeyAccessRule -Account 'CONTOSO\Analysts' -AccessRights ReadKey |
    Set-RegistryKeySecurityDescriptor -Confirm:$false

Edit-RegistryKeySecurityDescriptor `
    -Path 'HKLM:\SOFTWARE\Contoso' `
    -Sections Access `
    -ScriptBlock {
        param($descriptor)
        $descriptor | Clear-RegistryKeyAccessRule -Account 'CONTOSO\Legacy' | Out-Null
    } `
    -Confirm:$false
```

Exact ACE removal takes the rule through `-Rule` because the descriptor
occupies the pipeline:

```powershell
$rule = Get-RegistryKeyAccessRule -Path 'HKLM:\SOFTWARE\Contoso' -ExcludeInherited |
    Select-Object -First 1

Get-RegistryKeySecurityDescriptor -Path 'HKLM:\SOFTWARE\Contoso' -Sections Access |
    Remove-RegistryKeyAccessRule -Rule $rule |
    Set-RegistryKeySecurityDescriptor -Confirm:$false
```

## Reject a stale descriptor

A detached descriptor can drift from the live target. Persistence defaults to
last-writer-wins. Add `RequireUnchanged` to fail instead of overwriting a
concurrent change:

```powershell
$descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath $path -Sections Access |
    Add-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Read

$descriptor | Set-NTFSItemSecurityDescriptor -RequireUnchanged
```

The switch compares the descriptor's `ConcurrencyToken` against the live
selected sections immediately before the write. It narrows the race window and
fails fast; it is not a transactional guarantee. Re-read the descriptor and
reapply the edit when it rejects the write, and re-read again before a second
`RequireUnchanged` write because Windows can recompute inherited ACEs on write.

## Configure auditing

SACL reads and writes require `SeSecurityPrivilege`. Inspect the current token
before configuring an audit rule:

```powershell
Get-WindowsPrivilege
```

Audit failed writes by Everyone on a directory and its children:

```powershell
Add-NTFSAuditRule -LiteralPath $path `
    -Account 'S-1-1-0' `
    -AccessRights Write `
    -AuditFlags Failure `
    -AppliesTo ThisFolderSubfoldersAndFiles `
    -WhatIf
```

The SACL controls which operations are eligible for auditing. Windows audit
policy must also enable object access auditing before events are generated.

## Diagnose identity and access

Resolve account names and SIDs before using them in automation:

```powershell
'BUILTIN\Users', 'S-1-1-0' | Resolve-WindowsIdentity
```

Check whether an account has a requested effective NTFS right:

```powershell
Get-NTFSItemEffectiveAccess -LiteralPath $path `
    -Account $account `
    -AccessRights Modify
```

The effective-access result does not include SMB share permissions and can omit
logon-specific groups because it is calculated from a SID-derived Authz
context, not a live logon token.

Check canonical ACE ordering without changing the descriptor:

```powershell
Test-NTFSItemAcl -LiteralPath $path -Section All -PassThru
```

`Test-NTFSItemAcl` reports ordering problems; it does not repair them.

## Copy, back up, and restore descriptors

Copy only the DACL from a template directory to selected targets:

```powershell
Get-ChildItem -LiteralPath 'C:\Target' |
    Copy-NTFSItemSecurityDescriptor `
        -SourceLiteralPath 'C:\Template' `
        -Sections Access `
        -WhatIf
```

Back up one NTFS tree when no other object family is needed:

```powershell
Get-ChildItem -LiteralPath $path -Recurse |
    Backup-NTFSItemSecurityDescriptor `
        -DestinationPath $backupPath `
        -Sections Access

Restore-NTFSItemSecurityDescriptor -BackupPath $backupPath -WhatIf
```

The backup is written once after every selected item is read successfully.
Add `Force` only when an existing backup file should be replaced.

Create one unified backup for several supported object families:

```powershell
@(
    Get-NTFSItemSecurityDescriptor -LiteralPath $path -Sections Access
    Get-RegistryKeySecurityDescriptor -Path 'HKCU:\Software\Contoso' -Sections Access
    Get-ServiceSecurityDescriptor -Name 'BITS' -Sections Access
    Get-ProcessSecurityDescriptor -ProcessId $PID -Sections Access
) | Backup-WindowsSecurityDescriptor -DestinationPath $backupPath
```

Preview and then apply a restore:

```powershell
Restore-WindowsSecurityDescriptor -BackupPath $backupPath -WhatIf
Restore-WindowsSecurityDescriptor -BackupPath $backupPath -Confirm:$false
```

Restore changes only the sections recorded in each backup record. It validates
all records and prepares all targets before the first write, but independent
writes are not transactionally rolled back if a later runtime write fails.

Each record has a SHA-256 digest. Use `SigningCertificate` during backup and
the matching `VerificationCertificate` during restore when authenticity is
required. Review backup files received outside a trusted administrative
workflow because each record controls its restore target.

SMB share and Active Directory descriptors use record version 2 and bind the
server plus the immutable share name or distinguished name, `objectGUID`, and
domain naming context. A share record restores only on the computer it names,
and a directory record requires an explicit allowed organizational unit:

```powershell
Get-ADObjectSecurityDescriptor -DistinguishedName $distinguishedName |
    Backup-WindowsSecurityDescriptor -DestinationPath $backupPath

Restore-WindowsSecurityDescriptor `
    -BackupPath $backupPath `
    -AllowedBaseDistinguishedName 'OU=Apps,DC=contoso,DC=com' `
    -Confirm:$false
```

The restore can bind a different writable domain controller than the backup
did, because identity is matched on the immutable `objectGUID` and the recorded
domain rather than on the server name.

## Manage registry key permissions

Registry permissions apply to keys, not individual registry values. Commands
accept provider paths, native local paths, or local `RegistryKey` objects:

```powershell
Get-RegistryKeyAccessRule -Path 'HKLM:\Software\Contoso' `
    -ExcludeInherited

Add-RegistryKeyAccessRule -Path 'HKLM:\Software\Contoso' `
    -Account 'BUILTIN\Users' `
    -AccessRights ReadKey `
    -AppliesTo ThisKeyAndSubkeys `
    -WhatIf
```

Select an explicit 32-bit or 64-bit view when the default process view is not
the intended target:

```powershell
Get-RegistryKeySecurityDescriptor -Path 'HKLM:\Software\Contoso' `
    -RegistryView Registry64 `
    -Sections Access
```

Registry commands reject native remote paths and remote `RegistryKey` objects.

## Manage service and SCM permissions

Named-service commands use the service name, not its display name, and accept
local `ServiceController` objects through the pipeline:

```powershell
Get-Service -Name BITS |
    Get-ServiceAccessRule -Account 'BUILTIN\Users'

Get-Service -Name BITS |
    Add-ServiceAccessRule `
        -Account 'BUILTIN\Users' `
        -ServiceRights QueryStatus `
        -WhatIf
```

The local Service Control Manager is a separate parameter set with a different
rights enum:

```powershell
Get-ServiceAccessRule -ServiceControlManager

Add-ServiceAccessRule -ServiceControlManager `
    -Account 'BUILTIN\Administrators' `
    -ControlManagerRights Connect `
    -WhatIf
```

Services and the SCM do not support ACL inheritance.

## Manage live-process permissions

Process commands accept a PID, a local `Process` object, module output, or a
caller-owned handle. Start by reading the descriptor for a pinned process
instance:

```powershell
$process = Get-Process -Id $PID
$descriptor = $process |
    Get-ProcessSecurityDescriptor -Sections Access

$descriptor | Get-ProcessAccessRule
```

Preview an access-rule addition:

```powershell
Add-ProcessAccessRule -InputObject $descriptor `
    -Account 'BUILTIN\Users' `
    -ProcessRights QueryLimitedInformation `
    -WhatIf
```

PID targets are pinned by PID and creation time. If the process exits or the PID
is reused, subsequent operations fail instead of changing another process.
Caller-owned handles remain open, and process permissions end with the process
instance.

## Process bounded batches

Pass a target array to use bounded parallel processing. The default limit is
the smaller of eight and the logical processor count; valid values are 1
through 64:

```powershell
$paths = @(
    Get-ChildItem -LiteralPath $path -File |
        Select-Object -ExpandProperty FullName
)

Get-NTFSAccessRule -LiteralPath $paths -ThrottleLimit 8
```

Pipeline records retain streaming semantics and enter separate batches. Build
an array first, as above, when several targets should share one concurrent
batch. Use `ThrottleLimit 1` for deterministic input order.

Inspect redacted counters for the current module instance:

```powershell
Get-WindowsAccessControlMetric -ObjectFamily FileSystem
Get-WindowsAccessControlMetric -CommandName Get-NTFSAccessRule
```

Metrics contain aggregate operation, target, success, failure, and elapsed
counts. They do not contain descriptors or account secrets and reset when the
module instance ends.

## Run with another local identity

Create an explicit local impersonation scope when an operation must run as
another Windows identity:

```powershell
$credential = Get-Credential

Invoke-WindowsAccessControl -Credential $credential -ScriptBlock {
    Get-NTFSAccessRule -LiteralPath 'C:\Data' -ExcludeInherited
}
```

The command restores the caller identity after success or failure. The scope
is thread-local, so work started in a job, runspace, or another thread does not
inherit it. The supplied account must be allowed to log on locally, and the
calling token must be permitted to impersonate.

## Enforce permissions with DSC

The module provides exact selected-section descriptor resources and exact
access-rule presence resources for NTFS, registry keys, named services, the
SCM, pinned processes, SMB shares, Active Directory objects, task folders, and
registered tasks. This example
ensures one NTFS allow ACE is present:

```powershell
Configuration ContosoFilePermissions {
    Import-DscResource -ModuleName WindowsAccessControl

    Node localhost {
        WindowsAccessControlNtfsAccessRule AnalystsRead {
            Path = 'C:\Data'
            Account = 'CONTOSO\Analysts'
            AccessRights = 'Read'
            AccessControlType = 'Allow'
            AppliesTo = 'ThisFolderSubfoldersAndFiles'
            Ensure = 'Present'
        }
    }
}

ContosoFilePermissions -OutputPath 'C:\DSC\ContosoFilePermissions'
Start-DscConfiguration `
    -Path 'C:\DSC\ContosoFilePermissions' `
    -Wait `
    -Verbose `
    -Force
```

Compile and apply classic Windows PowerShell DSC configurations from Windows
PowerShell 5.1. Install the module in a path visible to the SYSTEM Local
Configuration Manager process, such as
`C:\Program Files\WindowsPowerShell\Modules`.

Use an exact-descriptor resource when DSC should own a complete selected DACL
or SACL. Use a rule-presence resource when DSC should own one explicit ACE and
preserve unrelated rules.

The SMB share and Active Directory resources manage the access section only.
A directory resource must declare its own destructive boundary:

```powershell
WindowsAccessControlADObjectAccessRule AnalystsReadProperty {
    DistinguishedName = 'CN=Contoso App,OU=Apps,DC=contoso,DC=com'
    AllowedBaseDistinguishedName = 'OU=Apps,DC=contoso,DC=com'
    Account = 'CONTOSO\Analysts'
    AccessRights = 'ReadProperty'
    AccessControlType = 'Allow'
    Ensure = 'Present'
}
```

Directory resources take no credential. The Local Configuration Manager binds
LDAP as the node's own identity, so a MOF never carries directory credentials.
Supply `ObjectGuid` on `WindowsAccessControlADObjectSecurityDescriptor` when the
configuration must fail rather than converge a recreated object that reuses the
same distinguished name.

The Task Scheduler resources also manage the access section only and declare
their containment boundary with `AllowedRootPath`:

```powershell
WindowsAccessControlTaskFolderAccessRule OperatorsTraverse {
    Path = '\Operations'
    AllowedRootPath = '\Operations'
    Account = 'CONTOSO\Operators'
    AccessRights = 'ReadAndTraverse'
    AccessControlType = 'Allow'
    AppliesTo = 'ThisFolderSubfoldersAndTasks'
    Ensure = 'Present'
}
```

Their compliance check ignores ACE order, because the Task Scheduler service
canonicalizes a stored DACL after every write. Protection state and every ACE
stay exact. Windows evaluates a DACL in order, so these resources cannot detect
or correct a reordering that promotes an allow ACE above a deny ACE; do not
make them the sole drift control for an order-sensitive deny ACE.

## Run against another computer

The module accepts local targets only. To manage another computer, establish a
PowerShell remoting session and run the module on that computer:

```powershell
Invoke-Command -ComputerName 'Server01' -ScriptBlock {
    Import-Module WindowsAccessControl
    Get-NTFSAccessRule -LiteralPath 'C:\Data' -ExcludeInherited
}
```

Do not pass UNC paths, native remote registry paths, remote service
controllers, or remote process objects to module commands.

## Resolve common failures

| Symptom | Check |
| --- | --- |
| A SACL operation reports access denied | Confirm `SeSecurityPrivilege` is present in the process token; the module cannot add a privilege that the token does not contain. |
| An audit rule produces no events | Enable the applicable Windows object access audit policy as well as the SACL rule. |
| An inherited ACE cannot be removed | Change the source ancestor or disable inheritance on the child. |
| A service target is not found | Supply the service name, not the display name. |
| A registry value appears to have no ACL | Manage the containing registry key; values have no independent security descriptor. |
| A process operation reports an identity mismatch | Reacquire the live process and its descriptor; the original pinned instance exited or changed. |
| A batch runs one target at a time | Pass one target array rather than individual streaming pipeline records. |
| The DSC LCM cannot find the resource | Install the module in a machine-wide module path visible to the SYSTEM process. |
| A remote target is rejected | Enter a remote session and run the command locally on the destination computer. |

## See also

- [Project overview and command catalog](../README.md)
- [Migration from NTFSPermission](migration-from-ntfspermission.md)
- [Public API contract](../specs/0003-public-api.md)
- [Security and persistence contract](../specs/0004-security-and-persistence.md)
- [Design research](research.md)
