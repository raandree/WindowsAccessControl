# Descriptor editing and concurrency

Each rule command normally performs its own read-modify-write cycle. When
several changes belong to one item, you can read the descriptor once, stage
every edit in memory, and persist once. This page covers that model, the rules
it enforces, and the optimistic concurrency gate.

It applies to the file system and registry key families.

## Stage several edits into one write

```powershell
$descriptor = Get-NTFSItemSecurityDescriptor `
    -LiteralPath 'C:\Data' `
    -Sections Access

$descriptor = $descriptor |
    Add-NTFSAccessRule `
        -Account 'CONTOSO\Analysts', 'CONTOSO\Auditors' `
        -AccessRights Read

$descriptor | Set-NTFSItemSecurityDescriptor -WhatIf
$descriptor | Set-NTFSItemSecurityDescriptor -Confirm:$false
```

Every filesystem access, audit, owner, and inheritance mutator accepts a
descriptor through its `SecurityDescriptor` parameter set, so unrelated edits
can share one write:

```powershell
Get-NTFSItemSecurityDescriptor -LiteralPath 'C:\Data' -Sections Access |
    Add-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Read |
    Set-NTFSAccessRule -Account 'CONTOSO\Auditors' -AccessRights Modify |
    Disable-NTFSItemInheritance -Section Access |
    Set-NTFSItemSecurityDescriptor -Confirm:$false
```

The registry family uses the same model with
`Get-RegistryKeySecurityDescriptor` and `Set-RegistryKeySecurityDescriptor`;
see [Registry keys](registry.md#stage-several-edits-into-one-write).

## Only loaded sections can be edited

A descriptor records the sections it was read with, and only those sections are
written. A mutation that would edit a section you did not load fails instead of
proceeding, because persisting an unloaded section would replace a live ACL
with an empty one:

```powershell
# Fails: the audit section was never read.
Get-NTFSItemSecurityDescriptor -LiteralPath 'C:\Data' -Sections Access |
    Add-NTFSAuditRule -Account 'S-1-1-0' -AccessRights Write -AuditFlags Failure
```

Read the sections you intend to edit:

```powershell
Get-NTFSItemSecurityDescriptor -LiteralPath 'C:\Data' -Sections Access, Audit
```

## Removing an exact rule from a staged descriptor

When the descriptor occupies the pipeline, pass the rule to remove through
`Rule` instead:

```powershell
$rule = Get-RegistryKeyAccessRule -Path 'HKLM:\SOFTWARE\Contoso' -ExcludeInherited |
    Select-Object -First 1

Get-RegistryKeySecurityDescriptor -Path 'HKLM:\SOFTWARE\Contoso' -Sections Access |
    Remove-RegistryKeyAccessRule -Rule $rule |
    Set-RegistryKeySecurityDescriptor -Confirm:$false
```

## Keep the read and the write in one lock

`Edit-*SecurityDescriptor` performs the read, runs your callback, and persists
the result inside one same-target lock with a bounded scope:

```powershell
Edit-NTFSItemSecurityDescriptor `
    -LiteralPath 'C:\Data' `
    -Sections Access `
    -ScriptBlock {
        param($descriptor, $identity)
        $descriptor | Add-NTFSAccessRule `
            -Account $identity `
            -AccessRights Read | Out-Null
    } `
    -ArgumentList 'CONTOSO\Analysts' `
    -WhatIf
```

What the callback contract guarantees:

| Behavior | Detail |
| --- | --- |
| `WhatIf` | The callback runs against a detached descriptor; only the final persistence is skipped |
| Raw side effects | Actions performed directly inside the trusted callback are not covered by that `WhatIf` guarantee |
| Output | Callback output is suppressed; use `PassThru` on the command to receive the edited descriptor |
| Errors | An error, or an attempt to add an unloaded section, prevents the descriptor write |
| Concurrency | Targets run sequentially, so one callback is never invoked concurrently across runspaces |

Pass explicit values through `ArgumentList` rather than relying on closure
capture from the calling scope.

## Reject a stale descriptor

A detached descriptor can drift from the live target. Persistence defaults to
last-writer-wins. Add `RequireUnchanged` to fail instead of overwriting a
concurrent change:

```powershell
$descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath 'C:\Data' -Sections Access |
    Add-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Read

$descriptor | Set-NTFSItemSecurityDescriptor -RequireUnchanged
```

The switch compares the descriptor's `ConcurrencyToken` against the live
selected sections immediately before the write. It narrows the race window and
fails fast; it is not a transactional guarantee.

When it rejects a write:

1. Re-read the descriptor.
2. Reapply the edit.
3. Re-read again before a second `RequireUnchanged` write, because Windows can
   recompute inherited ACEs on write.

`Edit-*SecurityDescriptor` accepts the same switch, which applies it to the
write at the end of the locked scope.

## Families without RequireUnchanged

`RequireUnchanged` exists on the file system and registry commands only.

- **Active Directory** offers no staleness gate because a security descriptor
  is one replicated attribute: two writes made from the same read through two
  controllers converge to one survivor and the losing edit is discarded whole.
  Compare `ConcurrencyToken` yourself and pin one controller. See
  [Active Directory objects](active-directory.md#concurrency-and-replication).
- **Certificate private keys** take a `ConcurrencyToken` parameter on the
  mutators instead. See
  [Certificate private keys](certificate-private-keys.md#concurrency).
- **Services, the SCM, processes, SMB shares, and Task Scheduler** persist
  whole selected sections without a staleness gate.

## Commands on this page

| Family | Commands |
| --- | --- |
| File system | `Get-NTFSItemSecurityDescriptor`, `Edit-NTFSItemSecurityDescriptor`, `Set-NTFSItemSecurityDescriptor` |
| Registry | `Get-RegistryKeySecurityDescriptor`, `Edit-RegistryKeySecurityDescriptor`, `Set-RegistryKeySecurityDescriptor` |

## See also

- [File system](file-system.md)
- [Registry keys](registry.md)
- [In-memory descriptor mutation](../../specs/0007-in-memory-descriptor-mutation.md)
