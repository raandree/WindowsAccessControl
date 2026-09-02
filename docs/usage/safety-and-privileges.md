# Safety, preview, and privileges

Every command in this module changes or reads an authorization decision, so the
safety surface is part of the API rather than an afterthought. This page covers
previewing a change, the confirmation model, the privileges Windows requires,
and running as another local identity.

## Preview every mutation

Rule, descriptor, owner, inheritance, backup, restore, and privilege mutators
support `WhatIf` and `Confirm`. Preview a change, review the target and the
action, then run the same command without `WhatIf`:

```powershell
$grantParameters = @{
    LiteralPath  = 'C:\Data'
    Account      = 'CONTOSO\Analysts'
    AccessRights = 'Modify'
    AppliesTo    = 'ThisFolderSubfoldersAndFiles'
}

Add-NTFSAccessRule @grantParameters -WhatIf
Add-NTFSAccessRule @grantParameters -Confirm:$false -PassThru
```

Use `Confirm:$false` only when the preview has been reviewed, or when
established automation provides equivalent controls.

## The confirmation model

Commands declare an impact level, and PowerShell prompts according to
`$ConfirmPreference`:

| Impact | Commands | Default behavior |
| --- | --- | --- |
| Medium | `Add-*` and `Set-*` rule commands | Runs without prompting |
| High | `Clear-*`, `Remove-*`, owner, copy, restore, private-key, and privilege commands | Prompts before acting |

Two consequences are worth knowing before you script against it:

- Interactive confirmation forces sequential execution, so prompts never
  overlap even when a command is given a target array.
- A non-interactive host cannot answer a prompt. Pass `-Confirm:$false`
  explicitly in scheduled or detached automation rather than relying on the
  host to suppress it.

## Output is opt-in

Mutators are silent by default and expose `PassThru` where output is useful:

```powershell
Add-NTFSAccessRule -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Analysts' `
    -AccessRights Read `
    -Confirm:$false `
    -PassThru
```

Silence means the operation succeeded. Failures surface as terminating or
non-terminating errors, not as a missing object.

## Deny rules

Windows evaluates an explicit deny ACE before the corresponding allow ACE, and
a deny rule that names a group can lock out accounts nobody was thinking about.
Check inherited and group-based access first:

```powershell
Get-NTFSAccessRule -LiteralPath 'C:\Data' |
    Where-Object AccessControlType -EQ 'Deny'

Get-NTFSItemEffectiveAccess -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Alice' `
    -AccessRights Modify
```

The certificate private-key family refuses to create a deny ACE at all, because
a deny rule naming a group that contains SYSTEM or Administrators would make
the key unusable while every per-account check still passed. See
[Certificate private keys](certificate-private-keys.md#what-a-write-refuses).

## Inherited rules cannot be removed from a child

An inherited ACE belongs to the ancestor that defines it. Change the rule on
that ancestor, or change inheritance on the child:

```powershell
Get-NTFSItemInheritance -LiteralPath 'C:\Data' -Section All
Disable-NTFSItemInheritance -LiteralPath 'C:\Data' -Section Access -WhatIf
```

See [File system](file-system.md#change-inheritance).

## Privileges

Some operations need a Windows privilege that an ordinary token does not enable
by default:

| Operation | Privilege |
| --- | --- |
| Read or write any SACL | `SeSecurityPrivilege` |
| Set an owner other than yourself | `SeRestorePrivilege` |
| Take ownership of an object you do not own | `SeTakeOwnershipPrivilege` |
| Open a process you would otherwise be denied | `SeDebugPrivilege` |

The module scopes a required privilege to the operation, reference-counts
nested use across parallel workers, and restores the original state afterwards.
It can only enable a privilege that is **already present** in the process
token; it cannot grant one. A privilege that the token does not contain
produces an explicit failure rather than a silent skip.

Inspect the token before an audit or ownership operation:

```powershell
Get-WindowsPrivilege
Test-WindowsPrivilege -Name SeSecurityPrivilege
```

`Get-WindowsPrivilege` distinguishes a privilege that is present but disabled
from one that is absent from the token entirely. Only the second case cannot be
fixed by the module.

Deliberate token management remains available:

```powershell
Enable-WindowsPrivilege -Name SeSecurityPrivilege
Disable-WindowsPrivilege -Name SeSecurityPrivilege
```

Both fail explicitly when Windows reports `ERROR_NOT_ALL_ASSIGNED`.

## Run with another local identity

Create an explicit local impersonation scope when an operation must run as a
different Windows identity:

```powershell
$credential = Get-Credential

Invoke-WindowsAccessControl -Credential $credential -ScriptBlock {
    Get-NTFSAccessRule -LiteralPath 'C:\Data' -ExcludeInherited
}
```

What the scope does and does not do:

- The caller identity is restored after success and after failure.
- The password is never written to module output, logs, metrics, or a backup
  document.
- The scope is thread-local. Work started in a job, runspace, or another thread
  runs under that execution context's identity instead.
- It does not enable remote target syntax. The local-only boundary still
  applies.
- The supplied account must be allowed to log on locally, and the calling token
  must be permitted to impersonate.

## Safety model summary

- Every mutator supports `WhatIf` and `Confirm`.
- A DACL-only operation persists DACL state only and never requests SACL
  privileges.
- Access and audit mutations preserve inherited, unknown, and unrelated ACEs.
- Descriptor writes persist only the sections that were selected and read.
- FileSystem path resolution follows reparse points such as symbolic links and
  junctions, and a path can change between resolution and persistence. Do not
  accept untrusted path input for a privileged operation.
- Extended `\\?\` and `\\?\UNC\` paths are passed to the host runtime; support
  depends on the active PowerShell and Windows long-path configuration.

## See also

- [Auditing and SACLs](auditing.md)
- [Descriptor editing and concurrency](descriptor-editing.md)
- [Troubleshooting](troubleshooting.md)
- [Security and persistence contract](../../specs/0004-security-and-persistence.md)
