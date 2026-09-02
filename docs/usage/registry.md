# Registry keys

Registry permissions apply to keys, not to individual values. A registry value
has no independent security descriptor, so manage the key that contains it.

## Target a key

Commands accept provider paths, native local paths, and local `RegistryKey`
objects:

```powershell
Get-RegistryKeyAccessRule -Path 'HKLM:\Software\Contoso' -ExcludeInherited

Get-Item -LiteralPath 'HKLM:\Software\Contoso' |
    Get-RegistryKeyAccessRule -ExcludeInherited
```

Native remote paths and remote `RegistryKey` objects are rejected. To manage
another computer, run the module inside a remoting session on that computer.

## Select a registry view

A 64-bit process sees the 64-bit view by default, and a 32-bit process sees the
redirected 32-bit view. Select the view explicitly when the process default is
not the intended target:

```powershell
Get-RegistryKeySecurityDescriptor -Path 'HKLM:\Software\Contoso' `
    -RegistryView Registry64 `
    -Sections Access
```

| Value | Meaning |
| --- | --- |
| `Default` | The view of the current process |
| `Registry32` | The 32-bit view, including `WOW6432Node` redirection |
| `Registry64` | The 64-bit view |

The view is part of a key's identity for desired state, so a DSC resource that
names `Registry32` and one that names `Registry64` manage different targets.

Windows does not resolve inheritance sources for the `Registry32` and
`Registry64` views, so `InheritedFrom` stays empty there. The default view
reports the ancestor key the same way the file system family does.

## Access rules

```powershell
Add-RegistryKeyAccessRule -Path 'HKLM:\Software\Contoso' `
    -Account 'BUILTIN\Users' `
    -AccessRights ReadKey `
    -AppliesTo ThisKeyAndSubkeys `
    -WhatIf

Set-RegistryKeyAccessRule -Path 'HKLM:\Software\Contoso' `
    -Account 'BUILTIN\Users' `
    -AccessRights ReadKey `
    -WhatIf
```

Exact removal consumes a path-bound rule from the matching `Get` command:

```powershell
Get-RegistryKeyAccessRule -Path 'HKLM:\Software\Contoso' `
    -Account 'BUILTIN\Users' `
    -ExcludeInherited |
    Remove-RegistryKeyAccessRule -WhatIf
```

`Clear-RegistryKeyAccessRule` removes every explicit rule and keeps inherited
rules:

```powershell
Clear-RegistryKeyAccessRule -Path 'HKLM:\Software\Contoso' -WhatIf
```

Access and audit mutations preserve inherited, unknown, and unrelated ACEs.

## Rule scope with AppliesTo

Registry keys use a smaller inheritance vocabulary than the file system,
because a key has subkeys but no separate leaf object type:

| Value | Applies to |
| --- | --- |
| `ThisKeyOnly` | The current key only |
| `ThisKeyAndSubkeys` | The current key and every subkey |
| `SubkeysOnly` | Subkeys only |
| `ThisKeyAndSubkeysOneLevel` | The current key and its immediate subkeys |
| `SubkeysOnlyOneLevel` | Immediate subkeys only |

The default is `ThisKeyOnly`.

## Audit rules

Registry audit rules mirror the access-rule commands and need
`SeSecurityPrivilege`:

```powershell
Get-RegistryKeyAuditRule -Path 'HKLM:\Software\Contoso' `
    -Account 'S-1-1-0' `
    -ExcludeInherited |
    Remove-RegistryKeyAuditRule -Confirm:$false
```

Registry SACL reads and writes temporarily enable `SeSecurityPrivilege` when it
is present in the process token, then restore its original state. See
[Auditing and SACLs](auditing.md).

## Inheritance

```powershell
Get-RegistryKeyInheritance -Path 'HKLM:\Software\Contoso' -Section All

Disable-RegistryKeyInheritance -Path 'HKLM:\Software\Contoso' `
    -Section All `
    -PreserveInherited $true

Enable-RegistryKeyInheritance -Path 'HKLM:\Software\Contoso' -Section All
```

`Section` selects `Access`, `Audit`, or `All`, so audit inheritance can be
changed without touching the DACL.

## Stage several edits into one write

The registry family uses the same in-memory descriptor model as the file
system:

```powershell
Get-RegistryKeySecurityDescriptor -Path 'HKLM:\SOFTWARE\Contoso' -Sections Access |
    Add-RegistryKeyAccessRule -Account 'CONTOSO\Analysts' -AccessRights ReadKey |
    Set-RegistryKeySecurityDescriptor -Confirm:$false
```

Exact ACE removal takes the rule through `Rule`, because the descriptor
occupies the pipeline:

```powershell
$rule = Get-RegistryKeyAccessRule -Path 'HKLM:\SOFTWARE\Contoso' -ExcludeInherited |
    Select-Object -First 1

Get-RegistryKeySecurityDescriptor -Path 'HKLM:\SOFTWARE\Contoso' -Sections Access |
    Remove-RegistryKeyAccessRule -Rule $rule |
    Set-RegistryKeySecurityDescriptor -Confirm:$false
```

Keep the read, the edit, and the write in one same-target lock with
`Edit-RegistryKeySecurityDescriptor`:

```powershell
Edit-RegistryKeySecurityDescriptor `
    -Path 'HKLM:\SOFTWARE\Contoso' `
    -Sections Access `
    -ScriptBlock {
        param($descriptor)
        $descriptor | Clear-RegistryKeyAccessRule -Account 'CONTOSO\Legacy' | Out-Null
    } `
    -Confirm:$false
```

See [Descriptor editing and concurrency](descriptor-editing.md) for the section
rules, `RequireUnchanged`, and what the callback guarantees under `WhatIf`.

## Commands on this page

| Area | Commands |
| --- | --- |
| Descriptors | `Get-RegistryKeySecurityDescriptor`, `Edit-RegistryKeySecurityDescriptor`, `Set-RegistryKeySecurityDescriptor` |
| Access rules | `Get-RegistryKeyAccessRule`, `Add-RegistryKeyAccessRule`, `Set-RegistryKeyAccessRule`, `Remove-RegistryKeyAccessRule`, `Clear-RegistryKeyAccessRule` |
| Audit rules | `Get-RegistryKeyAuditRule`, `Add-RegistryKeyAuditRule`, `Set-RegistryKeyAuditRule`, `Remove-RegistryKeyAuditRule`, `Clear-RegistryKeyAuditRule` |
| Inheritance | `Get-RegistryKeyInheritance`, `Enable-RegistryKeyInheritance`, `Disable-RegistryKeyInheritance` |

## See also

- [File system](file-system.md)
- [Auditing and SACLs](auditing.md)
- [Descriptor editing and concurrency](descriptor-editing.md)
