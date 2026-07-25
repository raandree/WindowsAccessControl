# Migrate from NTFSPermission

`NTFSPermission` was unpublished and had no known external consumers when it was
renamed to `WindowsAccessControl`. The rename is intentionally hard: the new
package does not export compatibility aliases, but it preserves the original
module GUID and NTFS-specific command nouns.

## Package paths

| Before | After |
| --- | --- |
| `NTFSPermission.psd1` | `WindowsAccessControl.psd1` |
| `NTFSPermission.psm1` | `WindowsAccessControl.psm1` |
| `NTFSPermission.Format.ps1xml` | `WindowsAccessControl.Format.ps1xml` |
| `about_NTFSPermission` | `about_WindowsAccessControl` |
| `output/module/NTFSPermission` | `output/module/WindowsAccessControl` |

Update imports to use the new manifest or package name:

```powershell
Import-Module WindowsAccessControl
```

## Renamed commands

Filesystem-specific commands retain their `NTFS` nouns. Cross-domain commands
use `Windows` nouns:

| Before | After |
| --- | --- |
| `Resolve-NTFSIdentity` | `Resolve-WindowsIdentity` |
| `Get-NTFSPrivilege` | `Get-WindowsPrivilege` |
| `Test-NTFSPrivilege` | `Test-WindowsPrivilege` |
| `Enable-NTFSPrivilege` | `Enable-WindowsPrivilege` |
| `Disable-NTFSPrivilege` | `Disable-WindowsPrivilege` |

Parameter names and pipeline behavior for those commands remain unchanged.

## Output type names

Stable PowerShell type names now use the `WindowsAccessControl` prefix. For
example, update checks for `NTFSPermission.AccessRule` to
`WindowsAccessControl.AccessRule`. The property contracts remain unchanged for
the original NTFS command surface.

## Compatibility policy

No compatibility package is shipped because the old package was never
published. If evidence of an external consumer appears before release, provide a
separately tested `NTFSPermission` compatibility package that imports
`WindowsAccessControl`; do not add permanent aliases to the new manifest.

## See also

- [WindowsAccessControl expansion design](../specs/0006-windows-access-control-expansion.md)
- [Rename architecture decision](../specs/decisions/0009-rename-module-to-windows-access-control.md)
