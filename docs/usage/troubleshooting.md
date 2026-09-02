# Troubleshooting

Most failures in this module are deliberate refusals rather than defects. The
tables below map a symptom to the rule that produced it.

## Quick reference

| Symptom | Check |
| --- | --- |
| A SACL operation reports access denied | Confirm `SeSecurityPrivilege` is present in the process token; the module cannot add a privilege the token does not contain |
| An audit rule produces no events | Enable the applicable Windows object access audit policy as well as the SACL rule |
| An inherited ACE cannot be removed | Change the rule on the source ancestor, or disable inheritance on the child |
| An owner change is denied | Setting an arbitrary owner can need `SeRestorePrivilege`; taking ownership can need `SeTakeOwnershipPrivilege` |
| A service target is not found | Supply the service name, not the display name |
| A registry value appears to have no ACL | Manage the containing key; values have no independent security descriptor |
| `InheritedFrom` is empty on a registry rule | The `Registry32` and `Registry64` views cannot resolve an inheritance source; only the default view can |
| A process operation reports an identity mismatch | Reacquire the live process and its descriptor; the pinned instance exited or the PID was reused |
| A batch runs one target at a time | Pass one target array rather than individual streaming pipeline records |
| A descriptor mutation says a section is not loaded | Read the sections you intend to edit with `-Sections` |
| A `RequireUnchanged` write is rejected | Another writer changed the target; re-read, reapply, and re-read again before retrying |
| A share command rejects the share | Administrative, drive, IPC, print, clustered, and continuously available shares are out of scope |
| A directory write is refused as out of bounds | The target is outside `AllowedBaseDistinguishedName` |
| A directory edit disappeared | Two controllers converged on one survivor; pin one `Server` for both writes |
| A task write is refused | The target is the scheduler root or `\Microsoft`, or the candidate removes or denies Local System |
| A private-key write is refused | Run `Test-CertificatePrivateKeyCriticalBinding` to see which binding blocks it |
| The DSC LCM cannot find the resource | Install the module in a machine-wide module path visible to the SYSTEM process |
| A remote target is rejected | Enter a remote session and run the command locally on the destination computer |

## Permission and privilege failures

A privilege that is **present but disabled** is handled by the module
automatically. A privilege that is **absent from the token** cannot be:

```powershell
Get-WindowsPrivilege
Test-WindowsPrivilege -Name SeSecurityPrivilege
```

If it is absent, run the operation from a process whose token holds it, which
usually means an elevated session or an account granted the privilege by
policy. See
[Safety, preview, and privileges](safety-and-privileges.md#privileges).

## The DACL looks right but access still fails

Work down the layers:

1. **Effective access**, which accounts for group membership, deny rules, and
   ACE order:

   ```powershell
   Get-NTFSItemEffectiveAccess -LiteralPath 'C:\Data' `
       -Account 'CONTOSO\Alice' -AccessRights Modify
   ```

2. **ACE order**, because Windows evaluates a DACL in order:

   ```powershell
   Test-NTFSItemAcl -LiteralPath 'C:\Data' -Section All -PassThru
   ```

3. **The share layer**, when the access is over SMB. A share DACL and the NTFS
   DACL are separate, and the more restrictive one wins:

   ```powershell
   Get-SmbShareEffectiveAccess -Name 'Data$' -Account 'CONTOSO\Alice'
   ```

4. **The logon context.** Both effective-access commands build a context from a
   SID, not from a live logon token, so a rule that depends on `Interactive`,
   `Network`, or another logon-specific group is not reflected.

## An account name will not resolve

```powershell
'CONTOSO\Analysts' | Resolve-WindowsIdentity
Get-NTFSAccessRule -LiteralPath 'C:\Data' -Orphaned
```

An unresolvable SID usually means a deleted account, but an unreachable domain
controller produces the same symptom. Confirm domain connectivity before
deleting anything that `Orphaned` reported.

## A change did not take effect

| Cause | How to confirm |
| --- | --- |
| `WhatIf` was still on the command | Re-read the target and compare |
| A mutator succeeded silently | Mutators are silent by default; add `PassThru` |
| Windows merged the ACE into a broader existing one | Inspect the DACL rather than searching for the exact rule you wrote |
| A DSC rule resource cannot converge under a superset ACE | Model the superset, or use an exact-descriptor resource |
| Another writer overwrote it | Use `RequireUnchanged` on the file system or registry; compare `ConcurrencyToken` for Active Directory |

## An operation targets the wrong object

| Family | Cause |
| --- | --- |
| Registry | The process view differs from the intended view; pass `RegistryView` explicitly |
| Service | A display name was supplied where a service name was required |
| Process | The PID was reused after the original instance exited |
| Certificate private key | The provider and key name now resolve to a different container; pass `ExpectedCanonicalTarget` |
| Active Directory | The distinguished name was recreated; the immutable object GUID is revalidated before every write |

## A remote target is rejected

The module accepts local targets only. Open a remoting session and run it
there:

```powershell
Invoke-Command -ComputerName 'Server01' -ScriptBlock {
    Import-Module WindowsAccessControl
    Get-NTFSAccessRule -LiteralPath 'C:\Data' -ExcludeInherited
}
```

Do not pass UNC paths, native remote registry paths, remote service
controllers, or remote process objects. Active Directory is the exception: its
commands bind LDAP to a domain controller directly.

## Report a problem

If the behavior is not covered above and not stated as a deliberate refusal in
the [specifications](../../specs/README.md), open an issue. Report a suspected
vulnerability privately instead; see the
[security policy](../../SECURITY.md).

## See also

- [Safety, preview, and privileges](safety-and-privileges.md)
- [Diagnostics, batching, and metrics](diagnostics.md)
- [Auditing and SACLs](auditing.md)
