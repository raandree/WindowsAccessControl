# Active Directory objects

Active Directory is the one family that crosses a machine boundary by design.
Its commands bind LDAP directly to a domain controller, with Kerberos, signing,
and sealing all mandatory.

This family manages the DACL only. It exposes no SACL and no owner or group
mutation. It computes no effective access either; it can only forward the
answer the domain controller computes for the calling identity.

## Choose a domain controller

`Server` is optional. Omit it and the command locates one writable domain
controller in the computer's domain and pins it for every target in that
invocation:

```powershell
$baseDn   = 'OU=Applications,DC=example,DC=test'
$targetDn = "OU=Database,$baseDn"

Get-ADObjectAccessRule -DistinguishedName $targetDn
Get-ADObjectAccessRule -Server 'dc01.example.test' -DistinguishedName $targetDn
```

Pin an explicit `Server` when several edits must land on the same replica; see
[Concurrency and replication](#concurrency-and-replication).

`Credential` is optional too, and is used only for the direct LDAP bind.

## Inspect delegation

```powershell
Get-ADObjectAccessRule -DistinguishedName $targetDn
```

| Parameter | Effect |
| --- | --- |
| `Account` | Returns rules for the named accounts or SIDs only |
| `ExcludeInherited` | Returns explicit rules only |
| `ExcludeExplicit` | Returns inherited rules only |
| `ExcludeSchemaDefault` | Hides the entries the object's class grants by default |

### See only what an operator configured

Every new directory object starts with the entries its structural class applies
through `defaultSecurityDescriptor`. Without a baseline, each of those looks
like deliberate delegation. `ExcludeSchemaDefault` removes them:

```powershell
Get-ADObjectAccessRule -DistinguishedName $targetDn `
    -ExcludeInherited `
    -ExcludeSchemaDefault
```

A rule is excluded only when a template entry matches it on account, access
mask, access control type, inheritance, and both object type GUIDs. Anything
the comparison cannot decide is reported rather than hidden, inherited rules
are never excluded, and neither are the entries a template placeholder such as
`CREATOR OWNER` became.

Read the template itself when you want to know what the baseline is:

```powershell
Get-ADObjectSchemaDefaultAccessRule -ObjectClass user
Get-ADObjectSchemaDefaultAccessRule -Server 'dc01.example.test' -ObjectClass user, group
```

The stored descriptor is SDDL that names domain-relative aliases such as `DA`
and `EA`. Those are expanded against the SID of the domain the selected
controller serves, and against the forest root domain SID where the alias is
forest wide, rather than against the calling computer's own domain. The result
describes a template, not the state of any object, so it is not path bound and
cannot be piped into a rule mutator.

### Where an inherited rule comes from

```powershell
Get-ADObjectAccessRule -DistinguishedName $targetDn -ExcludeExplicit |
    Format-Table Account, AccessRightsDisplay, ObjectTypeName,
        InheritedObjectTypeName, InheritedFrom
```

`InheritedFrom` names the nearest ancestor object that holds the originating
explicit inheritable ACE. Unlike the other families, it is inferred by walking
the ancestor chain over the same bound connection, because no Windows
inheritance-source API can honor the selected domain controller and credential.
It stays empty when an ancestor in the chain cannot be read, so an unreadable
parent costs the column rather than the rules.

`ObjectTypeName` and `InheritedObjectTypeName` resolve schema classes,
attributes, property sets, validated writes, and extended rights. They stay
empty for a GUID that resolves to none of those.

## Delegate access

Every mutator requires an explicit `AllowedBaseDistinguishedName`. It is the
containment boundary: the command refuses to write outside it, so a typo in a
distinguished name cannot reach the domain root.

```powershell
Add-ADObjectAccessRule `
    -Server 'dc01.example.test' `
    -DistinguishedName $targetDn `
    -AllowedBaseDistinguishedName $baseDn `
    -Account 'CONTOSO\Analysts' `
    -AccessRights ReadProperty `
    -InheritanceType Children `
    -WhatIf
```

Use `ObjectType` and `InheritedObjectType` GUIDs for property, extended-right,
or child-object-specific ACEs. The output retains those GUIDs, which is what
makes an exact removal possible later.

Replace, subtract, or purge with the remaining mutators. Each one matches on
account, qualifier, and **both** object GUIDs, so an ACE scoped to a different
GUID pair is preserved rather than folded into a common ACE:

```powershell
Set-ADObjectAccessRule `
    -DistinguishedName $targetDn `
    -AllowedBaseDistinguishedName $baseDn `
    -Account 'CONTOSO\Analysts' `
    -AccessRights 'ReadProperty, WriteProperty'

Remove-ADObjectAccessRule `
    -DistinguishedName $targetDn `
    -AllowedBaseDistinguishedName $baseDn `
    -Account 'CONTOSO\Analysts' `
    -AccessRights WriteProperty `
    -RemovalMode Rights

Remove-ADObjectAccessRule `
    -DistinguishedName $targetDn `
    -AllowedBaseDistinguishedName $baseDn `
    -Account 'CONTOSO\Analysts' `
    -RemovalMode All

Clear-ADObjectAccessRule `
    -DistinguishedName $targetDn `
    -AllowedBaseDistinguishedName $baseDn
```

`Clear-ADObjectAccessRule` removes every explicit ACE, or only the selected
accounts when `Account` is supplied, and never touches an inherited ACE.

## Two gates every write passes

- **The allowed base.** A write outside `AllowedBaseDistinguishedName` is
  refused, and the immutable object GUID is revalidated before every write, so
  an object recreated under the same distinguished name is not written to by
  accident.
- **Manageability.** A mutator refuses to write a DACL that would grant no
  principal `WriteDacl` on the object, because only its owner could then manage
  it. Apply such a descriptor deliberately with
  `Set-ADObjectSecurityDescriptor`.

## Ask the domain controller what you may write

```powershell
Get-ADObjectCallerEffectiveAccess -DistinguishedName $targetDn
```

```text
DistinguishedName             Account          WritableSections     Attributes ChildClasses Context
-----------------             -------          ----------------     ---------- ------------ -------
OU=Database,OU=Applications,… CONTOSO\alice    Owner, Group, Access         87           70 DomainControllerCallerScoped
```

The module computes none of that. It requests three constructed attributes and
formats what the controller returned:

| Attribute | Reported as |
| --- | --- |
| `allowedAttributesEffective` | `WritableAttribute`, `WritableAttributeCount` |
| `allowedChildClassesEffective` | `CreatableChildClass`, `CreatableChildClassCount` |
| `sDRightsEffective` | `SDRightsEffective`, `WritableDescriptorSection` |

`WritableDescriptorSection` uses the module's own section vocabulary, where
`Access` is the DACL and `Audit` is the SACL. The lists are sorted, so two
results can be compared:

```powershell
(Get-ADObjectCallerEffectiveAccess -DistinguishedName $targetDn).WritableAttribute
```

### Read the four limits before you trust it

- **It is scoped to the bind, and there is no `Account` parameter.** No in-box
  interface asks a domain controller what somebody else may do. `Credential`
  changes the bind and therefore changes the answer, which is the only
  supported way to evaluate a different principal.
- **It is a write-side answer.** Nothing here reports read access. A
  confidential attribute you can read does not appear if you cannot write it.
- **Extended rights are invisible.** Reset Password and the other
  control-access rights have no representation in these three attributes, and a
  validated write shows only as the attribute it governs.
- **It is one controller at one moment.** A descriptor that has not replicated
  yet produces a different answer elsewhere.

## Why there is still no general effective-access command

A domain controller decides directory access with the token it builds for a
specific inbound authentication, plus directory-only rules such as confidential
attributes, property sets, validated writes, and list-object mode. A locally
constructed access check reproduces none of that, so a number the module
computed for an account you merely named would be confidently wrong.

That is why the command above forwards the controller's own answer instead of
producing one, and why `Get-ADObjectAccessRule` remains the way to see who is
granted what.

## Concurrency and replication

A security descriptor is one replicated attribute. Two writes made from the
same read through two domain controllers converge to **one survivor**, and the
losing edit is discarded whole. That is why the directory commands offer no
`RequireUnchanged` gate: refusing a stale write on one replica would not
prevent the loss.

Compare `ConcurrencyToken` yourself, and write through one pinned controller
when both edits must survive:

```powershell
$before = Get-ADObjectSecurityDescriptor -Server $server -DistinguishedName $dn

# ... time passes ...

$now = Get-ADObjectSecurityDescriptor -Server $server -DistinguishedName $dn
if ($now.ConcurrencyToken -cne $before.ConcurrencyToken) {
    throw 'Another writer changed the object. Re-read and reapply the edit.'
}
```

`ConcurrencyToken` is content derived, so one converged descriptor reports the
same token through every controller, and a write on another controller changes
it once it replicates.

## Portability

Directory descriptors use record version 2 and bind the server plus the
distinguished name, `objectGUID`, and domain naming context. A restore requires
an explicit allowed organizational unit:

```powershell
Get-ADObjectSecurityDescriptor -DistinguishedName $targetDn |
    Backup-WindowsSecurityDescriptor -DestinationPath 'C:\Backup\directory.json'

Restore-WindowsSecurityDescriptor `
    -BackupPath 'C:\Backup\directory.json' `
    -AllowedBaseDistinguishedName $baseDn `
    -Confirm:$false
```

A restore can bind a different writable domain controller than the backup did,
because identity is matched on the immutable `objectGUID` and the recorded
domain rather than on the server name.

## Commands on this page

| Area | Commands |
| --- | --- |
| Descriptors | `Get-ADObjectSecurityDescriptor`, `Set-ADObjectSecurityDescriptor` |
| Access rules | `Get-ADObjectAccessRule`, `Add-ADObjectAccessRule`, `Set-ADObjectAccessRule`, `Remove-ADObjectAccessRule`, `Clear-ADObjectAccessRule` |
| Schema baseline | `Get-ADObjectSchemaDefaultAccessRule` |
| Caller-scoped access | `Get-ADObjectCallerEffectiveAccess` |

## See also

- [Desired State Configuration](dsc.md#active-directory-resources)
- [Backup, restore, and copy](backup-and-restore.md)
- [SMB share and Active Directory DACL management](../../specs/0009-smb-share-and-active-directory-dacl-management.md)
- [Active Directory multi-controller behavior](../../specs/0016-active-directory-multi-controller-behavior.md)
- [Active Directory caller-scoped effective access](../../specs/0018-active-directory-caller-effective-access.md)
