# Subtract a schema default only on an exact entry match

- Status: Accepted
- Date: 2026-08-11
- Deciders: user, software-engineer agent

## Context and problem statement

`Get-ADObjectSchemaDefaultAccessRule` returns the entries a `classSchema` object
carries in `defaultSecurityDescriptor`. Nothing consumed it, so a caller reading
a directory object still had to compare by hand to see which explicit entries an
operator actually added. The wanted shape is a filter on
`Get-ADObjectAccessRule` that drops every explicit entry the target's structural
class already grants.

A `defaultSecurityDescriptor` is a template, not a descriptor, and four
properties of that template break naive matching.

1. `CO` (`S-1-3-0`, CREATOR OWNER) is a placeholder. Active Directory replaces
   it when it creates the object, so the entry on the object carries a security
   identifier the template never named. Matching by security identifier
   under-matches. Measured on the acceptance lab: every `CO` entry of the
   `computer` class template reached a newly created computer object as an
   entry for that object's owner.
2. `PS` (`S-1-5-10`, PRINCIPAL SELF) is not a placeholder. It materializes
   verbatim, so matching by security identifier alone treats every `SELF` entry
   as the default whatever rights it grants. That over-matches.
3. Windows sets `INHERITED_ACE` and the descriptor-level auto-inherit control
   bits while it propagates, so raw access control entry flag equality is not a
   property of the entry itself.
4. A schema update rewrites the template without touching objects created
   before it, so today's template does not describe an object created yesterday.

Each of these can make a filter hide an entry an operator added. That is a
security-relevant failure: it makes a live grant invisible in the command people
use to audit grants. Showing a redundant entry is only noise.

## Decision

### The reporting bias

Every ambiguous case resolves toward showing the entry. The filter removes only
an entry it can positively identify as the class default. Anything it cannot
decide is reported.

### What counts as the same entry

An explicit entry on the object is the class default when all six of these equal
a template entry.

| Compared | Why it is part of the entry's identity |
| --- | --- |
| `SID` | The trustee is what the grant is worth. |
| `AccessMask` | All 32 bits, so a widened or narrowed mask is a different entry. |
| `AccessControlType` | An allow and a deny of the same mask are opposites. |
| `InheritanceType` | What the entry propagates to is part of what it grants. |
| `ObjectTypeGuid` | The property, property set, or right the entry is scoped to. |
| `InheritedObjectTypeGuid` | The class the entry propagates to. |

Everything else about either entry is ignored. Any difference in the six means
the entry is reported. The comparison is a set membership test, not a pairing:
one template entry can account for any number of identical entries on the
object, which is the safe direction because it can only ever hide entries that
are all identical to a default.

### The four template cases

1. **A creator placeholder is never matched.** A template entry whose trustee is
   `S-1-3-0` through `S-1-3-3` (CREATOR OWNER, CREATOR GROUP, and their server
   variants) is dropped from the baseline before comparison, so it can never
   hide anything. What that placeholder became on the object is an ordinary
   principal's own entry, and nothing readable from the object distinguishes it
   from a grant an operator made to the same principal.
   `S-1-3-4` (OWNER RIGHTS) is a real trustee rather than a placeholder and is
   matched like any other.
2. **`SELF` is matched, but never on the security identifier alone.** `PS`
   materializes verbatim, so `S-1-5-10` is a sound trustee comparison. The
   over-match the register warns about is prevented by comparing the whole
   six-field entry: an operator grant to `SELF` that differs in mask, type,
   inheritance, or either GUID does not match and is reported.
3. **Access control entry flags are compared as inheritance semantics only.**
   `InheritanceType` already reduces `ContainerInherit`, `InheritOnly`, and
   `NoPropagateInherit` to the five values the module exposes; `INHERITED_ACE`,
   the audit flags, and the descriptor control bits take no part. The flags
   Windows adds during propagation therefore cannot make a default look like an
   operator entry, and cannot make an operator entry look like a default.
   Separately, an inherited entry is never a candidate at all: it came from an
   ancestor, not from this object's class default.
4. **Schema drift is accepted, not detected.** The template is read now and the
   object may predate it, and nothing on the object records which template
   version was applied. Three of the four ways a template can change are already
   safe under the rule above: an entry added to the template is absent from an
   older object and matches nothing; an entry removed from the template leaves
   an entry on the object that matches nothing and is reported; an entry
   modified in the template no longer equals the one on the object and is
   reported. Only one residue is left, and it is reported here rather than
   mitigated: an operator entry that is byte-identical to a template entry added
   by a later schema update is hidden. That residue is the same one the feature
   has without any schema change at all, because an operator can always grant
   exactly what the default already grants, and no readable property separates
   the two.

`whenChanged` on a `classSchema` object was considered as a drift detector and
rejected. It is not replicated, so a domain controller stamps it on every object
it writes during promotion, which would make the filter refuse on every object
older than the newest controller. A gate that fires on an ordinary topology is
noise, not safety.

### Only explicit entries, only the structural class

The baseline is the `defaultSecurityDescriptor` of the object's structural
class, which is the last `objectClass` value Active Directory returns. A
superclass default is not consulted, because Active Directory applies the
structural class template. A structural class that carries no template subtracts
nothing, so every entry is reported.

### The matcher is pure and the switch is opt in

`Select-WindowsADNonDefaultAccessRule` takes two rule collections, holds no
connection, and performs no directory work, so all four cases above are proven
by unit tests without a domain controller. `Get-ADObjectAccessRule` gains
`-ExcludeSchemaDefault`, which defaults to off. This command is what people use
to see what is really on an object, so a filter that hid entries by default
would change the meaning of every existing call.

## Consequences

- A caller that asks for the filter sees the entries an operator added, plus
  every entry the rule could not positively identify, plus every inherited
  entry.
- An entry that materialized from `CO` is always reported, which for a freshly
  created object means the owner's entries stay visible. This is deliberate
  over-reporting.
- Extra directory reads when the switch is used: the RootDSE, the domain
  security identifiers the stored template expands against, and the class
  template itself. The template is cached per class for the invocation, and all
  of them use the connection already bound for the query ([0020](0020-enrich-directory-rules-over-the-bound-connection.md)).
- The result is an aid to reading a descriptor, not an authority on it. Nothing
  mutating consumes the filtered set.

## See also

- [Default security descriptors](https://learn.microsoft.com/en-us/windows/win32/ad/default-security-descriptor)
- [How security descriptors are set on new directory objects](https://learn.microsoft.com/en-us/windows/win32/ad/how-security-descriptors-are-set-on-new-directory-objects)
- [SID strings](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings)
- [0020 Enrich directory rules over the bound LDAP connection](0020-enrich-directory-rules-over-the-bound-connection.md)
- [Specification 0009](../0009-smb-share-and-active-directory-dacl-management.md)
