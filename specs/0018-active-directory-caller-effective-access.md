# Active Directory caller-scoped effective access

Status: Accepted. This specification defines a read-only reader for the
caller-scoped constructed attributes a domain controller evaluates on a
directory object.

## Why this is not the deferred command

ADR 0022 defers Active Directory effective access. It refuses a locally
constructed Authz result, a `tokenGroups` reconstruction, and any claim about a
principal the caller merely names. That refusal stands unchanged.

The same decision record already anticipated this increment: it lists
"return only `sDRightsEffective` and the effective attribute lists for the bound
caller" as an alternative that was *not rejected on correctness*, and its
consequences state that a later increment can add a caller-scoped
constructed-attribute reader "without renegotiating this boundary, because that
result answers a different and honestly labeled question".

`Get-ADObjectCallerEffectiveAccess` is that reader. It computes nothing. Every
value in its output is a constructed attribute the domain controller evaluated
in the security context of the LDAP bind that read it.

## Scope

The command accepts one or more distinguished names, the same optional `Server`,
`Credential`, `TimeoutSeconds`, and `ThrottleLimit` as the rest of the directory
family, and returns one result per target.

It performs a single base-scope search per target requesting exactly three
constructed attributes:

| Attribute | Question the controller answers |
| --- | --- |
| `allowedAttributesEffective` | Which attributes may the bound caller write? |
| `allowedChildClassesEffective` | Which classes may the bound caller create here? |
| `sDRightsEffective` | Which security-descriptor sections may the bound caller write? |

Constructed attributes are evaluated per request and are never returned by a
wildcard attribute request, so they must be named explicitly.

## Authorization boundary

The result is scoped to the identity of the LDAP bind, and to nothing else.

- The command exposes no `Account` parameter. There is no in-box way to ask a
  domain controller what another principal's effective access is, and inventing
  one is exactly what ADR 0022 refuses.
- `Credential` changes the bind and therefore changes the answer. That is the
  only supported way to evaluate a different principal, and it requires holding
  that principal's credential.
- Output sets `AuthorizationContext` to `DomainControllerCallerScoped` and
  `Account` to the identity the bind used, so a stored or piped result cannot be
  mistaken for a claim about somebody else.

## What the answer does not cover

The three attributes are a write-side answer. Stating the gaps is part of the
contract:

- No attribute reports read access. An attribute absent from
  `allowedAttributesEffective` may still be readable, and a confidential
  attribute the caller can read does not appear because it cannot be written.
- `allowedChildClassesEffective` answers creation only. It says nothing about
  deleting, moving, or renaming a child.
- Extended rights and validated writes are not enumerated. A validated write is
  visible only through the attribute it governs, and a control-access right such
  as Reset Password has no representation in these three attributes at all.
- The answer is one controller's evaluation at one moment. A descriptor that has
  not replicated yet produces a different answer on another controller.

`Get-ADObjectAccessRule` remains the command that reports who is granted what.

## Output contract

Type name `WindowsAccessControl.ADObjectCallerEffectiveAccess`, with the
directory family's usual target identity (`Server`, `DistinguishedName`,
`ObjectGuid`, `CanonicalTarget`) plus:

| Property | Contract |
| --- | --- |
| `Account` | The identity the LDAP bind used |
| `WritableAttribute` | Sorted `allowedAttributesEffective` names |
| `WritableAttributeCount` | Count of the above |
| `CreatableChildClass` | Sorted `allowedChildClassesEffective` names |
| `CreatableChildClassCount` | Count of the above |
| `SDRightsEffective` | The raw `sDRightsEffective` mask |
| `WritableDescriptorSection` | The same mask as `WindowsSecurityDescriptorSection` |
| `AuthorizationContext` | Always `DomainControllerCallerScoped` |

`WindowsSecurityDescriptorSection` names the DACL `Access` and the SACL `Audit`,
which is the module's existing vocabulary; the bits are identical to the ones
`sDRightsEffective` carries.

LDAP cannot return an empty attribute, so a controller that grants none of a
category returns nothing for it. An absent list is reported as an empty array
and an absent `sDRightsEffective` as zero, which is what "none" means here.

The command is read-only, supports no `ShouldProcess`, mutates nothing, and
reuses the directory family's existing target resolution, so the naming-context,
partition, and unique-resolution refusals apply unchanged. That resolution does
not request `nTSecurityDescriptor`, because no output property depends on it, so
a caller without read-control access to the object's security descriptor still
receives a result. The three-attribute request goes through the same directory
search seam as the family's other reads: an object deleted after target
resolution fails with `ItemNotFoundException` naming it, and a response without
exactly one entry fails as an object that did not resolve uniquely.

## Verification

- Unit tests cover the public parameter contract, the absence of an `Account`
  parameter, one result per target, the bind identity reported for a supplied
  credential, sorted list output, the section mask mapping including the empty
  case, and the context label.
- Unit tests replace the LDAP search that target resolution sends and prove
  that neither the prevalidation of every target nor the per-target resolution
  requests `nTSecurityDescriptor` or the security-descriptor flag control, and
  that a caller whose entry carries no descriptor still receives a result.
- Unit tests replace the three-attribute base-scope request at the directory
  search seam and prove that it is sent there, that a response without exactly
  one entry fails, and that an absent `sDRightsEffective` is reported as zero.
  Live domain-lab evidence proves the request against a controller, and deletes
  a disposable organizational unit after target resolution, just before the
  request reaches the controller, to prove that the command reports the
  object as not found.
- Live domain-lab evidence reads a real organizational unit as a domain
  administrator and proves a nonzero section mask, a nonempty writable-attribute
  list, and a nonempty creatable-child-class list against the same object
  `Get-ADObjectAccessRule` reports rules for. It also evaluates the delegated
  operator on a disposable organizational unit whose protected DACL grants it
  property reads but not read-control access: the command returns a result,
  while `Get-ADObjectSecurityDescriptor` fails with the read-control error.

## See also

- [Public API](0003-public-api.md)
- [SMB and AD DACL management](0009-smb-share-and-active-directory-dacl-management.md)
- [Enterprise portability and desired state](0013-enterprise-portability-and-desired-state.md)
- [Directory effective-access deferral](decisions/0022-defer-active-directory-effective-access.md)
