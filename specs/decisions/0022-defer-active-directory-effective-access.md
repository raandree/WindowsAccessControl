# Defer Active Directory effective access

- Status: Accepted
- Date: 2026-07-30
- Deciders: user, software-engineer agent

## Context and problem statement

Task `AD-7` requires either a bounded Active Directory effective-access result
or an explicit, evidence-based deferral. The existing local and SMB commands
answer "what does this descriptor grant this SID" through a SID-derived Windows
Authz context. A directory access decision is not that question: a domain
controller evaluates an inbound authentication context against object-specific
ACEs plus directory-only rules that a generic access check does not apply.

Read-only probes against the disposable lab domain measured the gap.

| Evidence | Measured value |
| --- | ---: |
| Extended rights published in the forest | 81 |
| Of those, property sets | 15 |
| Of those, validated writes | 6 |
| Of those, control-access rights | 60 |
| Schema attributes marked confidential (`searchFlags` bit 128) | 22 |
| `tokenGroups` computed for the disposable lab user | 4 |
| `tokenGroupsGlobalAndUniversal` for the same user | 3 |
| Group SIDs in the caller's live logon token | 16 |
| Group SIDs the directory computes for the same caller | 8 |
| `allowedAttributesEffective` returned for the lab OU | 87 |
| `allowedChildClassesEffective` returned for the lab OU | 70 |
| `sDRightsEffective` returned for the lab OU | 15 |

Three facts follow from those numbers.

1. The principal's evaluated SID set is not reproducible from either side. The
   directory computes 8 group SIDs for the caller while the caller's live logon
   token carries 16, and `tokenGroups` exceeds `tokenGroupsGlobalAndUniversal`
   by the domain-local groups that only a domain-scoped computation adds.
   Neither set equals the context a domain controller builds for a specific
   inbound authentication, which also depends on logon type, claims, armoring,
   and cross-domain SID filtering.
2. A directory decision is not one mask. 15 property sets and 6 validated
   writes expand a single ACE into attribute-level and operation-level results,
   22 confidential attributes require `CONTROL_ACCESS` in addition to
   `READ_PROPERTY`, and the third character of the domain-wide `dSHeuristics`
   attribute switches `ACTRL_DS_LIST_OBJECT` enforcement for the whole domain.
3. Windows already exposes an authoritative answer, but only for the bound
   caller. `allowedAttributesEffective`, `allowedChildClassesEffective`, and
   `sDRightsEffective` are constructed attributes the domain controller
   evaluates in the calling security context. There is no in-box API that asks
   a domain controller for another principal's effective access on a directory
   object.

## Decision

- Do not add an Active Directory effective-access command in this roadmap.
- Do not evaluate a directory descriptor through a locally constructed Authz
  context, with or without an `OBJECT_TYPE_LIST`, and do not present a
  `tokenGroups`-derived reconstruction as an access decision.
- Document the supported alternative: read the domain controller's
  caller-scoped constructed attributes with the in-box directory tooling, and
  read the object's explicit and inherited rules with `Get-ADObjectAccessRule`.
- Require a separately accepted contract, a domain-controller-evaluated
  authority for the named principal, and live cross-principal evidence before
  any future directory effective-access claim is admitted.

## Consequences

- `AD-7` closes as an explicit deferral with measured evidence rather than an
  approximation that would look authoritative.
- Callers cannot mistake a client-side reconstruction for the decision a domain
  controller would make.
- `Get-ADObjectAccessRule` remains the supported way to inspect who is granted
  what, including inherited-rule provenance and resolved GUID names.
- A later increment can still add a caller-scoped constructed-attribute
  reader without renegotiating this boundary, because that result answers a
  different and honestly labeled question.

## Alternatives considered

- Build an Authz context from `tokenGroups` and access-check the directory
  descriptor with an `OBJECT_TYPE_LIST`: rejected because the measured SID sets
  differ from a real logon context and the check would still omit confidential
  attribute, list-object, and validated-write semantics.
- Return only `sDRightsEffective` and the effective attribute lists for the
  bound caller: not rejected on correctness, but deferred because it answers a
  different question than callers ask and needs its own specification, output
  contract, and live evidence.
- Intersect the object DACL with a naive group expansion: rejected for the same
  reason ADR 0017 rejects mask intersection for SMB and NTFS.

## See also

- [Enterprise expansion](../0008-enterprise-access-control-expansion.md)
- [SMB and AD DACL management](../0009-smb-share-and-active-directory-dacl-management.md)
- [Remote and combined effective-access deferral](0017-defer-remote-and-combined-effective-access.md)
