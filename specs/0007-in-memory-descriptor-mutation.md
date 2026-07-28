# In-memory descriptor mutation

Status: Accepted. This contract defines an optional detached descriptor-editing
model. It reuses the existing access, audit, owner, inheritance, and descriptor
requirements (FR-3 through FR-10) rather than defining new requirement
identifiers. The explicit filesystem round-trip is implemented and verified;
the bounded filesystem scope and registry expansion remain focused follow-up
issues OI-12 and OI-13.

## Context and problem statement

Every mutating command today is path-bound: a single call reads the required
security-descriptor sections, mutates them, and persists the result. This is
correct and safe, but it cannot express workflows that upstream NTFSSecurity
and the underlying .NET `CommonObjectSecurity` model support:

- apply several edits and persist them with one descriptor write
- inspect or diff the complete resulting descriptor before committing it
- construct one descriptor and apply it to more than one target
- stage a complex edit that is awkward to express as separate path-bound calls

The research note records why this is deferred rather than adopted implicitly:
in-memory mutation "would create a second persistence model beside the
path-bound commands. It needs a separate contract rather than hidden
write-through behavior." See
[research sources](../docs/research.md) and
[open issues](open-issues.md). This specification defines that separate
contract so the second model is explicit, section-scoped, and testable.

## Goals

- Provide a detached, editable descriptor object whose mutations do not touch
  the target until an explicit persist step.
- Track which sections are loaded and which are dirty so persistence writes
  only the intended sections, consistent with
  [security and persistence](0004-security-and-persistence.md).
- Reuse the existing explicit mutation semantics (add, set, exact removal,
  rights subtraction, account purge, clear) from
  [public API](0003-public-api.md) without inventing new rule algebra.
- Keep the model local-only, with no new privilege escalation and no remote
  target surface.

## Non-goals

- A general descriptor builder unrelated to a real target object.
- Silent write-through, where a mutation persists as a side effect.
- Whole-DACL reset as a routine operation; it stays an explicit, guarded mode.
- Remote targets, remote registry or service objects, or computer discovery.
- Persistent desired state for a process after that process instance exits.

## Relationship to existing requirements

This contract is an alternative delivery model for the already-accepted
functional requirements, not a new capability set:

- FR-3 through FR-6 (access and audit add, set, remove, purge, clear) become
  available against a detached descriptor as well as a path.
- FR-7 (owner and group) and FR-8 (inheritance) apply to the detached
  descriptor for families that support them.
- FR-9 and FR-10 (section-scoped descriptor copy, versioned backup and
  restore) already produce and consume descriptor objects; this contract makes
  those objects editable and re-persistable.

No new `FR-*` or `NFR-*` identifier is introduced. Traceability is recorded
against the existing identifiers in
[verification and traceability](0005-verification-and-traceability.md) when the
model is implemented.

## Accepted model

The model has two composable shapes. The explicit descriptor round-trip is the
implemented foundation; a bounded editing scope remains planned sugar over that
foundation.

### Recommended: bounded editing scope

An `Edit-*SecurityDescriptor` command reads the selected sections once, runs a
caller script block that mutates the in-memory descriptor, then persists once
under `ShouldProcess`:

```powershell
Edit-NTFSItemSecurityDescriptor -LiteralPath 'C:\Data' -Section Access {
    param($descriptor)
    $descriptor | Add-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Read
    $descriptor | Remove-NTFSAccessRule -Account 'CONTOSO\Temp' -RemovalMode All
}
```

The scope owns the descriptor lifetime, guarantees exactly one read and at most
one write, and never leaves a half-applied target. This mirrors the existing
single-scope pattern used by `Invoke-WindowsAccessControl`.

### Secondary: explicit descriptor round-trip

Existing mutators accept a descriptor through the pipeline or an
`-InputObject` parameter. When bound to a descriptor rather than a path, a
mutator edits the descriptor in memory and returns it instead of persisting. A
dedicated `Set-*SecurityDescriptor` call performs the single write:

```powershell
$descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath 'C:\Data' -Section Access
$descriptor = $descriptor | Add-NTFSAccessRule -Account 'CONTOSO\Analysts' -AccessRights Read
$descriptor | Set-NTFSItemSecurityDescriptor
```

This is more composable but exposes a longer window in which a detached
descriptor can drift from the live target.

## Object ownership and lifetime

- The editable object is the existing
  `WindowsAccessControl.SecurityDescriptor` family type. Its `NativeSecurity`
  property already wraps a mutable descriptor, so no new type is introduced; the
  object records its canonical target, item type, and selected sections.
- The object records its canonical target, item type, and the sections it was
  read with, so a later persist knows exactly what to write.
- The native descriptor remains available as a property for callers that need
  exact Windows semantics, matching the current output contract in
  [public API](0003-public-api.md).

## Section state and persistence

- A detached descriptor tracks its loaded sections and, separately, its dirty
  sections. Persistence writes only dirty sections that were also loaded.
- Persistence uses the same runtime-specific, section-scoped path as
  path-bound commands, so a DACL edit never rewrites an unselected SACL, owner,
  or group. ADR 0003 and ADR 0004 continue to govern this behavior.
- Absent selected SACL and null DACL rules continue to fail closed exactly as
  they do for path-bound persistence.

## ShouldProcess, PassThru, and confirmation

- In-memory mutation has no side effect and therefore does not call
  `ShouldProcess` and does not prompt.
- Only the persist step participates in `ShouldProcess`, `WhatIf`, and
  `Confirm`. Under `WhatIf`, the scope runs the mutation script block against a
  clone and reports the intended write without persisting.
- `PassThru` on the persist step returns the persisted descriptor.

## Stale-target and concurrency behavior

A detached descriptor read at one time and persisted later can race another
writer. The contract must choose one default and one opt-in:

- Default last-writer-wins matches upstream NTFSSecurity and the current .NET
  behavior. It is simple and predictable but silently overwrites a concurrent
  change.
- Optional optimistic concurrency captures a section digest at read time and
  refuses to persist when the live descriptor no longer matches, requiring an
  explicit re-read. This aligns with the whole-record prevalidation stance in
  [security and persistence](0004-security-and-persistence.md).

The bounded editing scope reduces the drift window to a single call and is the
reason it is recommended.

## Object-family scope

| Family | In-memory mutation | Rationale |
| --- | --- | --- |
| File system | In scope | Persistent, hierarchical, already exposes a descriptor and inheritance. |
| Registry key | In scope | Persistent, hierarchical, same descriptor and inheritance model. |
| Named service and SCM | Deferred | Persistent but no inheritance; low incremental value until the two persistent hierarchical families ship. |
| Live process | Excluded | ADR 0022 pins one verified handle per operation and performs the complete read, compare, mutate, and write through it. A detached read-now, persist-later model breaks that pin and reintroduces the PID-reuse race the pin exists to close. |

The process exclusion is a hard design boundary, not a scheduling choice. If a
process editing model is ever wanted, it must re-open and re-verify the pinned
handle at persist time and accept that the descriptor read earlier may no
longer describe the same process instance.

## Security boundary

- Local targets only. No remote registry, service, or file targets and no
  computer discovery.
- No new privilege is enabled. SACL and owner or group edits acquire only the
  already-present, reference-counted operation scopes defined by ADR 0008 and
  ADR 0011, and only at persist time.
- The detached descriptor carries no secret material beyond the SDDL a caller
  could already read through `Get-*SecurityDescriptor`.

## Verification approach

When implemented, this contract is proven test-first against the existing
requirements:

- Unit tests assert that in-memory mutation changes only the intended sections
  and does not persist, using real in-memory security objects with mocked
  persistence.
- Live filesystem and registry tests assert exactly one descriptor write per
  scope, correct section preservation, and `WhatIf` non-persistence.
- A regression test asserts the process family rejects the detached model with
  an explicit, actionable error.
- Traceability is recorded against FR-3 through FR-10 in
  [verification and traceability](0005-verification-and-traceability.md).

## Resolved decisions

1. Shape: adopt both. The explicit descriptor round-trip is the foundation, and
   the bounded editing scope is sugar layered on top of it.
2. Editable type: reuse the existing `WindowsAccessControl.SecurityDescriptor`
   object, whose `NativeSecurity` is already mutable. No new type is added.
3. Concurrency: last-writer-wins by default, with opt-in optimistic concurrency
   in a later phase.
4. Families: filesystem first, then registry key. Named service and SCM stay
   deferred; the live-process family stays excluded.
5. Naming: `Set-*SecurityDescriptor` persists an edited descriptor and
   `Edit-*SecurityDescriptor` is the bounded scope. Both use approved verbs.

## Delivery status

- Phase 1 (delivered): `Set-NTFSItemSecurityDescriptor` persists an edited
  filesystem descriptor with one write, and `Add-NTFSAccessRule` stages an
  access rule on a descriptor in memory without writing. Covered by unit and
  live integration tests including `WhatIf` non-persistence.
- Phase 2 (tracked by OI-12): the `Edit-NTFSItemSecurityDescriptor` bounded scope and the
  remaining filesystem access, audit, owner, and inheritance mutators accepting
  a descriptor.
- Phase 3 (tracked by OI-13): the registry-key family and opt-in optimistic concurrency.

Full requirement traceability rows are added to
[verification and traceability](0005-verification-and-traceability.md) as each
phase lands.

## See also

- [Public API](0003-public-api.md)
- [Security and persistence](0004-security-and-persistence.md)
- [Architecture decisions](decisions/README.md)
- [Open issues](open-issues.md)
- [Research sources](../docs/research.md)
