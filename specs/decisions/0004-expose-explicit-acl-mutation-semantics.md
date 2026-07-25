# Expose explicit ACL mutation semantics

- Status: Accepted
- Date: 2026-07-25
- Deciders: user, software-engineer agent

## Context and problem statement

.NET access-control methods named add, set, reset, remove, remove-specific, and
purge have materially different behavior. Hiding those distinctions behind one
ambiguous operation makes accidental data loss likely.

## Decision

Expose separate public contracts:

- Add accumulates rights.
- Set replaces rules for one SID and qualifier.
- Exact removal removes an identical ACE.
- Rights removal subtracts a mask.
- All removal purges rules for one SID.
- Clear removes every explicit rule in one ACL.

Do not expose whole-list reset as a routine rule operation. Every destructive
mode participates in `ShouldProcess` and is directly testable.

## Consequences

- Callers choose destructive reach explicitly.
- Rule-pipeline removal remains ergonomic for exact ACEs.
- More parameter sets are required, but their behavior is predictable.

## Alternatives considered

- One `Remove` behavior selected implicitly from bound parameters: rejected as
  ambiguous and difficult to review.
- Expose `ResetAccessRule`: rejected because it can remove unrelated ACEs.

## See also

- [Public API](../0003-public-api.md)
- [Requirements FR-3 to FR-6](../0002-requirements.md)
