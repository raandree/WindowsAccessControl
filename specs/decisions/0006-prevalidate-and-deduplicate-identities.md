# Prevalidate and deduplicate identities before batching

- Status: Accepted
- Date: 2026-07-25
- Deciders: user, software-engineer agent

## Context and problem statement

Adding the same rule for several accounts should write a target descriptor once.
An invalid identity must not fail after earlier accounts were already persisted,
and duplicate names or SID aliases must not create duplicate `PassThru` output.

## Decision

Resolve every supplied account before target mutation, deduplicate by resolved
SID with ordinal-insensitive comparison, build all rules in memory, and persist
once per target. Emit one `PassThru` object per unique SID.

## Consequences

- Invalid identities fail closed before persistence.
- Account names and equivalent SID strings collapse to one rule.
- Batch writes are efficient and output reflects the requested unique identities.
- A target descriptor can still merge a new rule with an existing compatible
  ACE according to Windows semantics.

## Alternatives considered

- Persist one account at a time: rejected because a later identity failure
  would create avoidable partial results and repeated writes.
- Deduplicate raw strings: rejected because different names can resolve to the
  same SID.
- Return one result per raw input: rejected because it misrepresents duplicate
  persisted ACEs.

## See also

- [Public API identity input](../0003-public-api.md#identity-input)
- [Requirements FR-3 and NFR-6](../0002-requirements.md)
