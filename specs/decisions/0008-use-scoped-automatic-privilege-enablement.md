# Use scoped automatic privilege enablement

- Status: Accepted
- Date: 2026-07-25
- Deciders: user, software-engineer agent
- Supersedes: ADR 0007 for production command behavior

## Context and problem statement

SACL, arbitrary-owner, restore, and some process operations require privileges
that are commonly present but disabled in an elevated token. Requiring every
caller and DSC resource to coordinate privilege state makes otherwise safe
commands difficult to compose. Enabling privileges on import or leaving them
enabled would broaden authority beyond the operation that needs it.

## Decision

- Acquire each required privilege immediately before opening the target handle
  or performing the privileged operation.
- Enable a privilege only when it already exists in the current token. Report a
  terminating, actionable error when it is absent.
- Reference-count privilege scopes across parallel workers and restore the
  original enabled state in `finally` when the final scope exits.
- Keep explicit public privilege commands for deliberate token management.
- Never enable privileges on module import and never seize ownership as an
  authorization fallback.
- Redact token and descriptor details from normal output.

## Consequences

- Elevated callers and DSC resources can use SACL and restore operations without
  separate privilege choreography.
- Privilege lifetime is bounded to the operation, including parallel batches.
- The native scope implementation and failure cleanup become security-critical
  and require independent review and live tests.
- A token that does not contain the required privilege still cannot acquire it.

## Alternatives considered

- Keep all privilege enablement explicit: superseded by the signed product
  requirement because it makes DSC and batch operations unnecessarily fragile.
- Enable privileges on import: rejected because authority would remain broadened
  for the module lifetime.
- Retry after taking ownership: rejected because it changes an unrelated
  security boundary and rollback can fail.

## See also

- [Expansion design](../0006-windows-access-control-expansion.md#security)
- [Superseded privilege decision](0007-keep-privilege-changes-explicit.md)
