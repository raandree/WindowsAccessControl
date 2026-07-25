# Keep privilege changes explicit and acceptance gated

- Status: Accepted
- Date: 2026-07-25
- Deciders: user, software-engineer agent

## Context and problem statement

SACL and arbitrary-owner workflows depend on privileges that a normal process
often does not contain. Automatically enabling broad privileges or temporarily
changing owner state hides authority changes. Conversely, mocked tests must not
be described as successful live privileged writes.

## Decision

- Privilege inventory is read-only and opens the token for query only.
- Enable and disable operations are explicit public commands and participate in
  `ShouldProcess`.
- `ERROR_NOT_ALL_ASSIGNED` is checked because `AdjustTokenPrivileges` cannot add
  a privilege to a token.
- The module never enables broad privileges during import or as command fallback.
- Privileged acceptance tests are always discovered. They enable only required
  privileges already present in the isolated test token, restore original token
  state afterward, and skip with an exact reason when unavailable.
- Authorization failure never triggers temporary owner takeover.

## Consequences

- Read operations do not silently broaden process authority.
- Non-elevated CI provides honest skip evidence rather than false live passes.
- A suitably privileged release environment is required to close OI-1.
- Some administration remains more explicit than legacy modules that enable
  privileges automatically.

## Alternatives considered

- Enable backup, restore, security, and take-ownership privileges on import:
  rejected as excessive and surprising authority.
- Temporarily seize ownership on access denied: rejected because restoration can
  fail and mutates an unrelated security boundary.
- Mark privileged tests passed when mocks pass: rejected because it confuses
  descriptor logic with filesystem authorization.

## See also

- [Security and persistence](../0004-security-and-persistence.md)
- [Verification privileged release gate](../0005-verification-and-traceability.md#privileged-release-gate)
