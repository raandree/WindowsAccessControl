# Persist only selected descriptor sections

- Status: Accepted
- Date: 2026-07-25
- Deciders: user, software-engineer agent

## Context and problem statement

Filesystem security descriptors combine owner, group, DACL, and SACL state.
Writing a descriptor loaded with a broader section set can request unrelated
privileges or overwrite sections the caller did not intend to change.

## Decision

Load and persist only the sections required by an operation. Use the
runtime-appropriate filesystem API rather than routing every change through a
whole-descriptor `Set-Acl` call.

- DACL operations load and write `Access`.
- SACL operations load and write `Audit`.
- Owner operations write owner state.
- Copy and restore use the explicit recorded section mask.

## Consequences

- DACL-only work does not require `SeSecurityPrivilege` merely because a SACL
  exists.
- Unselected owner, group, DACL, and SACL state is preserved.
- Persistence logic is centralized and tested across both PowerShell editions.

## Alternatives considered

- Always call `Set-Acl`: rejected after live testing showed a DACL inheritance
  change could request `SeSecurityPrivilege`.
- Always read and write `All`: rejected because it broadens privilege and data
  loss risk.

## See also

- [Security and persistence](../0004-security-and-persistence.md)
