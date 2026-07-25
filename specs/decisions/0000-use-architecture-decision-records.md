# Use architecture decision records

- Status: Accepted
- Date: 2026-07-25
- Deciders: user, software-engineer agent

## Context and problem statement

Security descriptor behavior depends on choices that are not obvious from one
function: persistence sections, native API boundaries, destructive semantics,
backup trust, and privilege handling. Rationale kept only in code comments or a
lean Memory Bank would be easy to lose.

## Decision

Record significant cross-cutting decisions as MADR-style documents under
`specs/decisions/`, one numbered file per decision. Accepted ADRs are immutable;
a later ADR supersedes a decision rather than rewriting history.

## Consequences

- Design intent and alternatives are reviewable beside source changes.
- The Memory Bank remains a concise summary and links to normative records.
- A significant design change adds small documentation overhead.

## Alternatives considered

- Keep decisions only in `.memory-bank/systemPatterns.md`: rejected because the
  Memory Bank is compact and may be rewritten as context changes.
- Keep rationale only in implementation comments: rejected because the
  decision spans multiple commands and tests.

## See also

- [Specification conventions](../README.md)
