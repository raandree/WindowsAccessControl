# Specifications

This directory contains the normative requirements and design contracts for
the current `NTFSPermission` implementation and its accepted rename and
expansion to `WindowsAccessControl`. Specifications are the source of truth for
what the module does and how its public and security boundaries behave.
Comment-based help is the source of truth for exhaustive per-command parameter
reference.

The Memory Bank summarizes and points to these documents; it does not replace
them.

## Reading order

1. [Vision and scope](0001-vision-and-scope.md)
2. [Requirements](0002-requirements.md)
3. [Public API](0003-public-api.md)
4. [Security and persistence](0004-security-and-persistence.md)
5. [Verification and traceability](0005-verification-and-traceability.md)
6. [WindowsAccessControl expansion](0006-windows-access-control-expansion.md)
7. [In-memory descriptor mutation](0007-in-memory-descriptor-mutation.md)
8. [Enterprise access-control expansion](0008-enterprise-access-control-expansion.md)

## Status

| ID | Specification | Status |
| --- | --- | --- |
| 0001 | Vision and scope | Accepted |
| 0002 | Requirements | Accepted |
| 0003 | Public API | Accepted |
| 0004 | Security and persistence | Accepted |
| 0005 | Verification and traceability | Accepted |
| 0006 | WindowsAccessControl expansion | Accepted |
| 0007 | In-memory descriptor mutation | Draft |
| 0008 | Enterprise access-control expansion | Draft |

Specifications 0001 through 0005 describe the implemented 0.1.0 contract.
Specification 0006 is the accepted contract for the implemented and verified
registry-key, service/SCM, pinned-process, portability, bounded-execution, and
DSC expansion. Specification 0007 remains a Draft design contract for open
issue OI-5; its first filesystem round-trip increment is under implementation
and is not yet part of the accepted contract. Specification 0008 plans the
domain-lab-gated Task Scheduler, certificate private-key, SMB-share, and Active
Directory expansion. A future change starts as `Draft` and becomes `Accepted`
when approved.

## Architecture decisions

Cross-cutting decisions are recorded as immutable ADRs under
[decisions/](decisions/README.md) using the MADR structure. A later ADR
supersedes an accepted decision rather than rewriting its history.

## Open issues

Agreed but unfinished validation and design work is tracked in
[open-issues.md](open-issues.md). Resolved items are removed from that file and
recorded in the changelog.

## Conventions

- One specification per file, numbered `NNNN-title.md`.
- Sentence-case headings and American English.
- Each numbered specification declares `Status: Draft`, `Accepted`, or
  `Superseded` near the top.
- Requirements use stable `FR-*` and `NFR-*` identifiers.
- Tests and traceability tables reference requirement, specification, and ADR
  identifiers where they prove a contract.
- Specifications describe design contracts. Comment-based help beside the code
  describes every parameter and example.

## See also

- [Research sources](../docs/research.md)
- [Project README](../README.md)
