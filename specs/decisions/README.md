# Architecture decision records

This directory records significant cross-cutting decisions using the MADR
structure. One decision lives in each numbered `NNNN-title.md` file. Accepted
decisions are immutable; a later ADR supersedes one when the design changes.

## Index

| ID | Decision | Status |
| --- | --- | --- |
| 0000 | [Use architecture decision records](0000-use-architecture-decision-records.md) | Accepted |
| 0001 | [Document the API contract in specs and reference help in code](0001-document-api-contract-in-specs-and-help.md) | Accepted |
| 0002 | [Use only in-box runtime security APIs](0002-use-only-in-box-runtime-security-apis.md) | Accepted |
| 0003 | [Persist only selected descriptor sections](0003-persist-only-selected-descriptor-sections.md) | Accepted |
| 0004 | [Expose explicit ACL mutation semantics](0004-expose-explicit-acl-mutation-semantics.md) | Accepted |
| 0005 | [Use versioned validated JSON backups](0005-use-versioned-validated-json-backups.md) | Accepted |
| 0006 | [Prevalidate and deduplicate identities before batching](0006-prevalidate-and-deduplicate-identities.md) | Accepted |
| 0007 | [Keep privilege changes explicit and acceptance gated](0007-keep-privilege-changes-explicit.md) | Accepted |

## See also

- [Specification index](../README.md)
- [System patterns summary](../../.memory-bank/systemPatterns.md)
