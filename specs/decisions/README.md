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
| 0007 | [Keep privilege changes explicit and acceptance gated](0007-keep-privilege-changes-explicit.md) | Superseded by 0008 |
| 0008 | [Use scoped automatic privilege enablement](0008-use-scoped-automatic-privilege-enablement.md) | Accepted |
| 0009 | [Rename the module to WindowsAccessControl](0009-rename-module-to-windows-access-control.md) | Accepted |
| 0010 | [Use a shared binary security-descriptor engine](0010-use-shared-binary-security-descriptor-engine.md) | Accepted |
| 0011 | [Limit the release to local object families](0011-limit-release-to-local-object-families.md) | Accepted |
| 0012 | [Use object-specific commands and DSC resources](0012-use-object-specific-commands-and-dsc-resources.md) | Accepted |
| 0013 | [Use bounded parallel target execution](0013-use-bounded-parallel-target-execution.md) | Accepted |
| 0014 | [Stage enterprise expansion behind a domain lab](0014-stage-enterprise-expansion-behind-domain-lab.md) | Accepted |
| 0015 | [Use local SMB and signed and sealed LDAP authority](0015-use-local-smb-and-signed-sealed-ldap.md) | Accepted, explicit-server element superseded by 0021 |
| 0016 | [Require backup schema version 2 for enterprise targets](0016-require-schema-v2-for-enterprise-targets.md) | Accepted |
| 0017 | [Defer remote and combined effective access](0017-defer-remote-and-combined-effective-access.md) | Accepted |
| 0018 | [Use local Task Scheduler and software-key authority](0018-use-local-task-and-software-key-authority.md) | Accepted |
| 0019 | [Report null registry provenance instead of losing rules](0019-report-null-registry-provenance-for-wow64-views.md) | Accepted |
| 0020 | [Enrich directory rules over the bound LDAP connection](0020-enrich-directory-rules-over-the-bound-connection.md) | Accepted |
| 0021 | [Discover and pin one domain controller when Server is omitted](0021-discover-and-pin-a-domain-controller.md) | Accepted |
| 0022 | [Defer Active Directory effective access](0022-defer-active-directory-effective-access.md) | Accepted |

## See also

- [Specification index](../README.md)
- [System patterns summary](../../.memory-bank/systemPatterns.md)
