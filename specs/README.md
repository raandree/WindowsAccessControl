# Specifications

This directory contains the normative requirements and design contracts for
`WindowsAccessControl`, including the rename from `NTFSPermission` and the
accepted enterprise expansion. Specifications are the source of truth for
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
9. [SMB share and Active Directory DACL management](0009-smb-share-and-active-directory-dacl-management.md)
10. [Task Scheduler DACL management](0010-task-scheduler-dacl-management.md)
11. [SMB share-only effective access](0011-smb-share-only-effective-access.md)
12. [CNG private-key DACL inspection](0012-cng-private-key-dacl-inspection.md)
13. [Enterprise portability and desired state](0013-enterprise-portability-and-desired-state.md)
14. [Task Scheduler portability and desired state](0014-task-scheduler-portability-and-desired-state.md)
15. [CNG private-key DACL mutation](0015-cng-private-key-dacl-mutation.md)
16. [Active Directory multi-controller behavior](0016-active-directory-multi-controller-behavior.md)
17. [Certificate private-key portability and desired state](0017-certificate-private-key-portability-and-desired-state.md)

## Status

| ID | Specification | Status |
| --- | --- | --- |
| 0001 | Vision and scope | Accepted |
| 0002 | Requirements | Accepted |
| 0003 | Public API | Accepted |
| 0004 | Security and persistence | Accepted |
| 0005 | Verification and traceability | Accepted |
| 0006 | WindowsAccessControl expansion | Accepted |
| 0007 | In-memory descriptor mutation | Accepted |
| 0008 | Enterprise access-control expansion | Accepted |
| 0009 | SMB share and Active Directory DACL management | Accepted |
| 0010 | Task Scheduler DACL management | Accepted |
| 0011 | SMB share-only effective access | Accepted |
| 0012 | CNG private-key DACL inspection | Accepted |
| 0013 | Enterprise portability and desired state | Accepted |
| 0014 | Task Scheduler portability and desired state | Accepted |
| 0015 | CNG private-key DACL mutation | Accepted |
| 0016 | Active Directory multi-controller behavior | Accepted |
| 0017 | Certificate private-key portability and desired state | Accepted |

A future change starts as `Draft` and becomes `Accepted` when approved.

## Scope notes

- **0001-0005**: Describe the implemented 0.1.0 contract.
- **0006**: The accepted contract for the implemented and verified registry-key,
  service/SCM, pinned-process, portability, bounded-execution, and DSC
  expansion.
- **0007**: Accepts the implemented filesystem and registry-key
  descriptor-editing model, including opt-in optimistic concurrency.
- **0008**: The accepted roadmap contract for the domain-lab-gated Task
  Scheduler, certificate private-key, SMB-share, and Active Directory expansion.
  It approves the entry gates, work packages, and boundaries rather than
  claiming that every package is implemented.
- **0009**: Accepts the first SMB-share and Active Directory DACL-management
  increment without claiming replication work.
- **0010**: Accepts local Task Scheduler folder and registered-task DACL
  descriptor management without claiming typed rules, portability, DSC, SACL, or
  direct remote APIs.
- **0011**: Accepts a bounded local SID-derived SMB share-only result without a
  backing-NTFS, remote, or network-token claim.
- **0012**: Accepts read-only DACL inspection for an exact persisted RSA key in
  Microsoft Software Key Storage Provider without admitting mutation or broader
  provider support.
- **0013**: Accepts schema-version-2 portability, server-qualified SMB canonical
  identity, and object-specific desired-state resources for the SMB share and
  Active Directory families, and records the accepted directory effective-access
  boundary.
- **0014**: Extends the same portability and desired-state model to the Task
  Scheduler folder and registered-task families with computer-qualified
  canonical identity.
- **0015**: Supersedes the read-only boundary of specification 0012 with
  fail-closed typed private-key DACL mutation for the software key storage
  provider.
- **0016**: Records the multi-controller identity, replication, and
  pinned-controller outage behavior that specification 0009 deferred.
- **0017**: Extends the portability and desired-state model to the certificate
  private-key family, addressing the key by provider, persisted key name, and
  key scope rather than by a certificate.

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
- [Domain lab inventory](../docs/domain-lab-inventory.md)
- [Lab deployment and acceptance guide](../tests/Lab/README.md)
- [Project README](../README.md)
