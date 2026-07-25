# Requirements

Status: Accepted. These stable, testable identifiers define the implemented
`NTFSPermission` contract. Design details are resolved by specifications 0003
to 0005 and the linked ADRs.

## Functional requirements

- **FR-1**: Query access rules on files and directories, filtered by identity,
  explicit or inherited origin, and orphaned SID state.
- **FR-2**: Construct reusable in-memory access rules with rights, allow or deny
  qualifier, and Explorer-style inheritance scope.
- **FR-3**: Add access rules for one or more identities, deduplicated by SID,
  with one descriptor persistence operation per target.
- **FR-4**: Replace matching access rules for an identity and qualifier while
  preserving unrelated rules.
- **FR-5**: Remove an exact access rule, subtract matching rights, purge every
  explicit rule for an identity, or clear all explicit access rules.
- **FR-6**: Provide audit-rule construction, query, add, replace, remove, purge,
  and clear operations with access-rule-equivalent pipeline behavior.
- **FR-7**: Query and set the owner of files and directories, returning both
  account and SID forms.
- **FR-8**: Query, enable, and disable access or audit inheritance; preserve
  inherited rules by default when disabling, and optionally remove explicit
  rules when enabling.
- **FR-9**: Get and copy selected owner, group, DACL, or SACL descriptor
  sections without changing unselected sections.
- **FR-10**: Back up selected descriptor sections to versioned JSON and restore
  only after every record has been validated.
- **FR-11**: Resolve account names and SIDs while preserving unresolvable SIDs
  as inspectable orphaned identities.
- **FR-12**: Report managed canonical-order state without automatically
  rewriting an ACL.
- **FR-13**: Evaluate effective NTFS access for a user SID through Windows Authz
  and expose the granted mask, effective rights, and optional requested-rights
  result.
- **FR-14**: List, test, enable, and disable privileges in the current process
  token; never claim that a privilege absent from the token was enabled.
- **FR-15**: Accept wildcard paths, literal paths, filesystem objects, and
  relevant module output through composable PowerShell pipelines.
- **FR-16**: Expose wildcard `Path` and exact `LiteralPath` semantics, and
  document that extended-path support belongs to the host runtime while
  reparse-point and path replacement create time-of-check/time-of-use risk.
- **FR-17**: Every state-changing command honors `WhatIf` and `Confirm`; useful
  mutation results are available only through `PassThru`.

## Non-functional requirements

- **NFR-1**: Run on Windows PowerShell 5.1 and PowerShell 7 on Windows, and fail
  clearly when imported elsewhere.
- **NFR-2**: Use no third-party runtime dependency; rely on in-box managed APIs
  plus narrowly scoped Windows interop.
- **NFR-3**: Persist only the descriptor sections selected by an operation.
- **NFR-4**: Every exported function has direct Pester evidence and complete
  comment-based help; primary interactive result types have curated format
  views.
- **NFR-5**: Source passes PSScriptAnalyzer and the merged module meets the
  configured 80 percent executable coverage threshold.
- **NFR-6**: Identity and restore validation fail closed before persistence;
  errors are not suppressed to obtain a passing build.
- **NFR-7**: Privileged acceptance scenarios remain discovered and report an
  exact skip reason when the process token lacks a required privilege.
- **NFR-8**: Backup content is non-executable, schema-versioned, and treated as
  trusted administrative input because it controls restore targets.
- **NFR-9**: Read operations never enable privileges, seize ownership, or
  broaden process authority as a side effect.
- **NFR-10**: Build, versioning, packaging, changelog, and tests use the Sampler
  project workflow and Semantic Versioning.

## Traceability

[Verification and traceability](0005-verification-and-traceability.md) maps
every requirement to executable evidence. Tests use these stable identifiers
in file comments or test names when a scenario directly proves a specific
contract.

## See also

- [Public API](0003-public-api.md)
- [Security and persistence](0004-security-and-persistence.md)
