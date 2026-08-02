# Requirements

Status: Accepted. These stable, testable identifiers define the implemented
`NTFSPermission` contract. Design details are resolved by specifications 0003
to 0005 and the linked ADRs.

## Functional requirements

- **FR-1**: Query access rules on files and directories, filtered by identity,
  explicit or inherited origin, orphaned SID state, and the native ancestor
  provenance of each inherited ACE.
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
  on a local filesystem target, expose the granted mask, effective rights, and
  optional requested-rights result, and reject UNC targets before descriptor
  evaluation.
- **FR-14**: List, test, enable, and disable privileges in the current process
  token; never claim that a privilege absent from the token was enabled.
- **FR-15**: Accept wildcard paths, literal paths, filesystem objects, and
  relevant module output through composable PowerShell pipelines.
- **FR-16**: Expose wildcard `Path` and exact `LiteralPath` semantics, and
  document that extended-path support belongs to the host runtime while
  reparse-point and path replacement create time-of-check/time-of-use risk.
- **FR-17**: Every state-changing command honors `WhatIf` and `Confirm`; useful
  mutation results are available only through `PassThru`.
- **FR-18**: Query and set local SMB-share DACL descriptors, add typed allow or
  deny share ACEs, and remove exact path-bound share ACEs without changing the
  backing NTFS descriptor or unrelated share ACEs.
- **FR-19**: Query and set Active Directory object DACL descriptors through an
  explicit or automatically located and pinned writable domain controller, add
  typed common or object-specific ACEs, and remove exact path-bound ACEs while
  preserving GUID and inheritance metadata and reporting the ancestor source and
  resolved schema names of every inherited ACE.
- **FR-20**: Query and set DACL descriptors for local Task Scheduler folders and
  registered tasks inside an explicit allowed-root boundary while preserving
  required Local System access and task definitions.
- **FR-21**: Evaluate an ordinary local SMB share DACL for a user SID through
  Windows Authz and expose the granted mask, typed share rights, optional
  requested-rights result, and explicit exclusion of the backing NTFS DACL.
- **FR-22**: Edit selected NTFS descriptor sections in a bounded script-block
  scope with one detached read, at most one serialized persistence operation,
  optional positional arguments, and opt-in pass-through output.
- **FR-23**: Inspect the DACL descriptor of an exact persisted RSA CNG private
  key selected by a caller-owned certificate plus matching provider and key
  identity, without exporting or serializing private-key material.

## Non-functional requirements

- **NFR-1**: Run on Windows PowerShell 5.1 and PowerShell 7 on Windows, and fail
  clearly when imported elsewhere.
- **NFR-2**: Use no third-party runtime dependency; rely on in-box managed APIs
  plus narrowly scoped Windows interop.
- **NFR-3**: Persist only the descriptor sections selected by an operation.
- **NFR-4**: Every exported function has direct Pester evidence and complete
  comment-based help; primary interactive result types have curated format
  views.
- **NFR-5**: Source passes PSScriptAnalyzer and the commands the running test
  profile can execute meet the configured 80 percent executable coverage
  threshold.
- **NFR-6**: Identity and restore validation fail closed before persistence;
  errors are not suppressed to obtain a passing build.
- **NFR-7**: Privileged acceptance scenarios remain discovered and report an
  exact skip reason when the process token lacks a required privilege.
- **NFR-8**: Backup content is non-executable, schema-versioned, and treated as
  trusted administrative input because it controls restore targets.
- **NFR-9**: Operations may enable only required privileges already present in
  the token, must restore their original state after the final nested worker,
  and never seize ownership as an authorization fallback.
- **NFR-10**: Build, versioning, packaging, changelog, and tests use the Sampler
  project workflow and Semantic Versioning.
- **NFR-11**: SMB commands reject remote syntax and execute on the target
  computer; AD commands use direct LDAP Kerberos authentication with signing,
  sealing, no referral chasing, one validated domain-controller authority that
  is pinned for the whole invocation, and bounded timeouts.
- **NFR-12**: Enterprise DACL writes revalidate target identity immediately
  before persistence, reject protected or out-of-bound targets, and retain
  executable rollback evidence from disposable resources.
- **NFR-13**: Task Scheduler operations release every COM object in reverse
  ownership order, use no direct remote target syntax, and compare stored DACLs
  without treating service-derived ACE order or `DACL_AUTO_INHERITED` state as
  caller-controlled drift.
- **NFR-14**: SMB effective-access output identifies its authorization context
  as local and SID-derived, never claims backing-NTFS or remote evaluation, and
  uses the existing bounded native-resource cleanup contract.
- **NFR-15**: Bounded NTFS descriptor editing executes the callback under
  `WhatIf` but never persists it, suppresses callback output, rejects unloaded-
  section expansion, and never writes after callback failure.
- **NFR-16**: Private-key inspection supports only the explicitly allowed
  software CNG provider, rejects CAPI/ephemeral/mismatched targets, keeps the
  certificate caller-owned, disposes module-owned key wrappers, and uses a
  hashed canonical target identity.

## Traceability

[Verification and traceability](0005-verification-and-traceability.md) maps
every requirement to executable evidence. Tests use these stable identifiers
in file comments or test names when a scenario directly proves a specific
contract.

## See also

- [Public API](0003-public-api.md)
- [Security and persistence](0004-security-and-persistence.md)
