---
status: current
last-verified: 2026-07-25
owner: active-agent
source: repository evidence
---

# System patterns

Normative architecture decisions live under
[specs/decisions/](../specs/decisions/README.md). The entries below are routing
summaries only; accepted ADRs control when wording differs.

## Architecture

Public commands handle pipeline binding, path parameter sets, `ShouldProcess`,
and output. Private functions resolve paths and identities, map inheritance
semantics, load and persist only required security descriptor sections, and
convert native rules into stable PowerShell objects. Pure descriptor mutation
is separated from filesystem persistence so most behavior is unit-testable
without elevation.

## Decisions

### Decision 1: Use the canonical Memory Bank base

- Choice: Keep durable project context in .memory-bank.
- Rationale: Preserve evidence-backed context across sessions.

### Decision 2: Use only in-box runtime APIs

Normative record: [ADR 0002](../specs/decisions/0002-use-only-in-box-runtime-security-apis.md).

- Choice: Build on `Get-Acl`, `Set-Acl`, and
    `System.Security.AccessControl`, with narrowly scoped Windows interop only
    where no managed API exists.
- Rationale: Support both PowerShell editions without inheriting archived
    AlphaFS or ProcessPrivileges dependencies.

### Decision 3: Keep destructive ACL semantics explicit

Normative record: [ADR 0004](../specs/decisions/0004-expose-explicit-acl-mutation-semantics.md).

- Choice: Map add, set, exact removal, rights subtraction, and account purge to
    distinct parameter sets; do not expose whole-DACL reset as a routine rule
    operation.
- Rationale: The underlying .NET methods differ materially and accidental
    reset can remove every unrelated ACE.

### Decision 4: Preserve descriptor sections

Normative record: [ADR 0003](../specs/decisions/0003-persist-only-selected-descriptor-sections.md).

- Choice: Read and persist only the descriptor sections required by each
    operation.
- Rationale: Microsoft recommends matching loaded and persisted sections, and
    this prevents a DACL operation from clobbering a SACL, owner, or group.

### Decision 5: Use versioned, validated JSON backups

Normative record: [ADR 0005](../specs/decisions/0005-use-versioned-validated-json-backups.md).

- Choice: Store path, item type, selected section mask, and SDDL under schema
    version 1; validate and prepare every record before the first restore write.
- Rationale: Keep backup content non-executable, section-scoped, and resistant
    to malformed later records causing partial application.

### Decision 6: Keep destructive modes separately testable

Normative record: [ADR 0004](../specs/decisions/0004-expose-explicit-acl-mutation-semantics.md).

- Choice: Model exact removal, rights subtraction, and account-wide purge as
    explicit modes, with `WhatIf`, high confirmation impact, and regression tests
    for each access and audit path.
- Rationale: The native APIs have different semantics and account-wide purge
    does not require a rights mask.

### Decision 7: Batch only after identity prevalidation

Normative record: [ADR 0006](../specs/decisions/0006-prevalidate-and-deduplicate-identities.md).

- Choice: Resolve and deduplicate all account inputs by SID before changing a
    descriptor, then persist once per target and emit one result per unique SID.
- Rationale: Invalid identities fail before mutation, duplicate aliases cannot
    misrepresent persisted ACEs, and batch operations avoid repeated writes.

### Decision 8: Make privilege gaps executable and explicit

Normative record: [ADR 0007](../specs/decisions/0007-keep-privilege-changes-explicit.md).

- Choice: Enumerate current-token privileges without enabling them, and keep
    privileged acceptance scenarios discovered but skipped with exact reasons
    when required privileges are absent.
- Rationale: Missing privilege evidence must not look like a passing SACL or
    arbitrary-owner live test, and read operations must not broaden token state.

### Decision 9: Keep specifications authoritative and help beside code

Normative record: [ADR 0001](../specs/decisions/0001-document-api-contract-in-specs-and-help.md).

- Choice: Numbered specifications own requirements and holistic API/security
    contracts; comment-based help owns exhaustive per-command detail.
- Rationale: The design remains reviewable without duplicating parameter
    reference that belongs next to implementation.

### Decision 10: Persist ACL protection with the selected ACL

- Choice: When changing file-system DACL or SACL protection, persist the
    selected ACL pointer and its protected or unprotected native control flag
    together through `SetNamedSecurityInfoW`.
- Rationale: PowerShell 7 can persist ACE content through
    `FileSystemAclExtensions.SetAccessControl` while dropping an unprotected
    SACL control flag; passing only a native protection flag is rejected.

### Decision 11: Scope required privileges to operations

Normative record: [ADR 0008](../specs/decisions/0008-use-scoped-automatic-privilege-enablement.md).

- Choice: Reference-count required privilege scopes and restore original token
    state after the final worker exits.
- Rationale: Commands and DSC remain composable without import-time authority
    broadening.

### Decision 12: Rename to WindowsAccessControl

Normative record: [ADR 0009](../specs/decisions/0009-rename-module-to-windows-access-control.md).

- Choice: Hard-rename the unpublished package and cross-domain contracts while
    retaining NTFS in filesystem-specific command nouns.
- Rationale: The package name must describe all current object families.

### Decision 13: Share one binary descriptor engine

Normative record: [ADR 0010](../specs/decisions/0010-use-shared-binary-security-descriptor-engine.md).

- Choice: Use named Unicode APIs for registry/services and handle APIs for
    processes over self-relative binary descriptors.
- Rationale: This preserves section and ACE fidelity across both PowerShell
    editions without a runtime dependency.

### Decision 14: Keep the release local and testable

Normative record: [ADR 0011](../specs/decisions/0011-limit-release-to-local-object-families.md).

- Choice: Ship local file system, registry key, service/SCM, and live process
    targets; defer or exclude other securable object types explicitly.
- Rationale: Remote trust and ephemeral object lifetimes require separate
    contracts.

### Decision 15: Use object-specific public and DSC surfaces

Normative record: [ADR 0012](../specs/decisions/0012-use-object-specific-commands-and-dsc-resources.md).

- Choice: Export object-specific commands, typed object contracts, public
    enums, and exact/rule class-based DSC resources per family.
- Rationale: Rights and capabilities remain discoverable while internals stay
    shared.

### Decision 16: Bound parallel target execution

Normative record: [ADR 0013](../specs/decisions/0013-use-bounded-parallel-target-execution.md).

- Choice: Prevalidate and deduplicate before bounded parallel dispatch;
    serialize aliases of one canonical target.
- Rationale: Enterprise-size batches need throughput without lost updates or
    unbounded native resource use.
