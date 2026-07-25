---
status: current
last-verified: 2026-07-25
owner: active-agent
source: repository evidence
---

# System patterns

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

- Choice: Build on `Get-Acl`, `Set-Acl`, and
    `System.Security.AccessControl`, with narrowly scoped Windows interop only
    where no managed API exists.
- Rationale: Support both PowerShell editions without inheriting archived
    AlphaFS or ProcessPrivileges dependencies.

### Decision 3: Keep destructive ACL semantics explicit

- Choice: Map add, set, exact removal, rights subtraction, and account purge to
    distinct parameter sets; do not expose whole-DACL reset as a routine rule
    operation.
- Rationale: The underlying .NET methods differ materially and accidental
    reset can remove every unrelated ACE.

### Decision 4: Preserve descriptor sections

- Choice: Read and persist only the descriptor sections required by each
    operation.
- Rationale: Microsoft recommends matching loaded and persisted sections, and
    this prevents a DACL operation from clobbering a SACL, owner, or group.

### Decision 5: Use versioned, validated JSON backups

- Choice: Store path, item type, selected section mask, and SDDL under schema
    version 1; validate and prepare every record before the first restore write.
- Rationale: Keep backup content non-executable, section-scoped, and resistant
    to malformed later records causing partial application.

### Decision 6: Keep destructive modes separately testable

- Choice: Model exact removal, rights subtraction, and account-wide purge as
    explicit modes, with `WhatIf`, high confirmation impact, and regression tests
    for each access and audit path.
- Rationale: The native APIs have different semantics and account-wide purge
    does not require a rights mask.
