---
status: current
last-verified: 2026-07-25
owner: shared
source: repository evidence
---

# Project brief

The normative project contract lives under [specs/](../specs/README.md). This
Memory Bank file is a concise scope summary and does not replace the numbered
specifications or ADRs.

## Purpose

Provide an ergonomic, pipeline-first PowerShell module for managing Windows
security descriptors without requiring callers to manipulate native pointers
or .NET access-control classes directly.

## Scope

- In scope: local NTFS files/directories, registry keys, named services, the
    Service Control Manager, and pinned live processes; owner, group, DACL,
    SACL, descriptor portability, identity, privileges, effective access,
    metrics, and supported inheritance workflows.
- Deferred: scheduled tasks, printers, WMI namespaces, SMB shares, event-log
    channels, and certificate private keys.
- Out of scope: registry-value ACLs, native remote APIs, Active Directory,
    POSIX ACLs, cloud IAM, Group Policy authoring, Central Access Policy,
    operating-system audit policy, and graphical tooling.

## Stakeholders

- PowerShell users and administrators who manage NTFS permissions interactively
  or in automation.

## Acceptance criteria

1. Object-specific commands accept canonical target strings, native objects,
    relevant module output, and explicit caller-owned handles where supported.
2. Mutating commands support `WhatIf`, `Confirm`, and opt-in pass-through
    output.
3. Every current object family covers its supported owner, group, DACL, SACL,
    descriptor portability, identity, and effective-access workflows.
4. The module has no third-party runtime dependency and supports Windows
    PowerShell 5.1 and PowerShell 7 on Windows.
5. Required privileges are scoped to an operation, reference-counted across
    parallel workers, and restored to their original state.
6. Class-based DSC exact-descriptor and access-rule-presence resources cover
    every current object family.
7. A PowerShell 7 Sampler build, cross-edition Pester/live tests, static
    analysis, package inspection, and user documentation prove the behavior.

Stable requirement identifiers and their executable evidence are maintained in
[requirements](../specs/0002-requirements.md) and
[verification and traceability](../specs/0005-verification-and-traceability.md).
