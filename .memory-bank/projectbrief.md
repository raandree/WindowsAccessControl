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

- Current scope: local NTFS files/directories, registry keys, named services,
    the Service Control Manager, and pinned live processes; owner, group, DACL,
    SACL, descriptor portability, identity, privileges, effective access,
    metrics, and supported inheritance workflows.
- Planned enterprise expansion: scheduled tasks and task folders, CAPI/CNG
    certificate private keys, SMB shares, and Active Directory objects. This
    work is gated on a disposable domain lab, remote-security contracts, API
    probes, and separate executable evidence for each family.
- Deferred: printers, WMI namespaces, event-log channels, mandatory integrity
    labels, HTTP.sys URL reservations, Remote Desktop Services listeners, named
    pipes, PowerShell/WinRM endpoints, MSMQ queues, and device ACLs.
- Out of scope: registry-value ACLs, POSIX ACLs, cloud IAM, Group Policy
    authoring, Central Access Policy, operating-system audit policy, and
    graphical tooling.

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
8. Planned enterprise families do not claim implementation until their
    domain-lab, security, rollback, cross-edition, and independent-review gates
    pass.

Stable requirement identifiers and their executable evidence are maintained in
[requirements](../specs/0002-requirements.md) and
[verification and traceability](../specs/0005-verification-and-traceability.md).
