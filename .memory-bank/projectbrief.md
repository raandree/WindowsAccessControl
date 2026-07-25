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

Provide an ergonomic, pipeline-first PowerShell module for managing NTFS
permissions without requiring callers to manipulate .NET access-control
objects directly.

## Scope

- In scope: access and audit rules, owner, access and audit inheritance,
  security descriptors, copy, backup and restore, identity resolution,
  canonical-order diagnostics, and effective-access reporting for files and
  directories on Windows.
- Out of scope: registry, service, printer, process, share-level, and POSIX
  permissions; Central Access Policy management; and operating-system audit
  policy configuration.

## Stakeholders

- PowerShell users and administrators who manage NTFS permissions interactively
  or in automation.

## Acceptance criteria

1. Public commands accept paths, file-system objects, and relevant module
    output through the pipeline.
2. Mutating commands support `WhatIf`, `Confirm`, and opt-in pass-through
    output.
3. The module covers DACL, SACL, owner, inheritance, descriptor portability,
    identity, canonical-order, and effective-access workflows.
4. The module has no third-party runtime dependency and supports Windows
    PowerShell 5.1 and PowerShell 7 on Windows.
5. A Sampler build, Pester tests, static analysis, and user documentation prove
    the supported behavior.

Stable requirement identifiers and their executable evidence are maintained in
[requirements](../specs/0002-requirements.md) and
[verification and traceability](../specs/0005-verification-and-traceability.md).
