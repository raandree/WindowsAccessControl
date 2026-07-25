# Vision and scope

Status: Accepted. This specification defines the problem, goals, scope,
success criteria, and constraints for `NTFSPermission` 0.1.0. Detailed behavior
is defined by later specifications.

## Problem statement

Windows exposes complete NTFS security descriptor APIs through .NET and Win32,
but direct use is verbose, easy to get wrong, and poorly suited to PowerShell
pipelines. The standard commands operate on whole descriptors and do not offer
an ergonomic ACE-level workflow. Existing community modules demonstrate the
need but rely on dormant or archived dependencies and older design choices.

## Vision

Administrators compose safe, inspectable NTFS permission operations in normal
PowerShell pipelines without manually constructing or persisting .NET security
objects.

## Goals

- Cover access rules, audit rules, owner, inheritance, descriptor portability,
  identity resolution, canonical-order diagnostics, effective access, and
  process-token privileges.
- Make files, directories, path strings, and module output natural pipeline
  inputs.
- Preserve security descriptor sections that an operation did not select.
- Expose destructive distinctions explicitly and honor PowerShell safety
  conventions.
- Support Windows PowerShell 5.1 and PowerShell 7 on Windows with no third-party
  runtime dependency.
- Provide executable evidence at unit, live NTFS, and privilege-gated
  acceptance boundaries.

## Non-goals

- Registry, service, printer, process, share-level, or POSIX permissions.
- Central Access Policy or operating-system audit policy configuration.
- General filesystem commands for copying, hashing, links, compression, or
  disk-space management.
- Automatically enabling broad token privileges or temporarily taking
  ownership after an authorization failure.
- Claiming that mocked SACL behavior is a successful live SACL write.

## Success criteria

- Every exported command has a direct behavior specification and complete
  comment-based help.
- DACL, owner, inheritance, descriptor, Authz, and token workflows execute on a
  real NTFS volume without elevation where Windows permits it.
- SACL and arbitrary-owner acceptance scenarios execute unchanged when the
  isolated process contains the required privileges and otherwise report exact
  skips.
- All mutators support `WhatIf` and `Confirm`; applicable commands support
  opt-in `PassThru` output.
- Both supported PowerShell editions pass the behavior suite.
- The merged module passes static analysis and the enforced coverage threshold.

## Constraints and principles

- Windows-only runtime behavior fails clearly on another platform.
- Descriptor reads and writes use matching section sets.
- Invalid identities and restore records fail before the first persistence
  operation.
- Privilege inventory is read-only. Privilege mutation is always explicit.
- Backup documents are data, never executable PowerShell.
- Reparse points and path replacement create a time-of-check/time-of-use risk;
  privileged callers must treat path input as trusted administrative input.

## Key risks

- A whole-descriptor write can unintentionally require or overwrite unrelated
  security sections. Mitigation: section-scoped persistence (0004, ADR 0003).
- Similar-looking .NET ACL methods have materially different semantics.
  Mitigation: explicit add, set, exact, rights, and purge contracts (0003,
  ADR 0004).
- A non-elevated CI token cannot prove privileged writes. Mitigation: discovered
  privilege-gated acceptance tests with exact skip reasons (0005, ADR 0007).

## See also

- [Requirements](0002-requirements.md)
- [Research sources](../docs/research.md)
