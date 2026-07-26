# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add 28 pipeline-first commands for NTFS access rules, audit rules, ownership,
    inheritance, identities, privileges, effective access, and ACL diagnostics
- Add selected-section descriptor copy plus validated JSON backup and restore
- Add a Sampler build with PowerShell 7 and Windows PowerShell 5.1 test coverage
- Add command help, object formatting, usage documentation, and research notes
- Add structured current-token privilege inventory with `Get-WindowsPrivilege`
- Add privilege-gated live SACL and arbitrary-owner acceptance specifications
- Add live SACL-only descriptor-copy acceptance with owner, group, and DACL
    preservation evidence
- Add public registry-view, descriptor-section, service, SCM, and process
    rights enums
- Add 15 local registry-key commands for selected security descriptors,
    access and audit rules, inheritance control, explicit 32/64-bit views, and
    curated access/audit rule formatting
- Add 12 local service and Service Control Manager commands for selected
    descriptors plus typed access/audit rule CRUD without inheritance semantics
- Add 12 ephemeral live-process commands with PID/creation-time pinning,
    caller-owned handle support, typed process rights, and access/audit CRUD
- Add unified cross-domain descriptor backup and restore with SHA-256 record
    integrity and optional RSA X.509 signing and verification
- Add a shared Unicode named/handle security descriptor engine with pinned
    process identity checks and caller-owned handle support
- Allow `Resolve-WindowsIdentity` to accept native identity references, module
    output, and objects with `SID`, `Account`, or `IdentityReference` properties
- Add numbered source-of-truth specifications, stable requirement identifiers,
    ADRs, open issues, and automated specification conformance checks
- Add bounded target-array execution across filesystem, registry, service/SCM,
    and process commands with configurable `ThrottleLimit`, canonical target
    deduplication, and process-wide same-target write serialization
- Add `Get-WindowsAccessControlMetric` for redacted in-process operation,
    target, success, failure, and elapsed counters by command and object family
- Add a repeatable NTFS batch benchmark that records sequential and parallel
    throughput without a timing-based pass threshold

### Changed

- **Breaking:** rename the unpublished module and output type prefix from
    `NTFSPermission` to `WindowsAccessControl` while preserving its GUID
- **Breaking:** rename cross-domain identity and privilege commands from
    `*-NTFSIdentity` and `*-NTFSPrivilege` to `*-WindowsIdentity` and
    `*-WindowsPrivilege`
- Allow `Add-NTFSAccessRule` and `Add-NTFSAuditRule` to add rules for multiple
    unique accounts with one descriptor write per item
- Allow `Enable-NTFSItemInheritance` to remove explicit rules while enabling
    access or audit inheritance
- Automatically scope and restore `SeSecurityPrivilege` for SACL operations and
    `SeRestorePrivilege` for owner/group writes when the token contains them
- Read deduplicated NTFS backup targets with bounded parallelism while retaining
    one complete atomic envelope write

### Security

- Validate every unified backup record, digest, signature, canonical target,
    and process instance before restoring the first descriptor
- Reject recomputed-digest signature tampering, mixed signed/unsigned
    envelopes, duplicate targets, omitted selected ACL sections, and null DACLs
- Validate backup schema, record paths, item types, section masks, and SDDL
    before restoring security descriptors
- Persist only modified descriptor sections to avoid unintended SACL or owner
    changes during DACL operations
- Reject remote `RegistryKey` objects before their local-looking names can be
    normalized to local targets

### Fixed

- Persist DACL and SACL inheritance protection changes on PowerShell 7 through
    a section-scoped native security update
- Fix account-wide access and audit removal when `AccessRights` is omitted
- Validate all restore records before persisting the first descriptor
- Refuse to overwrite existing backup files unless `Force` is specified
- Treat disabling a privilege absent from the process token as a no-op
- Add destructive-mode, `WhatIf`, malformed-backup, orphaned-SID,
    noncanonical-ACL, and section-preservation regression coverage
- Preserve registry audit rules with opposite success/failure flags when
    replacing a matching rule
- Skip identical registry descriptor writes, preserve an absent SACL during a
    matchless clear, reject audit rules with `AuditFlags None`, and normalize
    provider-style forward-slash paths without changing native slash names
- Write completed backup envelopes through atomic same-directory replacement,
    defer signing-key access until `ShouldProcess`, and preserve absent SACLs
    through explicit `S:NO_ACCESS_CONTROL` records
- Preserve single-target canonical batches on Windows PowerShell 5.1 and share
    target locks across isolated module instances to prevent concurrent alias
    writes
