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
- Add numbered source-of-truth specifications, stable requirement identifiers,
    ADRs, open issues, and automated specification conformance checks

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

### Security

- Validate backup schema, record paths, item types, section masks, and SDDL
    before restoring security descriptors
- Persist only modified descriptor sections to avoid unintended SACL or owner
    changes during DACL operations

### Fixed

- Persist DACL and SACL inheritance protection changes on PowerShell 7 through
    a section-scoped native security update
- Fix account-wide access and audit removal when `AccessRights` is omitted
- Validate all restore records before persisting the first descriptor
- Refuse to overwrite existing backup files unless `Force` is specified
- Treat disabling a privilege absent from the process token as a no-op
- Add destructive-mode, `WhatIf`, malformed-backup, orphaned-SID,
    noncanonical-ACL, and section-preservation regression coverage
