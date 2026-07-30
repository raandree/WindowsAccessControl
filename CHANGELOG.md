# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Fix `Add-RegistryKeyAccessRule` and `Add-RegistryKeyAuditRule` silently
    discarding a rule that matched an existing account and rights combination
    but declared a different `AppliesTo` inheritance scope

### Added

- Add schema-version-2 descriptor portability for SMB share and Active
    Directory targets, binding the explicit server plus the immutable share
    name or distinguished name, `objectGUID`, and domain naming context into the
    SHA-256 record digest; the envelope schema version is the highest record
    version present and a record whose family and version disagree is rejected
- Add `Server`, `AllowedBaseDistinguishedName`, `Credential`, and
    `TimeoutSeconds` to `Restore-WindowsSecurityDescriptor`; an SMB record
    restores only on the computer it names and a directory record requires an
    explicit allowed organizational unit
- Add four class-based DSC resources:
    `WindowsAccessControlSmbShareSecurityDescriptor`,
    `WindowsAccessControlSmbShareAccessRule`,
    `WindowsAccessControlADObjectSecurityDescriptor`, and
    `WindowsAccessControlADObjectAccessRule`
- Add broader Active Directory DACL mutation with `Set-ADObjectAccessRule`,
    `Clear-ADObjectAccessRule`, and `Exact`, `Rights`, and `All` removal modes on
    a distinguished-name parameter set for `Remove-ADObjectAccessRule`; every
    mode matches on account, qualifier, and both object GUIDs so an object ACE is
    never flattened into a common ACE
- Add a fail-closed manageability gate that rejects an Active Directory rule
    mutation whose result would grant no principal `WriteDacl` or `WriteOwner` on
    the object
- Add a write-boundary staleness check that rejects an Active Directory rule
    mutation when the target DACL changed after the descriptor was staged
- Add `InheritedFrom` provenance to Active Directory access-rule results and
    their default table view, resolved by walking the ancestor chain over the
    same signed and sealed connection that returned the descriptor
- Add `ObjectTypeName` and `InheritedObjectTypeName` to Active Directory
    access-rule results, resolving schema classes, attributes, property sets,
    validated writes, and extended rights while preserving the GUID properties
- Add native `InheritedFrom` provenance to registry-key access-rule results and
    their default table view, resolved with the Windows inheritance-source API
    for the default registry view
- Add typed Task Scheduler access-rule commands (`Get-TaskFolderAccessRule`,
    `Add-TaskFolderAccessRule`, `Remove-TaskFolderAccessRule`,
    `Get-ScheduledTaskAccessRule`, `Add-ScheduledTaskAccessRule`,
    `Remove-ScheduledTaskAccessRule`) with separate `WindowsTaskFolderRights`
    and `WindowsScheduledTaskRights` models and folder inheritance scope
- Add `SecurityDescriptor` parameter sets to the remaining NTFS access, audit,
    owner, and inheritance mutators so a detached descriptor can be edited in
    memory and persisted with one write
- Add registry-key descriptor editing with `Edit-RegistryKeySecurityDescriptor`,
    descriptor input on `Set-RegistryKeySecurityDescriptor`, and
    `SecurityDescriptor` parameter sets on every registry access, audit, and
    inheritance mutator
- Add an opt-in `RequireUnchanged` optimistic-concurrency switch and a
    `ConcurrencyToken` descriptor property that reject a stale target before
    persistence; last-writer-wins remains the default
- Add 28 pipeline-first commands for NTFS access rules, audit rules, ownership,
    inheritance, identities, privileges, effective access, and ACL diagnostics
- Add selected-section descriptor copy plus validated JSON backup and restore
- Add a Sampler build with PowerShell 7 and Windows PowerShell 5.1 test coverage
- Add command help, object formatting, a task-oriented usage guide, and
    research notes
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
- Add five class-based exact selected-section DSC resources for NTFS, registry
    keys, named services, the Service Control Manager, and pinned processes,
    including prefixed compliance reasons and Desktop LCM acceptance
- Add five class-based exact access-rule presence DSC resources with typed
    rights, SID-normalized matching, `Present`/`Absent` convergence, duplicate
    exact-ACE cleanup, and ten-resource MOF/LCM acceptance
- Add `Invoke-WindowsAccessControl` for explicit, local-only credential
    impersonation across Windows PowerShell 5.1 and PowerShell 7
- Add three inherit-only single-level NTFS `AppliesTo` values
    (`SubfoldersAndFilesOnlyOneLevel`, `SubfoldersOnlyOneLevel`,
    `FilesOnlyOneLevel`) across the NTFS access and audit cmdlets and the NTFS
    DSC resource, matching the full NTFSSecurity `ApplyTo` coverage
- Add native `InheritedFrom` provenance to NTFS access-rule results and their
    curated table view
- Document the Draft, domain-lab-gated roadmap and tracked work packages for
    scheduled tasks/task folders, certificate private keys, SMB shares, and
    Active Directory objects
- Add a secret-free domain-lab inventory with symbolic topology, remote
    transport findings, cross-edition read-only LDAP evidence, and explicit
    safety and replication gates
- Add a test-only, ownership-marked domain-lab lifecycle harness for disposable
    directory identities and groups, an SMB share, a Task Scheduler folder, and
    a software CNG certificate key, with idempotent setup/teardown, compensating
    cleanup, and explicit private-key deletion evidence
- Add an unattended domain-lab acceptance runner with fixed suite ordering,
    heartbeat timestamps, strict nonzero/no-skip gates, exact sanitized skip
    reasons, atomic JSON evidence, and a fail-stop cleanup ledger
- Add local SMB-share DACL descriptor and typed access-rule query, add, set,
    and exact-remove workflows with bounded execution and share-description
    preservation
- Add bounded local SMB share-only effective access with explicit SID-derived
    context and backing-NTFS exclusion
- Add explicit-DC Active Directory object DACL descriptor and object-specific
    access-rule query, add, set, and exact-remove workflows over signed and
    sealed LDAP with allowed-OU and immutable-GUID enforcement
- Add local Task Scheduler folder and registered-task DACL descriptor get/set
    commands with allowed-root containment, Local System ACE preservation,
    COM cleanup, canonical verification, rollback, and disposable live evidence
- Add in-memory NTFS descriptor editing: `Set-NTFSItemSecurityDescriptor`
    persists an edited descriptor object with one write, and `Add-NTFSAccessRule`
    can stage an access rule on a descriptor from `Get-NTFSItemSecurityDescriptor`
    without writing until it is persisted
- Add `Edit-NTFSItemSecurityDescriptor` for a bounded one-read, at-most-one-write
    callback scope with `ArgumentList`, loaded-section enforcement, `WhatIf`,
    and pass-through output
- Add read-only DACL inspection for an exact persisted RSA key in Microsoft
    Software Key Storage Provider, with certificate/provider/key cross-checks,
    hashed canonical identity, and no private-key export

### Changed

- **Breaking:** qualify the SMB share canonical target and write-lock key with
    the owning computer name. `SmbShare:Local:<SHARE>` becomes
    `SmbShare:<SERVER>:<SHARE>`, and share targets, descriptors, and rules now
    report a `Server` property
- Defer Active Directory effective access on measured evidence rather than
    presenting a locally constructed Authz or `tokenGroups` result as a
    directory access decision
- Make `Server` optional on `Get-ADObjectAccessRule`,
    `Get-ADObjectSecurityDescriptor`, `Add-ADObjectAccessRule`, and
    `Set-ADObjectSecurityDescriptor`. When it is omitted, one writable domain
    controller is located in the computer's domain, validated by the same
    explicit-name rules, reported through the verbose stream, and pinned for
    every target of that invocation
- Make `SecurityDescriptor` the default parameter set on the registry
    descriptor and rule mutators so a piped descriptor binds to its typed
    parameter instead of the untyped `Path`. Path-based invocation is
    unchanged, but a call with no bound target now reports `SecurityDescriptor`
    as the missing mandatory parameter
- Complete the cross-edition enterprise release gate with privilege, static,
    package, cleanup, security-review, and policy-qualified impersonation
    evidence
- Accept the delivered first in-memory descriptor-editing contract, verify the
    enterprise lab entry gate, and split broad SMB/AD roadmap issues into
    focused follow-up work
- Reject UNC targets in `Get-NTFSItemEffectiveAccess` and explicitly defer
    remote or combined SMB-plus-NTFS effective-access claims
- Move continuous integration from Azure Pipelines to GitHub Actions while
    preserving full-history GitVersion builds and the PowerShell 7 and Windows
    PowerShell 5.1 test matrix
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
- Constrain the `AppliesTo` key of the `WindowsAccessControlNtfsAccessRule` and
    `WindowsAccessControlRegistryKeyAccessRule` DSC resources with a
    `ValidateSet` that matches the cmdlet surface, so `Get-DscResource -Syntax`
    advertises the allowed values and invalid values fail at compile time

### Security

- Reject a Task Scheduler DACL write that newly denies an identity in the Task
    Scheduler service token the read, write, or run access the service requires
- Reject object and compound ACEs in a Task Scheduler DACL, which the store
    silently re-revisions so exact-persistence verification cannot succeed
- Reject a Task Scheduler rule mutation whose target DACL changed after the
    staging read, instead of silently clobbering the concurrent change
- Verify the Task Scheduler rollback descriptor and report an indeterminate
    stored state when it cannot be confirmed
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
- Zero unmanaged password memory, restore the caller identity after every
    impersonation path, and dispose local logon tokens before returning

### Fixed

- Correct the published Active Directory authority contract, which still stated
    that the commands reject implicit domain-controller discovery after that
    behavior shipped
- Propagate a terminating error raised by a command downstream of a batched
    target instead of downgrading it to a non-terminating error, so a piped
    fail-closed rejection such as `Get-NTFSItemSecurityDescriptor -Sections
    Owner | Add-NTFSAccessRule` stops the caller as its own contract promises
- Let a command downstream of a batched target dispatch and lock its own
    targets, instead of observing the batch-worker flag and taking the inline
    branch that skips same-target write serialization
- Reject a descriptor-bound mutation whose required section was not loaded,
    instead of expanding the persisted section set and replacing a live ACL
    with an empty one
- Persist the selected ACL protection state with `Set-NTFSItemSecurityDescriptor`
    so a detached inheritance edit converges like its path-bound equivalent
- Request NTFS ACL protection only for an ACL that is present, so persisting an
    `Access, Audit` descriptor on an item without a SACL no longer fails after
    the DACL was already written
- Refresh a filesystem descriptor's SDDL, protection, and canonical projection
    after each in-memory mutation so a staged descriptor cannot be backed up or
    inspected with pre-edit content
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
- Use Pester breakpoint coverage so Windows PowerShell 5.1 exact-descriptor DSC
    integration tests remain constructible after LCM acceptance
