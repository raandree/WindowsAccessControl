# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `RegistryTargetAliasMatrix.Tests.ps1` and `RegistryViewsAndRights.Tests.ps1`
    and record ADR 0032. The two registry views were carried on the returned
    object but never proven independent: writing an entry through the 32-bit view
    of a genuinely redirected key now has to leave the 64-bit view unchanged, and
    the reverse, with the view carried into every emitted rule and neither pass
    leaking into the other. Every accepted hive alias, the
    `Microsoft.PowerShell.Core\Registry::` prefix, the current-config expansion,
    and every documented rejection now has a case, asserted on the canonical
    target rather than on the absence of an error. Three rights facts are pinned:
    `FullControl` is 983103, which is `KEY_ALL_ACCESS` and carries no
    `SYNCHRONIZE`; `ReadKey` and `ExecuteKey` are the same value and survive a
    round trip without a name flip; and no registry rights value carries
    `SYNCHRONIZE`. The Windows PowerShell defect that only existed as a source
    comment is now an asserted difference: `Get-Acl -LiteralPath` cannot resolve
    a bracketed registry key in Windows PowerShell and can in PowerShell 7, while
    the module resolves it in both because it resolves the target itself
- Add stable identifier `FR-32` for the registry view, alias, and rights contract
- Add `NtfsIcaclsDifferentialOracle.Tests.ps1`, which compares what the module
    writes against what `icacls` reads back, parsing only bracketed tokens so the
    suite passes on a localized host. It covers all thirteen `AppliesTo` values
    on disk, the deny matrix including a deny that would land after an existing
    allow, `Synchronize` normalization on allow and deny, `icacls /verify` over
    every list the module writes, automatic propagation to pre-existing children
    in both directions, and an `icacls /save` byte-identical backup and restore
    round trip. Two platform behaviors are now asserted rather than assumed:
    `icacls` applies the file system generic mapping when it renders a mask, so
    it prints `F` or `M` for an entry whose stored mask still carries
    `GENERIC_ALL`; and a noncanonical list written through `SetSecurityInfo` is
    stored exactly as written, neither reordered nor marked protected, which
    both `Test-NTFSItemAcl` and `icacls /verify` report
- Add stable identifier `FR-31` for the materialized-descriptor contract
- Add `NtfsReparsePointsAndLinks.Tests.ps1` and record ADR 0030 and ADR 0031.
    Nothing in the test tree mentioned a junction, a symbolic link, or a hard
    link, so the module's behavior on a reparse point was whatever `Get-Acl`
    happened to do. Measured in both editions, a junction, a directory symbolic
    link, and a file symbolic link each carry their own security descriptor: a
    write through the link changes the link and leaves the destination
    untouched, which is what `Get-Acl`, `Set-Acl`, `icacls`, and `icacls /L` all
    do. A hard link shares one descriptor between both names because there is
    one file record. That behavior is now stated in the module help and in the
    description of the commands that resolve a file system path, and asserted on
    real fixtures. Termination is asserted too: no command walks a tree, so a
    self-referential junction is one ordinary target and a wildcard expands
    exactly one level
- Add stable identifier `FR-30` for the reparse-point and target-set contract
- Add `NtfsPathInputMatrix.Tests.ps1`, a table-driven matrix that pins a
    deterministic outcome for every hostile path and name shape: a trailing
    space or period, a name beginning with `$ - + # { ,`, a bracketed name under
    both parameter sets, a bare drive specification against a drive root, a
    drive-relative child, `.` and `..`, a `FileInfo` and a `DirectoryInfo` bound
    positionally, a path past `MAX_PATH`, a 255-character component, the
    reserved device names, mixed case, forward slashes, the administrative
    share, and the device namespace. Where the two supported PowerShell
    editions genuinely differ the difference is asserted rather than skipped:
    a target past `MAX_PATH` is reachable in PowerShell 7 and reported as
    missing in Windows PowerShell, and a wildcard supplied through
    `-LiteralPath` is a missing path in PowerShell 7 and an empty result in
    Windows PowerShell
- Add stable identifier `FR-29` for the NTFS path contract and record ADR 0029
- Accept a raw access mask wherever an NTFS command takes `-AccessRights`, so an
    access control entry carrying `GENERIC_ALL`, the `GENERIC_READ` /
    `GENERIC_WRITE` / `GENERIC_EXECUTE` combination, or `ACCESS_SYSTEM_SECURITY`
    can be created, replaced, and removed. The parameter stays typed as
    `FileSystemRights` so a name still completes and an unknown name is still
    rejected; a numeric mask is now converted before the enum conversion rejects
    it. Supply such a mask as a decimal number or a quoted hexadecimal string,
    because a bare hexadecimal literal in argument mode never reaches the
    conversion
- Add `NtfsGenericAndOrphanedAceRemoval.Tests.ps1`, which proves on a real
    directory that an entry carrying generic bits or an unresolvable identifier
    is reported with its exact mask and can be removed by account purge, by
    exact mask, through a pipeline round trip, and by `Clear-NTFSAccessRule`,
    with the same evidence for the audit family. Both existing test groups mock
    `Get-Acl`, so nothing had ever reached disk. The suite also pins the
    platform behavior that Windows maps the generic bits of an entry that is not
    inherit-only through the file system generic mapping when the descriptor is
    written
- Add stable identifier `FR-28` for reporting and removing an entry whose mask
    carries bits the `FileSystemRights` enumeration cannot name

### Fixed

- Refuse a Win32 device-namespace path (`\\?\`, `\\.\`) and a bare drive
    specification such as `C:` in every NTFS command. Both resolved to something
    other than what the caller wrote: the device namespace bypasses
    normalization and produces a target key that is not canonical, and `C:`
    resolves to the current location of that drive rather than the volume root,
    so a command meant for a volume silently addressed a directory inside it.
    Each is now a terminating error that names the replacement. See ADR 0029
- Fix removal of an access or audit entry whose mask carries bits the
    `FileSystemRights` enumeration cannot name. The public rule constructors
    reject any mask outside `FullControl`, and `RemoveAccessRuleSpecific`
    rebuilds the rule through exactly that constructor when no stored entry
    matches, so a documented orphan-cleanup one-liner reported the entries and
    deleted nothing. Rules are now built through the rule factory, which takes
    the mask verbatim, and an exact removal that finds no match is a no-op
    instead of an argument-range error

- Add tab completion for the `Name` parameter of `Enable-WindowsPrivilege`,
    `Disable-WindowsPrivilege`, and `Test-WindowsPrivilege`. The parameter takes
    a constant nobody recalls exactly, and a misspelling was reported only after
    the command ran. Completion now offers every documented Windows privilege
    constant together with the user right it grants, matches a fragment anywhere
    in the name because all of them share the same prefix, and treats the typed
    text as literal so an unbalanced bracket cannot fail a keystroke
- Add a PowerShell edition matrix to the domain-lab acceptance runner. The six
    enterprise suites are cross-edition contracts, but the runner started only
    Windows PowerShell, so PowerShell 7 had no live enterprise evidence even
    though the deployment installs it on every lab machine. The runner now takes
    `-PowerShellEdition` and runs one complete pass per edition against the same
    fixture set, writes one evidence file per pass, and carries every artifact
    back before it fails the run. `-CoverageEdition` arms code coverage in
    exactly one pass, because instrumentation is what makes a pass slow and the
    second pass measures no line the first cannot reach
- Add two DSC engine contract tests. The five enterprise resource pairs were
    converged only by direct class instantiation, so nothing proved the engine
    could see them: a compile test now puts all ten into one Managed Object
    Format document, and a discovery test asserts that `Get-DscResource`
    advertises every resource the manifest exports
- Add `ForeignPrincipalPermissions.Live.Tests.ps1`, a seventh acceptance suite
    that writes and reads an access control entry for a principal from another
    domain in the forest, from a trusted forest, and for a security identifier
    no lookup can resolve. Every other suite uses a principal from the fixture
    domain, so nothing proved that a foreign identity survives a write and a
    read or that an orphaned entry is reported instead of failing the descriptor
- Add stable identifiers `FR-24` through `FR-27` and `NFR-17` through `NFR-20`
    for the behavior delivered after read-only private-key inspection:
    fail-closed private-key DACL mutation, schema-version-2 enterprise
    portability, the enterprise desired-state resources, and immutable directory
    identity. Each is traced to executable evidence in specification 0005
- Add roadmap task traceability to specification 0005, which maps every `ENT-*`,
    `TASK-*`, `KEY-*`, `SMB-*`, and `AD-*` task to its current state and to the
    evidence or the decision record that closes it
- Add ADR 0027, which records that the coverage threshold is asserted over the
    commands the running test profile can execute, why the whole-module number
    is reported rather than asserted, and why a source file may only be declared
    domain-lab-only while the local profile executes no command of it
- Add certificate private-key portability and desired state. Every private-key
    command gains a `Key` parameter set that selects the key by CNG provider,
    persisted key name, and `Machine` or `User` key scope, so a portability
    record and a Managed Object Format document never carry a certificate.
    `Backup-WindowsSecurityDescriptor` emits a schema-version-2
    `CertificatePrivateKey` record and `Restore-WindowsSecurityDescriptor`
    replays it only on the computer that produced it, through the same
    fail-closed write boundary as a direct write. A certificate thumbprint is
    recorded as evidence and is never used to find a key, because a renewal that
    reuses the key changes it while the key stays the same
- Add `WindowsAccessControlCertificatePrivateKeySecurityDescriptor` and
    `WindowsAccessControlCertificatePrivateKeyAccessRule`, which manage the
    private-key DACL as desired state. Compliance expands the generic bit the key
    storage provider adds to a stored ACE, so a converged key does not report
    drift on every consistency run. Creating a deny rule is refused, because the
    write boundary admits no way to create one
- Add specification 0017 and ADR 0026, which record the key-addressed selector,
    the computer-scoped record, and the rule that a restore inherits every
    fail-closed private-key write gate without an override
- Add fail-closed DACL mutation for a persisted RSA private key in Microsoft
    Software Key Storage Provider through
    `Add-CertificatePrivateKeyAccessRule`,
    `Remove-CertificatePrivateKeyAccessRule`,
    `Set-CertificatePrivateKeySecurityDescriptor`, and the typed reader
    `Get-CertificatePrivateKeyAccessRule`; the write is refused unless the
    provider itself reports a software-only implementation, no HTTP.sys, WinRM
    HTTPS, Remote Desktop, or LDAPS binding uses the same private key, every
    candidate ACE is a plain allow or deny, no deny ACE is added, and the result
    keeps SYSTEM, Administrators, and every existing service grant
- Add `Test-CertificatePrivateKeyCriticalBinding` so a refused private-key write
    can be explained without changing state; it compares the private key by
    public key rather than by thumbprint, so a certificate renewed with key reuse
    cannot hide a live binding
- Add `WindowsCryptoKeyRights`, which mirrors the file rights the software key
    storage provider stores, and compare every private-key ACE after expanding
    the generic bit the provider adds when it stores a candidate
- Add a reproducible multi-forest lab deployment
    (`tests/Lab/Deploy-WindowsAccessControlLab.ps1`) with three forests, two
    child domains, a second writable domain controller in the fixture domain, an
    enterprise root certification authority, and four member servers
- Add live Active Directory replication, domain-controller switch, rename, move,
    deletion, and distinguished-name reuse coverage
    (`tests/Lab/ADObjectReplication.Live.Tests.ps1`), plus a pinned-controller
    outage test that proves a command fails instead of silently redirecting to a
    surviving controller
- Add specification 0016, which records the Active Directory multi-controller
    identity, replication, and outage behavior that specification 0009 deferred
- Add a lab guide (`tests/Lab/README.md`) that names the AutomatedLab sample
    scenario the domain acceptance lab is based on, lists every addition made on
    top of that baseline with the suite that requires it, maps each machine to
    the behavior it serves, and documents the deployment and acceptance workflow

### Changed

- Publish the module from the continuous integration pipeline. A build of the
    default branch, or of a stable `v*` tag, now packages the module, creates the
    GitHub release with the NuGet package attached, publishes to the PowerShell
    Gallery, and raises the changelog pull request. The publish job requires both
    the `GitHubToken` and the `GalleryApiToken` repository secret and fails when
    either is missing, because a skipped GitHub release combined with a
    successful Gallery publish ships a version without the tag the next version
    calculation depends on. It runs only on the upstream repository, so a fork
    and a pull request never reach the Gallery, and a release run is never
    cancelled by a newer one
- Remove any PowerShell 7 `$PSHOME\Modules` directory from the machine module
    search path before the Windows PowerShell 5.1 test job runs. PowerShell 7
    ships `Core`-only copies of the in-box `Microsoft.PowerShell.*` modules, and
    when its module directory precedes the in-box one, Windows PowerShell
    resolves those first and cannot load them. Every host that has to autoload
    one then fails: `build.ps1` reports `Import-PowerShellDataFile` as
    unrecognized, and the DSC engine reports that `Get-Acl` was found but its
    module could not be loaded. The step is a no-op on a worker that does not
    carry such an entry
- Accept specification 0008. The enterprise roadmap is no longer a Draft: the
    acceptance conditions are recorded against the artifacts that satisfy them,
    the seven open questions are answered by the contracts that resolved them,
    and the claims that replication evidence was blocked and that open issue
    OI-18 tracked it are removed, because specification 0016 closed both
- Assert the 80 percent code-coverage threshold over the commands the running
    test profile can execute rather than over the whole module, so the same gate
    produces a verdict in the hosted build and on a host that has run the domain
    lab. Every measured line of the built module is attributed to its source file
    through the `#Region` markers ModuleBuilder writes, and only the fifteen
    Active Directory and SMB share files the local profile executes no command of
    are declared out of scope. The threshold is unchanged, the whole-module and
    domain-lab-only numbers are reported on every run together with whether
    domain-lab evidence was merged, and the build fails both when a declared path
    matches no source file and when the local profile does execute a declared
    file
- Treat a domain-lab coverage document that measures another build as absent
    with a warning instead of failing the build. It is still never merged, so a
    union of disjoint line sets stays impossible, but a contributor who cannot
    run the lab is no longer blocked by evidence only the lab can refresh
- Assert the 80 percent code-coverage threshold over the local run merged with
    the domain-lab acceptance instead of over the local run alone, so the gate
    measures the Active Directory, certificate private-key, SMB share, and Task
    Scheduler families that the default Pester profile structurally cannot
    execute; the threshold is unchanged and no test was added to reach it
- Collect code coverage in `Invoke-WindowsAccessControlDomainLabAcceptance`,
    including for the suites whose real work runs in a member-server session,
    by publishing the measurable locations of the module under test, arming them
    in the member runspace, and adding the returned hit counts to the
    harness-side counts
- Run the domain-lab acceptance in a child console process on the management
    domain controller, because a session runspace allows only 165 nested script
    frames there against 4694 in a console host, and the directory suites fail
    with a call-depth overflow rather than their asserted rejection once
    coverage instrumentation is added
- Key the private-key critical-binding gate on the write target's own public
    key, read from the key rather than from a certificate, so it applies
    identically whether the key was addressed through a certificate or through
    its provider and key name. A public key that cannot be read throws instead of
    reporting no binding
- Report the owning computer as `Server` on every certificate private-key
    descriptor and access rule, so evidence and portability records name the
    machine that produced them
- Rebuild a private-key candidate descriptor from its access section before the
    provider write, so an owner, group, or SACL supplied in `Sddl` is dropped
    rather than carried into the binary form
- Resolve a bound certificate against every local machine certificate store that
    exists plus the `NTDS` service store, instead of a fixed list of four
    stores, so a binding created against another store no longer blocks every
    private-key write on the machine; the stores a binding names in practice are
    searched first and the search stops once every bound thumbprint is resolved
- Read the `NTDS` service store natively under `CERT_SYSTEM_STORE_SERVICES`,
    which `StoreLocation` cannot address, so the LDAPS branch of the
    critical-binding gate is reachable on a domain controller
- Derive a concurrency token from their own read in
    `Add-CertificatePrivateKeyAccessRule` and
    `Remove-CertificatePrivateKeyAccessRule` when the caller supplies none, so a
    change another writer makes between that read and the write is rejected
    instead of overwritten
- Warn from `Remove-CertificatePrivateKeyAccessRule` naming every account the
    request did not match, because rights are matched exactly and a revocation
    that removed nothing must not look like one that succeeded
- Qualify Task Scheduler canonical identity by the owning computer, so
    `CanonicalTarget` is now `TaskFolder:<COMPUTER>:<PATH>` or
    `ScheduledTask:<COMPUTER>:<PATH>` instead of the previous `Local` form, and
    a registered task in the root folder no longer reports a doubled separator

### Fixed

- Fix access rules reporting a signed integer instead of rights names. A .NET
    rights enum has no name for the four `GENERIC_*` bits, and `Enum.ToString`
    abandons every name it did resolve as soon as one bit is unnameable. Windows
    splits an inheritable entry that carries generic rights into a mapped copy
    and an inherit-only copy that keeps the generic bits, so any directory under
    a volume root listed one `Authenticated Users` entry as `Modify,
    Synchronize` and the next as `-536805376`. Every rule object now also
    carries `AccessRightsDisplay`, which reuses the enum rendering wherever the
    enum can name the mask and otherwise names the generic rights,
    `ACCESS_SYSTEM_SECURITY`, and `MAXIMUM_ALLOWED`, leaving any remainder as
    hexadecimal. The default table views report it, and NTFS rules gained the
    `AccessMask` property the other object families already expose
- Fix `Get-NTFSItemEffectiveAccess` failing outright on a granted mask that
    `FileSystemRights` cannot name. The enum cast rejects such a value rather
    than boxing it, so the command threw instead of reporting the access it had
    just computed
- Fix two registry inheritance-source unit tests failing on Windows PowerShell
    5.1. `Get-Acl -LiteralPath` cannot resolve a registry key there and returns
    nothing, and `-bor` on two `AceFlags` values throws `InvalidCastException`
    because that enum is backed by `Byte`. The tests now read the key with
    `-Path` and build the ACE flags through `[int]` operands
- Fix `-Sections All` reporting inherited NTFS access rules as explicit rules.
    `GetNamedSecurityInfo` clears `INHERITED_ACE` on every DACL entry when the
    SACL is requested in the same call, so a whole-descriptor capture recorded
    inherited entries as explicit ones. Replaying that descriptor wrote them as
    explicit entries and detached the target from its parent, and the exact
    NTFS descriptor DSC resource never converged. The DACL now always comes
    from a read that omits the SACL, and the audited SACL is grafted onto it.
    See ADR 0028
- Fix the domain lab inventory claiming that a lab web server produces the
    HTTP.sys binding evidence; the evidence comes from a disposable `netsh http`
    binding on the fixture member server, and the web-server role is reserved
- Fix the private-key service-preservation gate refusing an exact reassert of a
    stored DACL that contains an inherit-only service ACE, which grants nothing
    and must not count as access the candidate has to preserve
- Fix a private-key DACL protection-state mismatch being detected only after a
    real provider write and a rollback; it is now refused before the write
- Fix `Add-RegistryKeyAccessRule` and `Add-RegistryKeyAuditRule` silently
    discarding a rule that matched an existing account and rights combination
    but declared a different `AppliesTo` inheritance scope
- Fix the account column printing nothing for an access or audit rule whose
    identity Windows cannot translate. A deleted account, an unreachable domain,
    and a foreign principal all rendered as an empty cell, so the entry could
    not be recognized without inspecting the object. Every rule table view now
    falls back to the security identifier, while the `Account` property stays
    empty and `IsOrphaned` keeps reporting the unresolved state

### Added

- Add schema-version-2 descriptor portability for Task Scheduler folders and
    registered tasks, qualifying canonical identity by the owning computer
    (`TaskFolder:<COMPUTER>:<PATH>`) so a record cannot be replayed on another
    machine; no hashed field was added, so every existing backup still validates
- Add `AllowedRootPath` to `Restore-WindowsSecurityDescriptor`; a Task Scheduler
    record restores only on the computer it names and every target is resolved
    for write during preparation
- Add four class-based DSC resources:
    `WindowsAccessControlTaskFolderSecurityDescriptor`,
    `WindowsAccessControlScheduledTaskSecurityDescriptor`,
    `WindowsAccessControlTaskFolderAccessRule`, and
    `WindowsAccessControlScheduledTaskAccessRule`
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
