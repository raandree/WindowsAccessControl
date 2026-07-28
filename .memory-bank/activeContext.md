---
status: current
last-verified: 2026-07-28
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

The `ENT-1` enterprise domain-lab inventory is active on
`ai/domain-lab-inventory`. The current lab provides one writable domain
controller, one member server, and one management host in a single-domain
forest with no trusts. Read-only cross-edition Active Directory probes are
unblocked; mutation remains gated on verified isolation, reset, and recovery
boundaries. Remote push and publication remain under explicit user control.

## Evidence

- `docs/domain-lab-inventory.md` records symbolic roles and capabilities
    without machine names, domain names, addresses, credentials, or recovery
    material.
- The member server is domain joined, runs Windows Server 2022, accepts an
    explicit Kerberos WinRM session, and exposes Task Scheduler, SMB server,
    WinRM, and the LDAP protocol API through Windows PowerShell 5.1.
- The management host and writable domain controller provide both supported
    PowerShell editions needed for read-only LDAP probes. The member server
    still needs PowerShell 7 or an equivalent cross-edition replacement.
- Signed and sealed Negotiate LDAP probes in PowerShell 7.6.3 and Windows
    PowerShell 5.1 selected a writable domain controller, read RootDSE naming
    contexts, retrieved the domain DACL, and parsed its binary descriptor.
- The member-server WinRM service permits Basic, CredSSP, and unencrypted
    traffic. Explicit Kerberos succeeded, but `ENT-4` remains blocked until the
    approved encrypted transport and downgrade-rejection contract is defined.
- One writable domain controller is sufficient for entry-gate and read-only
    work but not `AD-6` replication, domain-controller switch, or failover
    evidence.
- `.github/workflows/build.yml` passes actionlint 1.7.12, uses read-only
    permissions, pins official actions to reviewed commits, and defines a
    full-history build followed by two artifact-consuming Windows test jobs.
- GitVersion 5.12.0 resolves `main` as `0.2.0-preview0001`; no active Azure
    Pipelines file remains.
- A clean CI-only clone built successfully. PowerShell 7 passed 816 tests with
    zero failures or skips at 88.22 percent coverage; Windows PowerShell 5.1
    passed 789 with zero failures or skips at 87.83 percent coverage.
- Specification 0008 defines separate Task Scheduler, certificate-key, SMB,
    and Active Directory work packages plus cross-cutting `ENT-*` foundation
    tasks and a domain-lab entry gate.
- Open issues OI-6 through OI-10 track the lab/security foundation and four
    independently closable domain implementations.
- ADR 0014 records that no production implementation or remote public API
    begins before the lab and security contracts exist; ADR 0011 remains the
    current-release boundary.
- Specification conformance passes eight tests after indexing specification
    0008 and ADR 0014 and resolving every local link.
- `Get-NTFSAccessRule` exposes `InheritedFrom` from `GetInheritanceSourceW`.
    Explicit rules and unresolved native sources return null; no parent-rule
    heuristic is used.
- Native source rows are filtered from the same binary descriptor to the
    `CommonAce` allow/deny subset emitted by .NET, preserving positional pairing
    when unrelated object ACEs exist. Explicit-only queries skip the native walk.
- Eight focused provenance tests pass in PowerShell 7 and Windows PowerShell
    5.1. They cover explicit nulls, files, directories, original grandparents,
    mixed rules, object ACE coexistence, and the explicit-only fast path.
- Specification QA passes eight tests. The final privilege-compatible Sampler
    profile passes 714 tests with zero failures and one skip; the complete
    elevation/coverage gate requires a privileged token.
- Independent native-interop re-review returned APPROVE with no Blocker or
    Major findings after managed/native ACE alignment and fast-path repairs.
- The package is hard-renamed to `WindowsAccessControl`, retains its GUID, and
    has no third-party runtime dependency.
- Accepted specifications and ADRs define automatic scoped privileges, one
    shared binary descriptor engine, a local-only object boundary,
    object-specific cmdlet and DSC surfaces, and bounded parallel execution.
- NTFS, registry-key, named-service, and Service Control Manager families are
    complete and green in PowerShell 7 and Windows PowerShell 5.1.
- The live-process family adds 12 descriptor and access/audit rule commands.
- Process commands accept `Process`, PID, pinned module output, or borrowed raw
    handles. PID operations verify creation `FILETIME` and use one handle for the
    complete read, comparison, mutation, and write operation.
- Process writes include `READ_CONTROL`; module-owned handles close in
    `finally`, caller-owned handles remain open, and operation plus cleanup
    failures are aggregated.
- SACL and owner/group work scopes `SeSecurityPrivilege` and
    `SeRestorePrivilege`. An access-denied PID open retries with
    `SeDebugPrivilege` only when the token already contains it, then restores the
    exact initial enabled state.
- `Backup-WindowsSecurityDescriptor` and `Restore-WindowsSecurityDescriptor`
    provide one schema-versioned envelope for filesystem, registry, service/SCM,
    and pinned process descriptors.
- Every record carries a deterministic SHA-256 digest over restore-relevant
    fields. Optional RSA X.509 signatures are thumbprint-pinned to the supplied
    certificate and verified before target preparation.
- Restore validates every record, integrity proof, canonical target, selected
    section, duplicate, and process creation identity before the first write.
- Backup signs only after `ShouldProcess`, rejects duplicate canonical targets,
    and atomically moves or replaces a completed same-directory temporary file.
- Selected absent SACLs use explicit `S:NO_ACCESS_CONTROL`; omitted selected
    SACLs and all null DACLs fail closed.
- Historical unmarked NTFS schema-version 1 files remain readable. The legacy
    NTFS restore command rejects unified records from other object families.
- All ordinary target-array commands expose `ThrottleLimit` from 1 through 64,
    defaulting to the smaller of eight and the logical processor count.
- Complete target normalization and case-insensitive canonical deduplication
    precede dispatch. Mutations of the same canonical target serialize across
    isolated module instances through an application-domain lock registry.
- Worker runspaces import isolated module instances; the parent module owns
    target locks and aggregate metrics. `ThreadLocal[bool]` prevents recursive
    single-target command entry.
- `Get-WindowsAccessControlMetric` is the 70th export and reports redacted
    operation, target, success, failure, and elapsed aggregates.
- `Backup-NTFSItemSecurityDescriptor` performs bounded descriptor reads and one
    complete atomic envelope write only after every read succeeds.
- The reusable NTFS benchmark alternates sequential and parallel runs without a
    timing assertion. The retained 512-target sample averaged 407.94 targets/s
    sequential and 431.45 targets/s at throttle 8.
- The authoritative PowerShell 7 gate passes 670 tests with zero failures or
    skips at 86.35 percent coverage. The focused Windows PowerShell 5.1
    concurrency gate passes 37 tests with zero failures or skips.
- PSScriptAnalyzer is clean across 75 changed PowerShell files; all 75 parse,
    `git diff --check` passes, and 81 changed files satisfy encoding/newline
    rules.
- Two independent concurrency reviews returned APPROVE with no Blocker or
    Major findings. Live tests cover canonical deduplication, prevalidation,
    bounded mutation, parallel `WhatIf`, and aggregate backup behavior.
- Five class-based exact-descriptor resources cover NTFS, registry key, named
    service, SCM, and pinned process targets with object-specific composite
    keys, selected-section SDDL, and prefixed compliance reasons.
- Exact comparison ignores only Windows-derived DACL/SACL `AUTO_INHERITED`
    flags. Protection state and every selected ACE remain exact; omitted
    selected sections and null DACLs fail closed.
- Live tests reconverge NTFS DACL and all-section state plus registry DACL state;
    named service, SCM, and pinned process resources query real descriptors.
    Desktop evidence compiles all five resources into one MOF and invokes the
    all-section NTFS resource through the SYSTEM LCM.
- The authoritative PowerShell 7 gate passes 716 tests with zero failures or
    skips at 86.69 percent coverage. The focused Windows PowerShell 5.1 exact
    gate passes 31 tests plus two LCM tests with zero failures or skips.
- Independent exact-resource review and re-review returned APPROVE after
    fail-closed and combined DACL/SACL coverage was added.
- Five access-rule presence resources manage one exact explicit ACE for NTFS,
    registry key, named service, SCM, and pinned process targets. Composite keys
    include typed rights, qualifier, scope where supported, registry view, and
    process creation identity.
- Exact matching normalizes account aliases to SID, 32-bit masks to unsigned
    values, and NTFS Allow masks through `FileSystemAccessRule` so its automatic
    `Synchronize` bit converges. `Absent` removes every duplicate exact native
    ACE while preserving partial, inherited, opposite-qualifier/scope, and
    unrelated rules.
- Live tests converge `Present` and `Absent` for all five families with SCM and
    process DACL rollback. Desktop LCM evidence compiles all ten resources and
    invokes NTFS exact-descriptor and rule-presence resources.
- The authoritative PowerShell 7 gate passes 766 tests with zero failures or
    skips at 87.59 percent coverage. The focused Windows PowerShell 5.1 rule
    gate passes 35 tests plus three LCM tests with zero failures or skips.
- Independent rule-resource review and re-review returned APPROVE with no
    remaining Blocker, Major, or Minor findings.
- `Invoke-WindowsAccessControl` provides one explicit local impersonation scope
    over existing command calls without adding remote target syntax.
- `LogonUserW` receives password data through temporary unmanaged memory that
    is zeroed in `finally`; `WindowsIdentity.RunImpersonated` restores the
    caller identity and the safe token handle is disposed before return.
- Disposable-local-user acceptance passes argument, nested-scope, exception,
    and invalid-credential cases in both PowerShell 7 and Windows PowerShell
    5.1 with zero failures or skips and no leaked test accounts.
- The final PowerShell 7 gate passes 779 tests with zero failures or skips at
    87.53 percent coverage. The combined Windows PowerShell 5.1 QA and
    impersonation gate passes 450 tests with zero failures or skips.
- `WindowsAccessControl.0.2.0-windows.nupkg` builds in a clean detached host
    with 71 functions, ten DSC resources, the local impersonation export, and
    only the eight expected package entries.
- Final AST, PSScriptAnalyzer, whitespace, archive inventory, manifest, and
    cleanup checks are green. Independent impersonation review and re-review
    returned APPROVE with no Blocker or Major findings.
- The NTFS and registry DSC `AppliesTo` key properties now carry a `ValidateSet`
    matching the cmdlet surface, so `Get-DscResource -Syntax` advertises the
    allowed values and invalid values fail at compile time. A contract test
    keeps each set equal to its cmdlet parameter set.
- The NTFS `AppliesTo` vocabulary now includes the three inherit-only
    single-level values (`SubfoldersAndFilesOnlyOneLevel`, `SubfoldersOnlyOneLevel`,
    `FilesOnlyOneLevel`), matching full NTFSSecurity `ApplyTo` coverage; a
    converter round-trip test guards all thirteen labels.
- The two untracked pre-rename stale files
    (`source/Private/Initialize-NTFSNativeType.ps1` and
    `tests/Integration/Elevated-NTFSPermission.Tests.ps1`) were removed with
    explicit approval; their tracked renamed equivalents remain. The full
    PowerShell 7 gate is now fully green at 797 passed, 0 failed, 0 skipped,
    88.06 percent coverage.
- Pester 5.7.1 profiler-tracer coverage reproduced six Windows PowerShell 5.1
    exact-descriptor DSC failures after Desktop LCM acceptance. The same
    covered nine-test sequence passed with breakpoint coverage and the original
    fixture.
- The final breakpoint-coverage gates pass 770 Windows PowerShell 5.1 tests at
    87.79 percent coverage and 797 PowerShell 7 tests at 88.19 percent coverage,
    with zero failures or skips in either edition.

## Next step

Confirm the forest-isolation, machine-reset, and untouched recovery-identity
gates. Then turn the successful `AD-1` baseline into a repeatable read-only
probe and design idempotent `ENT-2` setup and teardown without applying it.
Provide a second writable domain controller only when `AD-6` replication and
failover work begins. Do not push or publish without an explicit request.
