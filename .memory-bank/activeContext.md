---
status: current
last-verified: 2026-07-26
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

Continue the signed `WindowsAccessControl` expansion on
`ai/windows-access-control`. Bounded cross-family execution, canonical target
serialization, metrics, aggregate NTFS backup reads, and five exact-descriptor
DSC resources are complete. The next signed slice is access-rule presence DSC
resources for every supported family.

## Evidence

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

## Next step

Implement class-based access-rule presence DSC resources for filesystem,
registry key, named service, SCM, and pinned-process contracts. Revisit optional
local impersonation only if the signed scope retains it. Do not push or publish
without an explicit request.
