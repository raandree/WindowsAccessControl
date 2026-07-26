---
status: current
last-verified: 2026-07-26
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

Continue the signed `WindowsAccessControl` expansion on
`ai/windows-access-control`. Unified cross-domain descriptor portability is
complete; the next milestone is bounded execution and metrics.

## Evidence

- The package is hard-renamed to `WindowsAccessControl`, retains its GUID, and
    has no third-party runtime dependency.
- Accepted specifications and ADRs define automatic scoped privileges, one
    shared binary descriptor engine, a local-only object boundary,
    object-specific cmdlet and DSC surfaces, and bounded parallel execution.
- NTFS, registry-key, named-service, and Service Control Manager families are
    complete and green in PowerShell 7 and Windows PowerShell 5.1.
- The live-process family adds 12 descriptor and access/audit rule commands,
    bringing the module to 67 exported commands.
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
- The authoritative PowerShell 7 gate passes 596 tests with zero failures or
    skips at 84.21 percent coverage against the 80 percent threshold.
- The 14 live process scenarios and 12 exact-name command contracts pass in
    Windows PowerShell 5.1 with zero failures or skips.
- A focused process rerun asserts exact before/after state for all three scoped
    privileges; all 14 scenarios pass and no `WacProcessTest` child remains.
- PSScriptAnalyzer is clean across 39 changed scripts, workspace diagnostics
    are clean, and changed-file encoding and whitespace checks pass.
- Independent security review returned APPROVE with no Blocker or Major
    findings. Residual risk is limited to caller misuse of stale output from a
    borrowed handle and defensive native cleanup/dead-code follow-ups.
- `Backup-WindowsSecurityDescriptor` and `Restore-WindowsSecurityDescriptor`
    provide one schema-versioned envelope for filesystem, registry, service/SCM,
    and pinned process descriptors, bringing the module to 69 exports.
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
- The authoritative PowerShell 7 gate passes 629 tests with zero failures or
    skips at 85.39 percent coverage. The focused Windows PowerShell 5.1 gate
    passes 76 tests with zero failures or skips.
- Independent security re-review returned APPROVE with no Blocker or Major
    findings after adversarial recomputed-digest, mixed-signature, atomic-write,
    absent-SACL, and cross-edition hash-vector coverage.
- Final out-of-band checks report 69 exports, exact privilege-state restoration,
    and zero leaked processes, services, or registry roots.

## Next step

Implement bounded target execution, same-target serialization, and metrics,
then optional local impersonation if retained and class-based DSC resources. Do
not push or publish without an explicit request.
