---
status: current
last-verified: 2026-07-25
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

Expand and rename the unpublished module to `WindowsAccessControl` on
`ai/windows-access-control`, following the signed one-round design interview.

## Evidence

- Microsoft documentation confirms distinct add, set, reset, and remove ACL
    semantics, Windows-only support, and canonical ACE ordering requirements.
- Sampler 0.120.0, Pester 5.7.1, PowerShell 7.6.1, and Windows PowerShell 5.1
    are available locally.
- The module exports 28 commands, has 50 direct command specifications, and has
    no third-party runtime dependency.
- Full cross-edition QA runs covered 244 tests at 84.5 percent before the final
    two deduplication guards were added. Final behavior reruns in each edition
    discovered 73 tests: 67 passed, zero failed, and six privilege-gated tests
    skipped with explicit reasons.
- The elevated token contains `SeSecurityPrivilege`, `SeRestorePrivilege`, and
    `SeTakeOwnershipPrivilege`; all seven live SACL, descriptor-copy, and
    arbitrary-owner scenarios pass with zero skips.
- PowerShell 7 did not persist an unprotected SACL control flag through
    `FileSystemAclExtensions.SetAccessControl`; section-scoped
    `SetNamedSecurityInfoW` persistence with the selected ACL pointer fixed it.
- Independent security and quality review returned APPROVE with no Blocker or
    Major findings; all concrete Minor and Nit findings were resolved.
- The current package is `output/NTFSPermission.0.1.0.nupkg`.
- `specs/` now owns six accepted numbered specifications, 27 stable
    requirements, 14 indexed ADRs, open issues, and executable conformance
    checks. Comment-based help remains the per-command reference.
- Specification 0006 and ADRs 0008 through 0013 define the signed
    `WindowsAccessControl` expansion, automatic scoped privileges, shared
    binary descriptor engine, local object boundary, public/DSC shape, and
    bounded parallel execution.
- A disposable local native-API probe returned nonempty descriptors for a
    registry key, service, and process and cleaned up its scratch targets.
- Full QA with the specification contract passes 181 tests with zero failures;
    its eight conformance checks cover structure, status, requirement identity,
    traceability, exports, local links, format views, and ADR indexing.

## Next step

Implement the module rename and shared Windows identity/security-descriptor
engine test-first, then layer object-specific registry/service/process commands
and class-based DSC resources. Do not push or publish without an explicit
request.
