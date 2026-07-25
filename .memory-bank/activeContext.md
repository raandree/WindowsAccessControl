---
status: current
last-verified: 2026-07-25
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

The NTFSSecurity comparison, specification audit, live-test expansion, and
selected 0.1.0 enhancements are complete and locally committed on
`ai/ntfs-permissions-module`.

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
- The current token does not contain `SeSecurityPrivilege` or
    `SeRestorePrivilege`; real SACL persistence and arbitrary-owner acceptance
    remain an elevated release gate rather than a claimed pass.
- Independent security and quality review returned APPROVE with no Blocker or
    Major findings; all concrete Minor and Nit findings were resolved.
- The current package is `output/NTFSPermission.0.1.0.nupkg`.

## Next step

Do not push or publish without an explicit request. Run the six
`RequiresElevation` specifications before a release when a suitably privileged
token is available.
