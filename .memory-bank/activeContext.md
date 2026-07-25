---
status: current
last-verified: 2026-07-25
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

The fully implemented and independently approved `NTFSPermission` 0.1.0 module
is complete and locally committed on `ai/ntfs-permissions-module`.

## Evidence

- Microsoft documentation confirms distinct add, set, reset, and remove ACL
    semantics, Windows-only support, and canonical ACE ordering requirements.
- NTFSSecurity and PowerShellAccessControl validate the desired command surface
    but are dormant; NTFSSecurity relies on archived AlphaFS-era components.
- Sampler 0.119.1, Pester 5.7.1, PowerShell 7.6.1, and Windows PowerShell 5.1
- Sampler 0.120.0, Pester 5.7.1, PowerShell 7.6.1, and Windows PowerShell 5.1
    are available locally.
- The module exports 27 commands and has no third-party runtime dependency.
- PowerShell 7 and Windows PowerShell 5.1 each pass 228 tests with 84.41
    percent executable coverage.
- Independent security and quality re-review approved the implementation after
    all Blocker, Major, and Minor findings were resolved.

## Next step

Await the next user-directed release, publication, or feature task after the
required local commit. Do not push without an explicit request.
