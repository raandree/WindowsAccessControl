---
status: current
last-verified: 2026-07-28
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

The first SMB-share and Active Directory DACL management slice is complete on
`ai/domain-lab-inventory`. The accepted specification, ten public commands,
focused and live tests, documentation, package validation, and independent
security review are ready for local handoff. The disposable lab is restored to
its ready state. Remote push and publication remain under explicit user control.

## Evidence

- Specification 0009 and ADRs 0015 and 0016 define the accepted SMB/AD
    authority, transport, schema, and safety boundaries.
- Five local SMB-share commands query and mutate DACLs through the shared
    binary descriptor engine. Targets must resolve through the local SMB
    provider topology; native writes preserve share descriptions.
- Five Active Directory commands query and mutate object DACLs through direct
    LDAP v3 to an explicit FQDN domain controller with Kerberos authentication,
    signing, sealing, referrals disabled, and bounded timeouts.
- Active Directory writes prevalidate every target before dispatch. Allowed-OU
    containment, immutable object GUIDs, excluded naming contexts, protected
    targets, and DACL-only LDAP controls fail closed.
- The source and generated manifests export exactly 82 functions.
- Delegated live acceptance passes 4 of 4 SMB scenarios, 5 of 5 Active
    Directory scenarios in PowerShell 7, and 5 of 5 Active Directory scenarios
    in Windows PowerShell 5.1. No Domain Admin credential is required.
- Complete repository QA passes 509 tests with zero failures or skips.
- The configured Sampler profile executes 903 tests: 900 pass and the three
    existing local-impersonation cases fail because this domain controller
    denies interactive logon to ordinary disposable accounts. All enterprise
    tests pass, and coverage is 81.44 percent over the 80 percent threshold.
- All 51 changed PowerShell files parse in PowerShell 7 and Windows PowerShell
    5.1 with zero PSScriptAnalyzer warnings or errors. Markdown/XML diagnostics,
    whitespace checks, and retained lab-identifier/private-key scans are clean.
- The local validation package `WindowsAccessControl.0.0.1.nupkg` contains the
    eight expected entries, exports 82 functions, and contains no source tree,
    tests, lab identifiers, or private-key markers.
- Independent security re-review returned APPROVE with no unresolved Blocker
    or Major findings.

## Next step

Review or push the local commit only on explicit request. Task Scheduler and
certificate private-key adapters remain separate enterprise work packages. A
second writable domain controller is still required before claiming Active
Directory replication or failover evidence.
