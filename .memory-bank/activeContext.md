---
status: current
last-verified: 2026-07-30
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

Two open issues closed. The registry family now treats inheritance scope as ACE
identity when adding a rule, and the Active Directory family gained set,
rights-removal, account-purge, and clear semantics behind a fail-closed
manageability gate and a write-boundary staleness check.

## Evidence

- OI-25: `Add-RegistryKeyAccessRule` and `Add-RegistryKeyAuditRule` opt into
    `Invoke-WindowsAclRuleMutation -MatchAceFlags` on both the descriptor-staging
    and path-write paths. `Set` and `Clear` are deliberately unchanged, recorded
    in specification 0003.
- OI-16: `Set-ADObjectAccessRule` and `Clear-ADObjectAccessRule` are new exports,
    and `Remove-ADObjectAccessRule` gained a distinguished-name parameter set
    with `Exact`, `Rights`, and `All` modes. Every mode matches on account,
    qualifier, and both object GUIDs, so an object ACE is never flattened.
- Rights removal expands a stored native `GENERIC_*` bit to the rights it
    confers before subtracting, so revoking a specific right cannot leave the
    generic grant standing.
- Two independent security reviews ran. The first returned REQUEST CHANGES with
    four Major findings; all four plus every Minor and Nit were fixed. The
    re-review returned APPROVE WITH COMMENTS, and its six follow-up Minor/Nit
    findings were also fixed.
- The live domain lab passes 10 of 10 Active Directory acceptance scenarios,
    including the manageability gate and the staleness rejection, both bounded to
    a disposable child organizational unit.

## Next step

Review or push the local changes only on explicit request. Seven focused issues
remain: OI-14, OI-17, OI-18, and OI-20 through OI-24. OI-18 remains externally
blocked until a second writable domain controller exists; do not repurpose the
member server that hosts SMB, Task Scheduler, and software-key fixtures.
