---
status: current
last-verified: 2026-07-29
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

Active Directory access rules now report where an inherited ACE came from and
what its object GUIDs mean, and `Server` is optional across the directory
commands. Provenance and schema names are resolved over the same signed and
sealed connection that returned the descriptor, and a discovered writable domain
controller is resolved once per invocation and pinned for every target.

## Evidence

- A live probe established both constraints. `GetInheritanceSourceW` does work
    with `SE_DS_OBJECT` and returned `DC=contoso,DC=com` for every inherited ACE
    of the lab user, but it rejects a server-qualified object name and locates
    its own domain controller, so it cannot honor `Server` or `Credential`.
- The LDAP ancestor-walk inference agrees with that native oracle: 26 of 26
    inherited ACEs resolve to `DC=contoso,DC=com` in both PowerShell editions.
- Schema and extended-right lookups resolve the reported GUIDs to
    `Account Restrictions`, `inetOrgPerson`, `user`, `Logon Information`, and
    `Group Membership`.
- ADR 0020 records the enrichment decision, ADR 0021 the discovery decision;
    specifications 0002, 0003, 0005, and 0009 record the expanded contract.
- Independent security review returned APPROVE WITH COMMENTS with no Blocker and
    one Major finding. The Major finding and three fail-open Minor findings were
    fixed and covered by regression tests.
- `tests/Unit` plus `tests/QA` pass 1022 of 1022 with the module built from
    source, and the same paths work under Windows PowerShell 5.1.

## Next step

Review or push the local commits only on explicit request. Ten focused issues
remain: OI-14, OI-16 through OI-18, OI-20, and OI-22 through OI-25, plus the
elevation-dependent failures that predate this work. OI-18 remains externally
blocked until a second writable domain controller exists; do not repurpose the
member server that hosts SMB, Task Scheduler, and software-key fixtures.
