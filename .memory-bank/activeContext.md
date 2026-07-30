---
status: current
last-verified: 2026-07-30
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

Two more open issues closed. The SMB share and Active Directory families now
have schema-version-2 descriptor portability, server-qualified SMB canonical
identity, and four object-specific DSC resources. Active Directory effective
access is deferred on measured evidence.

## Evidence

- OI-14: `Resolve-WindowsSmbShareTarget` emits `Server` and
    `SmbShare:<SERVER>:<SHARE>`; share backups are record version 2 and restore
    only on the computer they name.
- OI-17: directory backups are record version 2, bind server plus immutable
    `objectGUID` and domain naming context, and restore through one pinned
    writable domain controller inside an explicit allowed organizational unit.
    ADR 0022 defers directory effective access.
- Record version is a property of the object family, so an enterprise record
    cannot be replayed as a local target and a local record cannot claim server
    authority. The pinned version-1 digest test proves existing local backups
    still validate.
- Four new DSC resources ship: SMB share and directory descriptors plus their
    access-rule presence resources. Directory resources require an allowed base,
    take no credential, and re-assert an optional `ObjectGuid` before the write.
- One independent security review returned three Major findings (server-scoped
    directory deduplication, an unprevalidated directory write boundary, and an
    object-GUID pin enforced only on the read path). All three plus every Minor
    were fixed and covered by new tests.
- The live domain lab passes 29 of 29 acceptance tests across all five suites
    with zero skips and both boundaries ready.

## Next step

Review or push the local changes only on explicit request. Five focused issues
remain: OI-18 and OI-20 through OI-24. OI-18 remains externally blocked until a
second writable domain controller exists; do not repurpose the member server
that hosts SMB, Task Scheduler, and software-key fixtures.
