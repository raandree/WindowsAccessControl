# Active Directory multi-controller behavior

Status: Accepted. This specification records the multi-controller identity,
replication, and pinned-controller outage behavior that specification 0009 left
open, and closes open issue OI-18 for tasks `AD-3` and `AD-6`.

## Scope

The increment adds no command, parameter, or output property. It states and
verifies behavior that already follows from ADR 0021 (discover and pin one
domain controller) and from binding a directory target by its immutable
`objectGUID`.

Read-only domain controllers, inter-site replication scheduling, and forest-wide
partitions other than the default domain naming context remain outside this
contract.

## Controller pinning

Every command pins exactly one domain controller for its whole invocation. Two
consequences are normative.

- The canonical target carries the pinned server, so the same directory object
  read through two controllers yields the same `ObjectGuid` and the same DACL
  but two different canonical targets. The canonical target is
  `ADObject:<SERVER>:<OBJECTGUID>` in uppercase.
- A pinned controller that cannot serve the request produces a terminating
  error. The command never falls back to another controller, because a silent
  switch would break the read-compare-write pairing that the staleness check and
  the object-GUID pin depend on. Choosing a different controller is the caller's
  decision, expressed through `Server`.

## Replication

A DACL change is a normal directory write and converges through ordinary
replication. The contract does not add a wait, a poll, or a convergence check,
and does not promise read-your-write consistency across controllers.

A caller that must observe a change on a specific controller either pins that
controller for the write or forces replication with the in-box tooling. The live
suite uses `Sync-ADObject` so convergence is asserted deterministically rather
than by waiting for the replication interval.

## Concurrent writers

A security descriptor is one directory attribute. Two controllers written from
the same base therefore do not merge: replication settles the conflict by
attribute version, then originating time, then originating controller, and the
losing write is discarded whole rather than entry by entry. Measured in the lab,
two access control entries added through the two writable controllers from one
baseline read leave exactly one of them once both controllers agree.

No Active Directory command offers `RequireUnchanged`. That gate belongs to the
file-system and registry families of specification 0003, where the read and the
write address the same local object; across two controllers it would narrow
nothing that pinning does not already narrow. A directory caller compares
`ConcurrencyToken` itself. The token is a hash of the sections that were read,
so a converged descriptor reports the same token through either controller, an
unchanged descriptor reports a stable token, and a write made through the other
controller changes it.

Serializing the writes through one pinned controller is the only mechanism that
keeps both edits, because a read-modify-write on that controller observes the
previous one. Same-target write serialization is keyed on the canonical target,
and the canonical target carries the pinned server, so two writes that differ
only by server are deliberately not serialized against each other.

## Immutable identity

A directory object is identified by `objectGUID`, which survives a rename and a
move. Three behaviors follow.

- After a rename or a move, the new distinguished name resolves to the same
  `ObjectGuid` and the same canonical target.
- The previous distinguished name no longer resolves, and the read fails rather
  than returning an empty result.
- A portability record binds `objectGUID` in addition to the distinguished name.
  When a distinguished name is reused by a different object, restore is rejected
  because the recorded GUID no longer matches. This is the property that stops a
  backup from being replayed onto an unrelated object that merely inherited its
  name.

## Verification

[ADObjectReplication.Live.Tests.ps1](../tests/Lab/ADObjectReplication.Live.Tests.ps1)
requires two writable domain controllers in the fixture domain and fails its
`BeforeAll` when fewer exist, so the suite can never pass by silently degrading
to a single controller.

| Behavior | Evidence |
| --- | --- |
| Controller pinning | The same object read through two controllers reports one `ObjectGuid`, one DACL, and two canonical targets that differ only by server |
| Replication convergence | A rule added on the primary and replicated is visible on the partner, and its removal on the partner is visible on the primary after replication back |
| Concurrency token | One converged descriptor reports one token through both controllers, an unchanged descriptor reports a stable token, and a write on the other controller changes it |
| Concurrent writers | Two edits written from one baseline through the two controllers converge to exactly one surviving edit, and the stale write is accepted rather than refused |
| Serialized writers | Two edits written through one pinned controller both survive |
| Rename and move | `ObjectGuid` and canonical target are unchanged, and the previous distinguished name fails to resolve |
| Distinguished-name reuse | A restore of a record whose distinguished name was recreated as a different object is rejected |
| Deleted object | A read of a deleted object fails instead of returning an empty result |
| Pinned-controller outage | With the partner's directory service stopped, a pinned read and a pinned write both fail with an LDAP-unavailable error while the surviving controller still serves the object |
| Recovery | The suite restarts the directory service and every dependent service it stopped, verifies the partner serves the object again, and fails its `AfterAll` if it does not |

The outage test stops a real directory service, so recovery is part of the
assertion rather than a cleanup detail. Decision 71 makes a throwing `AfterAll`
report the suite as failed, which is what prevents a half-recovered lab from
being reported green.

## See also

- [SMB share and Active Directory DACL management](0009-smb-share-and-active-directory-dacl-management.md)
- [Enterprise portability and desired state](0013-enterprise-portability-and-desired-state.md)
- [Discover and pin one domain controller](decisions/0021-discover-and-pin-a-domain-controller.md)
- [Enterprise access-control expansion](0008-enterprise-access-control-expansion.md)
