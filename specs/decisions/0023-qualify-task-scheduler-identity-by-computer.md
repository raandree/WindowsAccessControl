# Qualify Task Scheduler identity by computer and use schema version 2

- Status: Accepted
- Date: 2026-07-30
- Deciders: user, software-engineer agent

## Context and problem statement

ADR 0016 limits backup schema version 1 to local object families identified by
local canonical target metadata, and reserves version 2 for records that carry
explicit server authority. Task Scheduler targets are local by ADR 0018, but
their canonical identity was `TaskFolder:Local:<PATH>`, which names no machine.
A portability record built from that identity could be replayed against a
different computer's task store, and evidence would not name the machine that
produced it.

Adding the owning computer to the record requires deciding whether the two Task
Scheduler families join schema version 1 as local targets or version 2 as
records that bind explicit authority.

## Decision

- Qualify Task Scheduler canonical identity by the owning computer:
  `TaskFolder:<COMPUTER>:<PATH>` and `ScheduledTask:<COMPUTER>:<PATH>`. The
  resolved target also reports `Server`.
- Keep the root task folder unsupported for both families, so a task path always
  names a real subfolder and a registered-task record that would split to the
  root is rejected during restore validation.
- Encode both families as schema-version-2 records, so a version-1 reader can
  never interpret them and a family/version mismatch is rejected in both
  directions.
- Reuse the existing version-2 `Server` field and store the absolute task path
  in `Target`. Add no new hashed field, so every existing version-1 and
  version-2 backup keeps validating.
- Require `AllowedRootPath` on `Restore-WindowsSecurityDescriptor` and on every
  Task Scheduler DSC resource, and resolve every target for write during
  preparation.

## Consequences

- A Task Scheduler backup cannot be replayed on another computer, and the
  containment boundary is stated by the caller rather than inferred.
- The canonical target change also changes the process-wide write lock key and
  metric identity for the two families. The module is unpublished, so no
  released consumer depends on the previous `Local` form.
- Task Scheduler records participate in the same envelope, digest, signature,
  duplicate, and prevalidation rules as the other families without a
  family-specific schema.

## Alternatives considered

- Keep `Local` and add an unhashed server field: rejected because an
  unauthenticated field cannot bind authority.
- Add `TaskPath` and `TaskName` as new hashed version-2 fields: rejected
  because it would change the digest of every existing version-2 record while
  adding nothing that `Target` and the canonical target do not already carry.
- Encode Task Scheduler as schema version 1: rejected because version 1 records
  carry no server authority, which is exactly what the replay boundary needs.

## See also

- [Task Scheduler portability and desired state](../0014-task-scheduler-portability-and-desired-state.md)
- [Require backup schema version 2 for enterprise targets](0016-require-schema-v2-for-enterprise-targets.md)
- [Use local Task Scheduler and software-key authority](0018-use-local-task-and-software-key-authority.md)
