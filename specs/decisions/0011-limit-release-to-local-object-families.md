# Limit the release to local object families

- Status: Accepted
- Date: 2026-07-25
- Deciders: user, software-engineer agent

## Context and problem statement

Windows exposes security descriptors for many named and unnamed object types.
Native remote APIs add credentials, impersonation, RPC, trust, availability,
and rollback boundaries. Several securable objects are ephemeral or already
have strong in-box management commands.

## Decision

- Ship local NTFS files/directories, registry keys, named services, the Service
  Control Manager, and live processes.
- Treat registry values as rights on their containing key because values have no
  independent descriptor.
- Support process permissions as an explicitly ephemeral imperative and DSC
  convergence surface tied to one pinned process instance.
- Defer scheduled tasks, printers, WMI namespaces, SMB shares, event-log
  channels, and certificate private keys to separate specifications.
- Exclude Active Directory, COM/AppID, JEA endpoints, window stations/desktops,
  and named synchronization objects from this release.
- Do not expose native remote target syntax or `ComputerName` parameters.
- Limit explicit credentials to local impersonation.

## Consequences

- The release has a testable trust boundary and disposable local fixtures.
- Registry and service APIs may be technically remote-capable, but public target
  validation rejects remote syntax.
- Process desired state ends when the pinned process instance exits.
- Future object families can reuse the shared engine without silently expanding
  this release's security boundary.

## Alternatives considered

- Implement every `SE_OBJECT_TYPE`: rejected because lifetime, inheritance,
  safety, and operational value differ substantially.
- Include native remote APIs now: rejected by the signed local-only and remote
  non-goal decisions.
- Exclude processes as ephemeral: rejected because process permissions are an
  explicit user requirement; the limitation is made visible instead.

## See also

- [Expansion object-type decision](../0006-windows-access-control-expansion.md#additional-object-type-decision)
