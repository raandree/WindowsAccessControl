# Use a shared binary security-descriptor engine

- Status: Accepted
- Date: 2026-07-25
- Deciders: user, software-engineer agent

## Context and problem statement

Managed access-control wrappers differ by object type and PowerShell edition.
Registry keys have a managed wrapper, services do not, and processes require a
handle. The module must preserve unknown ACEs and unselected descriptor sections
without adding a runtime dependency.

## Decision

- Represent the cross-domain persistence boundary as a self-relative binary
  Windows security descriptor.
- Use Unicode `GetNamedSecurityInfoW` and `SetNamedSecurityInfoW` for local named
  registry keys and services.
- Use `GetSecurityInfo` and `SetSecurityInfo` for pinned process and caller-owned
  handles.
- Keep filesystem-specific managed APIs where they preserve the selected
  sections, with narrowly scoped native calls for control flags that the managed
  runtime drops.
- Parse and mutate descriptors with in-box `CommonSecurityDescriptor`,
  `RawSecurityDescriptor`, and ACL types while preserving unknown ACEs.
- Put target normalization, handle acquisition, section mapping, and rights
  conversion behind private object-family adapters.
- Release native buffers and module-owned handles in `finally`; never close a
  caller-owned handle.

## Consequences

- One mutation and serialization model supports all current object families in
  Windows PowerShell 5.1 and PowerShell 7.
- Object-specific rights and target semantics remain visible at public command
  boundaries.
- Native interop becomes a small, high-risk core with strong unit and live-test
  obligations.
- Section masks and null or absent ACL handling must be explicit to avoid
  granting unintended access.

## Alternatives considered

- Use `Get-Acl` and `Set-Acl` for every target: rejected because provider support
  and section behavior are inconsistent and processes are handle-only.
- Build separate engines per object family: rejected because it would duplicate
  high-risk descriptor parsing and persistence logic.
- Depend on a third-party ACL library: rejected by the runtime dependency
  constraint.

## See also

- [Expansion design](../0006-windows-access-control-expansion.md#security)
- [Selected-section persistence decision](0003-persist-only-selected-descriptor-sections.md)
