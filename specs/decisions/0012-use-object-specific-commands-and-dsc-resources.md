# Use object-specific commands and DSC resources

- Status: Accepted
- Date: 2026-07-25
- Deciders: user, software-engineer agent

## Context and problem statement

A single generic command could expose the shared descriptor engine, but it would
hide object-specific rights, target validation, inheritance capability, and help.
Callers should use cmdlets and enums rather than constructing module classes.
DSC must support both exact descriptor ownership and individual rule presence.

## Decision

- Export object-specific NTFS, registry-key, service/SCM, and process command
  families over private shared helpers.
- Align safe command concepts, parameter aliases, SID handling, pipeline input,
  and descriptor-object flow with NTFSSecurity without reproducing unsafe owner
  fallback or its public wrapper classes.
- Emit versioned `PSCustomObject` contracts with native objects available as
  properties; expose only enums as direct non-DSC caller types.
- Export two class-based DSC resources per object family: an exact selected-
  section descriptor resource and an individual access-rule presence resource.
- Prefix DSC resource and embedded reason class names with
  `WindowsAccessControl` to avoid global class collisions.
- Keep DSC methods thin and route behavior through independently tested module
  commands and private helpers.

## Consequences

- Help, validation, and IntelliSense expose correct rights for each domain.
- The public command count grows, but high-risk behavior remains centralized.
- DSC users can choose ownership of a complete selected descriptor or additive
  rule convergence without deleting unrelated ACEs.
- DSC resource classes are necessarily discoverable; other helper classes remain
  private implementation details.

## Alternatives considered

- One `ObjectType` command family: rejected because it weakens type safety and
  discoverability.
- Public smart wrapper classes modeled directly on NTFSSecurity: rejected by the
  caller contract; safe conversion behavior is implemented in cmdlets instead.
- Exact-descriptor DSC only: rejected because many configurations must preserve
  unrelated rules.

## See also

- [Expansion outputs](../0006-windows-access-control-expansion.md#outputs)
- [Class-based DSC resource documentation](https://learn.microsoft.com/en-us/powershell/dsc/concepts/class-based-resources)
