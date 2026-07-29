# Report null registry provenance instead of losing rules

- Status: Accepted
- Date: 2026-07-29
- Deciders: user, software-engineer agent

## Context and problem statement

`Get-RegistryKeyAccessRule` reported `IsInherited` without naming the ancestor
key an ACE came from, while `Get-NTFSAccessRule` already exposed
`InheritedFrom` through `GetInheritanceSourceW`. Extending the same API to the
registry raised two questions that the filesystem contract does not answer.

A live probe established the constraints. `GetInheritanceSourceW` succeeds with
`SE_REGISTRY_KEY` and returns ancestor names in the native hive form such as
`CURRENT_USER\Control Panel`. It fails with `ERROR_INVALID_PARAMETER` (87) for
`SE_REGISTRY_WOW64_32KEY` and `SE_REGISTRY_WOW64_64KEY`, even though
`GetNamedSecurityInfoW` accepts both for the same key. Passing
`SE_REGISTRY_KEY` for a view-specific target does succeed, but it walks the
process-native view and would confidently report an ancestor from the wrong
view.

The call also re-opens the target and its ancestor chain after the descriptor
has already been read. A key that is deleted, renamed, or protected between the
two reads, or an ancestor the caller cannot open, makes the lookup fail after
the requested data is already in hand.

## Decision

- Resolve registry provenance only with `SE_REGISTRY_KEY`, and report a null
    source for the `Registry32` and `Registry64` views.
- Enforce the object type in the native entry point as well as in the calling
    PowerShell helper, so the guarantee does not depend on one call site.
- Translate ancestor names to provider form, and report a native form that is
    not a supported local hive as no source rather than as an unopenable path.
- Degrade to a null source with a non-terminating error when the lookup fails
    or returns a row count that does not match the ACL, instead of terminating
    the target as the filesystem path does.
- Never infer a source by comparing an ACE with rules on parent keys.

## Consequences

- A caller reading a 32-bit or 64-bit view sees `InheritedFrom` empty. That is
    the already-defined "Windows cannot identify the source" state, so no new
    output contract is introduced.
- `Get-RegistryKeyAccessRule` keeps the availability it had before provenance
    existed. An enrichment failure costs the column, not the rules.
- Registry and filesystem provenance now differ in failure handling. The
    asymmetry is deliberate: a registry ancestor chain commonly crosses keys a
    caller cannot read, which is not typical of a filesystem parent chain.
- A successful lookup is still resolved against the live ancestor chain rather
    than the descriptor snapshot, so a concurrent ancestor change can return a
    source that no longer matches the reported ACE.
- Registry rules cost one extra native call per target when inherited rules are
    requested. `-ExcludeInherited` skips it entirely.

## Alternatives considered

- Resolve `Registry32` and `Registry64` with `SE_REGISTRY_KEY`: rejected
    because it returns a plausible ancestor from the wrong view, and a wrong
    provenance claim is worse than none in an access-control tool.
- Translate a view-specific path to its physical redirected path: rejected
    because registry redirection rules are subtree specific and version
    dependent, so the module would be reimplementing an undocumented mapping.
- Terminate the target on a lookup failure, matching the filesystem path:
    rejected because it converts a working read-only inspection command into a
    failure for the sake of an optional column.
- Suppress the failure silently: rejected because a caller cannot then tell an
    unresolvable source from an unattempted one.
