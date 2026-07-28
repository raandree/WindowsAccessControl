# Defer remote and combined effective access

- Status: Accepted
- Date: 2026-07-28
- Deciders: user, software-engineer agent

## Context and problem statement

The existing NTFS effective-access command evaluates a security descriptor
through a SID-derived local Authz context. It does not have a remote logon token,
the target server's group expansion, SMB share policy, or the target resource
manager's authorization state. Presenting that result as remote or combined
SMB-plus-NTFS access would overstate what Windows actually evaluated.

## Decision

- Keep `Get-NTFSItemEffectiveAccess` limited to local filesystem targets and a
    SID-derived Authz result.
- Reject standard and extended UNC targets before reading their descriptors.
- Do not add a remote resource-manager mode, direct remote effective-access
    API, or combined SMB-plus-NTFS result in the current roadmap.
- Keep share and NTFS descriptor management as separate authorization layers.
- Require a new accepted security design and executable server-side token
    evidence before any future remote or combined claim is admitted.

## Consequences

- OI-4 closes as an explicit deferral rather than an incomplete implementation.
- Local effective-access output remains backward compatible for local paths.
- Callers cannot accidentally treat a descriptor read over UNC as a target-
    server authorization result.
- SMB share management can ship independently without an effective-access
    claim.

## Alternatives considered

- Evaluate a UNC descriptor with the caller's local SID context: rejected
    because local group expansion and logon groups do not model the server.
- Add an on-target evaluator now: rejected because the approved first
    enterprise increments use local-on-target object APIs and no secure remote
    evaluator contract exists.
- Intersect share and NTFS masks client-side: rejected because Windows access
    checks include token, deny, privilege, and server policy semantics that a
    mask intersection does not reproduce.

## See also

- [Security and persistence](../0004-security-and-persistence.md)
- [Enterprise expansion](../0008-enterprise-access-control-expansion.md)
