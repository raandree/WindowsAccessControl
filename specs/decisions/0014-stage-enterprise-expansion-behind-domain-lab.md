# Stage enterprise expansion behind a domain lab

- Status: Accepted
- Date: 2026-07-28
- Deciders: user, software-engineer agent

## Context and problem statement

The implemented object families are local and testable on disposable resources.
Scheduled tasks, certificate private keys, SMB shares, and Active Directory add
COM, cryptographic-provider, remote-server, LDAP, credential, replication, and
directory-lockout boundaries. The user will provide a domain lab so these
boundaries can be implemented and tested against real machines.

ADR 0011 remains the release boundary for existing behavior. Planning future
enterprise work must not silently enable remote syntax or weaken the current
local security contract before the lab and threat model exist.

## Decision

- Plan Task Scheduler, certificate private-key, SMB-share, and Active Directory
  support through specification 0008 and separately closable work packages.
- Promote Active Directory from excluded in the current local release to
  planned for a future release; ADR 0011 continues to govern current behavior.
- Keep current local commands and their compatibility contract unchanged.
- Block production implementation on a versioned domain-lab inventory,
  repeatable disposable setup/teardown, API probes, and per-domain threat models.
- Require a non-production lab forest with no production trust or routable path
  and an untouched recovery identity that can perform teardown after lockout.
- Require explicit server, domain-controller, credential, authentication, and
  consistency semantics before exposing any remote public API.
- Require remote channels to provide mutual authentication, integrity, and
  confidentiality; reject LDAP, SMB, or remoting security downgrade rather
  than silently retrying with weaker protection.
- Prohibit CredSSP and unconstrained delegation. Any multi-hop flow requires an
  accepted constrained-delegation or explicit per-hop credential design.
- Define required rights and privileges on the target token per descriptor
  section; unsupported remote SACL behavior fails explicitly rather than
  requiring broad administration or claiming a missing privilege.
- Preserve object-specific commands, rights, outputs, and DSC resources over
  shared private descriptor infrastructure.
- Implement Active Directory reads before writes and initially confine writes
  to a disposable organizational unit in the domain partition.
- Keep private-key material and all lab secrets out of backup records,
  repository files, logs, metrics, and tool output.
- Leave every other discussed candidate deferred until a separate scope
  decision admits it.

This decision extends the roadmap but does not supersede ADR 0011 for the
current release.

## Consequences

- The new domains have executable trust and rollback boundaries instead of
  inheriting unsafe assumptions from local object adapters.
- A missing lab role or topology leaves only the affected evidence gate blocked;
  it does not become a passing skip.
- Remote and directory work requires independent security review before release.
- Cryptographic-provider work requires its own independent security review
  before release.
- The expansion can ship in independently verified increments instead of one
  all-or-nothing change.
- Backup schema and remote effective-access behavior remain explicit design
  decisions rather than accidental extensions of schema version 1 or local
  Authz results.

## Alternatives considered

- Implement all four families before obtaining a lab: rejected because mocks
  cannot prove remote authorization, provider behavior, replication, or cleanup.
- Treat Active Directory as another named-object adapter: rejected because
  object-specific ACEs, schema GUIDs, inheritance, and replication are material
  parts of the contract.
- Wrap existing SMB, Task Scheduler, and certificate commands without unified
  descriptor behavior: rejected because it would not provide the module's
  section-preservation, explicit mutation, backup, and DSC value.
- Supersede the local-only release boundary immediately: rejected because the
  current package must remain predictable while future remote contracts are
  still Draft.

## See also

- [Enterprise access-control expansion](../0008-enterprise-access-control-expansion.md)
- [ADR 0011](0011-limit-release-to-local-object-families.md)
- [Open issues](../open-issues.md)
