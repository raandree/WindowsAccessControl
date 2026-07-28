# Use local Task Scheduler and software-key authority

- Status: Accepted
- Date: 2026-07-28
- Deciders: user, software-engineer agent

## Context and problem statement

Task Scheduler objects and certificate private keys are persistent local
authorization surfaces with remote-capable management APIs. Their first module
increment needs a boundary that can be proven in the existing disposable member
server without creating a second-hop credential, transport-downgrade, private-
key export, or system-task lockout risk.

## Decision

- Implement the first Task Scheduler and software-key increments as local-on-
    target, DACL-only adapters.
- Expose no server, computer, session, credential, or direct remote parameter.
    A caller managing another computer establishes an independently approved
    secure session and runs the local command there.
- Limit Task Scheduler writes to marked disposable folders and tasks outside
    the `\Microsoft` tree. Reject built-in and unmarked system targets.
- Limit private-key writes to software-backed CNG or CAPI keys whose provider
    exposes a mutable descriptor and whose stable provider/container identity
    is available. Never export or serialize key material.
- Reject hardware, smart-card, TPM, remote, ambiguous, missing, and known
    critical-service key bindings in the first increment.
- Keep SACL, owner/group, backup/restore, DSC, and direct remote APIs outside
    each first increment.
- Require `ShouldProcess`, section preservation, exact rollback, native handle
    cleanup, cross-edition evidence, and no unresolved Blocker or Major security
    findings before either family is declared shipped.

## Authority and threat matrix

| Family | Read authority | Write authority | Outbound channel | First-increment containment |
| --- | --- | --- | --- | --- |
| Task Scheduler | Local token with descriptor-read access | Local token with `WRITE_DAC` through the Task Scheduler service | None in the adapter | Marked disposable target; reject `\Microsoft` and unmarked system targets |
| Software private key | Local token with key-open and descriptor-read access | Local token with provider-specific DACL write access | None in the adapter | Stable provider/container identity; software providers only; reject critical bindings |

Descriptor bytes, SIDs, provider names, and container identifiers are treated
as administrative data. Task XML is not executed by the adapter. Private-key
bytes are never requested. The adapters emit no arbitrary outbound request and
do not accept content as code.

## Consequences

- The existing member server can prove ordinary DACL behavior without changing
    its role or adding a direct remote public API.
- PowerShell remoting policy remains an orchestration concern; tests select
    explicit Kerberos and never Basic or CredSSP.
- Later SACL, portability, DSC, or direct remote behavior requires a focused
    follow-up contract rather than widening the first increment implicitly.

## Alternatives considered

- Implement direct remote APIs now: rejected because the server baseline still
    exposes prohibited downgrade choices and no public credential contract is
    accepted.
- Require the complete family roadmap before shipping DACL management:
    rejected because a local DACL-only increment is coherent, independently
    testable, and useful.
- Treat certificates as the protected object: rejected because the permission
    target is the provider-backed private key, while a certificate is only one
    selector for it.

## See also

- [Enterprise expansion](../0008-enterprise-access-control-expansion.md)
- [Domain lab inventory](../../docs/domain-lab-inventory.md)
- [Enterprise staging decision](0014-stage-enterprise-expansion-behind-domain-lab.md)
