# Discover and pin one domain controller when Server is omitted

- Status: Accepted
- Date: 2026-07-29
- Deciders: user, software-engineer agent

This decision supersedes only the "require an explicit domain-controller
`Server` on every AD command" element of ADR 0015. Every other constraint in
ADR 0015 remains in force.

## Context and problem statement

ADR 0015 made `Server` mandatory on every Active Directory command so that no
operation could silently target an unintended domain controller. In practice
the requirement forces every caller, including a simple read on the computer's
own domain, to name a domain controller that the Windows DC locator already
knows. Callers work around it by calling the locator themselves, which produces
the same implicit choice without the module's validation.

The real requirement is not that a human types the name. It is that one command
uses exactly one identified consistency point and that the choice is visible.

## Decision

- Make `Server` optional on `Get-ADObjectAccessRule`,
    `Get-ADObjectSecurityDescriptor`, `Add-ADObjectAccessRule`, and
    `Set-ADObjectSecurityDescriptor`.
- When `Server` is supplied, keep the existing validation unchanged: an explicit
    DNS domain-controller name only, with IP literals, URLs, local aliases, and
    remote syntax rejected.
- When `Server` is omitted, locate one writable domain controller in the
    calling computer's domain through `System.DirectoryServices.ActiveDirectory`
    with `LocatorOptions.WriteableRequired`, then validate the returned name
    through the same explicit-name rules.
- Resolve the name once per invocation, before target prevalidation, and pin it
    into the dispatched parameters so every target, batch worker, and follow-up
    read in that invocation uses the same domain controller.
- Write the discovered name to the verbose stream, and emit it on every result
    through the existing `Server` property and canonical target.
- Fail with an actionable error that names the `Server` parameter when discovery
    fails.
- Keep discovery scoped to the computer's domain. Discovery does not use
    `Credential`, and it does not search another domain or forest.

## Consequences

- Everyday reads no longer require a domain-controller name, while every result
    still records which domain controller answered.
- The consistency point is still singular: one invocation cannot span two
    domain controllers, because discovery happens once and is pinned.
- A caller that supplies `Credential` for another domain without `Server` binds
    that credential to the local domain's controller. The existing default
    naming context check then rejects a distinguished name from another domain,
    so the mismatch fails clearly instead of reading the wrong object.
- Automation that must not depend on the locator keeps full control by passing
    `Server` explicitly.
- `Remove-ADObjectAccessRule` is unaffected. It continues to take the server
    from the path-bound rule it removes.

## Alternatives considered

- Keep `Server` mandatory: rejected because it moves the same implicit locator
    call into caller scripts, where it is neither validated nor pinned.
- Discover per target instead of per invocation: rejected because a batch could
    then split across domain controllers and observe different replicas.
- Accept a domain name and locate inside it: rejected for this increment because
    cross-domain and cross-forest targets are still outside the accepted
    boundary.
- Use `DsGetDcName` interop: rejected because the managed locator is available
    in both supported PowerShell editions and adds no native surface.

## See also

- [SMB share and Active Directory DACL management](../0009-smb-share-and-active-directory-dacl-management.md)
- [Enterprise authority decision](0015-use-local-smb-and-signed-sealed-ldap.md)
- [Directory rule enrichment decision](0020-enrich-directory-rules-over-the-bound-connection.md)
