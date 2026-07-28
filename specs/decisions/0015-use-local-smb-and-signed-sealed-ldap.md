# Use local SMB and signed and sealed LDAP authority

- Status: Accepted
- Date: 2026-07-28
- Deciders: user, software-engineer agent

## Context and problem statement

SMB-share and Active Directory DACLs are remote-capable Windows authorization
surfaces, but the current module deliberately rejects implicit remote targets.
The first enterprise commands need an authority model that cannot silently
fall back to NTLM, plaintext credentials, CredSSP, or an unintended server.

## Decision

- Execute SMB share commands only on the target computer through the local
  `SE_LMSHARE` descriptor API. Reject UNC and server-qualified public input.
- Require an explicit domain-controller `Server` on every AD command.
- Bind directly with LDAP v3 Kerberos authentication, signing, sealing, no
  referral chasing, and a bounded timeout.
- Permit an optional explicit credential only for direct binding to the final
  DC. Never forward it through a member server or expose it in output.
- Reject IP literals, URLs, local aliases, protected directory targets, targets
  outside the default domain partition, and mutations outside an explicit
  allowed OU.
- Revalidate AD `objectGUID` immediately before every write.
- Keep SACL, remote SMB APIs, CredSSP, unconstrained delegation, and NTLM
  fallback outside this increment.

## Consequences

- SMB commands compose with approved PowerShell remoting without adding remote
  syntax to the object adapter.
- AD operations identify their authority and consistency point explicitly.
- Current-identity and explicit-credential AD calls share one secure transport
  implementation.
- Cross-DC replication behavior remains blocked until a second writable DC is
  available.

## Alternatives considered

- Accept UNC share targets: rejected because remote authentication and
  downgrade behavior would become public contract without channel evidence.
- Use ActiveDirectory module cmdlets for descriptor writes: rejected because
  server, referral, and channel behavior is less explicit than a dedicated
  LDAP protocol connection.
- Use simple bind over TLS: rejected for this increment because it adds
  certificate-name and trust-chain configuration not yet proven by the lab.
- Use CredSSP: rejected because direct DC authentication removes the second hop.

## See also

- [SMB share and Active Directory DACL management](../0009-smb-share-and-active-directory-dacl-management.md)
- [Enterprise staging decision](0014-stage-enterprise-expansion-behind-domain-lab.md)
