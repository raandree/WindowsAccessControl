# Use only in-box runtime security APIs

- Status: Accepted
- Date: 2026-07-25
- Deciders: user, software-engineer agent

## Context and problem statement

Existing NTFS modules demonstrate useful ergonomics but depend on AlphaFS-era
or other dormant runtime components. The module must support two PowerShell
editions without inheriting an archived filesystem abstraction.

## Decision

Use `Microsoft.PowerShell.Security`, `System.Security.AccessControl`, and
narrow Windows interop only where no managed equivalent exists:

- token privilege query and adjustment
- Authz effective-access evaluation

Do not take a runtime dependency on AlphaFS, ProcessPrivileges, or another
third-party ACL engine.

## Consequences

- Installation has no third-party runtime dependency.
- Windows PowerShell 5.1 and PowerShell 7 use their appropriate in-box
  persistence APIs.
- Advanced non-permission filesystem commands are outside module scope.
- Native interop requires explicit memory, handle, and architecture review.

## Alternatives considered

- Depend on NTFSSecurity/AlphaFS: rejected because AlphaFS is archived and the
  broader command surface is outside scope.
- Implement all access logic with ad hoc P/Invoke: rejected because managed
  security types already model ACL rules and descriptors correctly.

## See also

- [Security and persistence](../0004-security-and-persistence.md)
- [Research sources](../../docs/research.md)
