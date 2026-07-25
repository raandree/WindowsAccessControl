---
status: current
last-verified: 2026-07-25
owner: software-engineer
source: implementation and test evidence
---

# Debugging insights

## Section-scoped ACL persistence

`Set-Acl` requested `SeSecurityPrivilege` while re-enabling DACL inheritance in
a non-elevated test. Persisting through `FileSystemAclExtensions` on PowerShell
Core and the .NET Framework filesystem APIs on Windows PowerShell wrote only
the modified sections and removed that false SACL privilege dependency.

## Command collision avoidance

The installed NTFSSecurity module autoloaded `Get-NTFSOwner` and related names
during red tests. Public owner and inheritance commands therefore use the
`NTFSItem` noun, and the private persistence helper uses an `Invoke` name that
does not collide with installed commands.

## Account-wide removal

Account-wide purge does not need a filesystem rights mask. Constructing an ACE
with an unbound rights parameter fails before `ShouldProcess`; `All` mode must
purge by the resolved identity directly and capture explicit rules before the
purge only when `PassThru` is requested.

## Restore validation

Validate path, item type, section mask, SDDL, and duplicate targets for every
backup record before the first persistence call. In-memory descriptor mutation
during validation is safe; filesystem writes belong in a second loop.

## Cross-edition Pester evidence

Windows PowerShell treats native Git line-ending warnings as error records when
`ErrorActionPreference` is `Stop`. Normalize changed files according to
`.gitattributes` before QA, and set Pester `Run.Exit` to false when a caller must
inspect the returned result instead of allowing Pester to terminate the host.
Keep console output separate from explicit NUnit or JSON result artifacts when
the Desktop host buffers streams.
