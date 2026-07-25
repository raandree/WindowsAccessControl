# NTFS permission module research

This note records the web research completed on 2026-07-25 before the module
API was designed. It separates verified platform behavior from project design
choices.

## Existing module landscape

The established
[NTFSSecurity module](https://github.com/raandree/NTFSSecurity) demonstrates the
need for ACE-level, pipeline-first commands. PowerShell Gallery lists version
4.2.6 as published on 2019-07-12. Its repository uses AlphaFS-era components
and has not shipped a newer gallery release.

[AlphaFS](https://github.com/alphaleonis/AlphaFS) was archived on 2024-12-06
and labels itself unmaintained. The latest listed release is 2.2.6. Depending
on it would inherit an archived runtime dependency primarily used for legacy
long-path and advanced file-system support.

[PowerShellAccessControl](https://github.com/rohnedwards/PowerShellAccessControl)
has a broad securable-object scope, but its repository has been inactive for
many years and references the retired TechNet Gallery for its compiled version.

The design therefore uses no third-party runtime dependency. Runtime behavior
is based on in-box Windows security types, supported PowerShell security
commands for descriptor reads, and narrow Win32 interop where no managed API
exists.

## Detailed NTFSSecurity comparison

A follow-up source review used the upstream
[module manifest](https://github.com/raandree/NTFSSecurity/blob/master/NTFSSecurity/NTFSSecurity.psd1)
and command implementations rather than command names alone.

The following ideas are implemented here:

- Pipeline input from paths and filesystem objects, account and inheritance
  filters, orphaned SID reporting, and opt-in `PassThru` output.
- Multi-account additions modeled on
  [`AddAccess.cs`](https://github.com/raandree/NTFSSecurity/blob/master/NTFSSecurity/AccessCmdlets/AddAccess.cs),
  with one descriptor persistence operation per target.
- Optional removal of explicit rules while enabling inheritance, modeled on
  [`EnableAccessInheritance.cs`](https://github.com/raandree/NTFSSecurity/blob/master/NTFSSecurity/InheritanceCmdlets/EnableAccessInheritance.cs).
- Structured current-token privilege inventory corresponding to upstream
  `Get-Privileges`, without enabling privileges as an import side effect.
- Access and audit parity for rule construction, query, mutation, orphaned SID
  filtering, inheritance, and selected-section descriptor portability.

The following ideas are deliberately deferred:

- Inherited-source provenance requires the Windows inheritance-source API for
  unambiguous results. Guessing by comparing parent ACEs can report the wrong
  ancestor when identical rules exist at multiple levels.
- Remote effective-access evaluation changes RPC, trust, and authorization
  boundaries. The current Authz result is explicitly local and SID based.
- In-memory descriptor mutation would create a second persistence model beside
  the path-bound commands. It needs a separate contract rather than hidden
  write-through behavior.
- A simplified access view is lossy because composite rights, deny rules, and
  inheritance scopes cannot always be collapsed without changing meaning.

The following upstream behavior is rejected for this module:

- AlphaFS-backed `Item2`, link, disk-space, and hash commands are general
  filesystem utilities rather than permission management.
- Automatically enabling backup, restore, take-ownership, and security
  privileges is broader than the requested operation and obscures token state.
- Temporarily changing ownership after an authorization failure mutates an
  additional security boundary and creates restoration failure modes.

## Verified access-rule semantics

The .NET
[`CommonObjectSecurity`](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.commonobjectsecurity)
methods have materially different behavior:

- `AddAccessRule` adds or combines a rule; rights accumulate.
- `SetAccessRule` removes rules with the same SID and allow or deny qualifier,
  then adds the replacement.
- `ResetAccessRule` removes every DACL rule before adding one rule.
- `RemoveAccessRule` subtracts matching rights and can split an ACE.
- `RemoveAccessRuleSpecific` removes exact matches.
- `RemoveAccessRuleAll` removes every rule for a SID.

Because `ResetAccessRule` can destroy unrelated access, it is not exposed as a
routine public rule operation. Removal modes are explicit instead.

Windows automatically adds
[`Synchronize`](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights)
to allowed filesystem rules in some rights combinations. The module reports
the persisted native mask rather than hiding that behavior.

## Inheritance and descriptor sections

[`SetAccessRuleProtection`](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.objectsecurity.setaccessruleprotection)
uses two Boolean arguments. Enabling protection disables inheritance. When
protection is enabled, preserving inherited rules converts them to explicit
rules; not preserving them removes those inherited entries.

The module therefore preserves inherited rules by default when disabling
inheritance.

Microsoft recommends passing identical section sets when loading and
[`persisting a security descriptor`](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.objectsecurity.persist).
Testing also showed that `Set-Acl` could request `SeSecurityPrivilege` while
re-enabling a DACL after inheritance was protected. The implementation uses the
runtime-appropriate filesystem access-control persistence API so only modified
sections are written.

## ACE order

The Windows
[preferred DACL order](https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl)
places explicit ACEs before inherited ACEs, deny before allow within each
level, and inherited entries in inheritance order. `Test-NTFSItemAcl` exposes
the managed canonical-order checks without attempting a potentially destructive
automatic rewrite.

## SACL privileges

Microsoft's
[privilege constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
define the relevant token rights:

- `SeSecurityPrivilege` controls and views audit information.
- `SeBackupPrivilege` grants backup-oriented read access.
- `SeRestorePrivilege` grants restore-oriented writes and can set any valid SID
  as owner.
- `SeTakeOwnershipPrivilege` permits taking ownership without discretionary
  access.

[`AdjustTokenPrivileges`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges)
cannot add privileges to a token. It can only enable or disable existing ones,
and a successful API return can still report `ERROR_NOT_ALL_ASSIGNED`. The
module checks that error explicitly.

## Effective access

There is no managed filesystem effective-access API. The older
[`GetEffectiveRightsFromAcl`](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-geteffectiverightsfromaclw)
omits owner rights, privileges, logon-session groups, and resource-manager
policy, and it fails on inherited deny ACEs.

The module instead uses
[`AuthzInitializeContextFromSid`](https://learn.microsoft.com/en-us/windows/win32/api/authz/nf-authz-authzinitializecontextfromsid)
and
[`AuthzAccessCheck`](https://learn.microsoft.com/en-us/windows/win32/api/authz/nf-authz-authzaccesscheck)
with `MAXIMUM_ALLOWED`. A SID-derived context can still omit logon-specific
groups and is less complete than a context built from a live token. The command
documents and returns that bounded NTFS result; share permissions are outside
scope.

## Paths and platform

Microsoft documents the extended path prefixes and constraints in
[Maximum Path Length Limitation](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation).
The module accepts literal `\\?\` and `\\?\UNC\` paths supported by the host
runtime. It does not add an AlphaFS compatibility layer.

The underlying ACL APIs and PowerShell
[`Get-Acl`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl)
and
[`Set-Acl`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl)
commands are Windows-specific. The built module fails clearly during import on
another platform instead of implying cross-platform ACL support.

## Scope decision

Version 0.1 covers files and directories:

- DACL and SACL rule construction, query, add, replace, remove, and clear
- owner and access or audit inheritance
- identity and orphaned-SID handling
- selected-section descriptor get, copy, JSON backup, and restore
- canonical-order diagnostics
- Authz effective access
- process token privilege inventory, query, enable, and disable

Registry, service, printer, process, share-level, POSIX, Central Access Policy,
and operating-system audit policy management are deliberately outside scope.
