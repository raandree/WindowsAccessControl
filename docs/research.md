# Windows access-control module research

This note records the web research completed on 2026-07-25 before the original
NTFS API and the expanded Windows access-control API were designed. It
separates verified platform behavior from project design choices. Normative
requirements and decisions live under
[specs/](../specs/README.md); this note supplies their external evidence.

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
- Inherited access-rule provenance through the Windows inheritance-source API,
  including original-ancestor resolution through intermediate inherited ACEs.

The following ideas are deliberately deferred:

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
- Enabling backup, restore, take-ownership, and security privileges on module
  import is broader than the requested operation and obscures token state. The
  expanded design instead uses reference-counted operation scopes that restore
  the original state.
- Temporarily changing ownership after an authorization failure mutates an
  additional security boundary and creates restoration failure modes.

### NTFSSecurity identity and conversion model

The upstream
[`IdentityReference2`](https://github.com/raandree/NTFSSecurity/blob/master/Security2/IdentityReference2.cs)
class accepts `IdentityReference` and string input, detects SID text, translates
account names to SIDs, preserves an unresolvable but valid SID, compares values
by SID, and returns an account name when resolvable or SID text otherwise. It
also defines conversions among strings, `NTAccount`, `SecurityIdentifier`, and
`IdentityReference`.

`WindowsAccessControl` adopts those observable conveniences through cmdlet
binding and conversion helpers rather than a caller-facing wrapper class:

- account names, SID strings, `NTAccount`, `SecurityIdentifier`, and module
  output normalize to one SID
- deduplication and equality use SID identity, not display-name spelling
- orphaned SIDs remain inspectable and round-trip through rule output
- `Account`, `SID`, `IdentityReference`, and compatibility aliases support
  object-to-command pipelines
- only domain rights and configuration enums are direct caller types

## Active Directory Management Framework comparison

A 2026-08-11 review examined the
[Active Directory Management Framework](https://github.com/ActiveDirectoryManagementFramework/ADMF)
and the modules that carry its access-control logic.
[ADSec](https://github.com/PSSecTools/ADSec) reads and writes directory
descriptors through `Get-AdsAcl`, `Set-AdsAcl`, `Set-AdsOwner`, the two
inheritance commands, and `Get-AdsOrphanAce`.
[ADMF.Core](https://github.com/ActiveDirectoryManagementFramework/ADMF.Core)
and
[DomainManagement](https://github.com/ActiveDirectoryManagementFramework/DomainManagement)
compare those descriptors against a registered desired state.

ADMF solves a different problem. It is a domain-wide configuration engine:
`Register-DMAccessRule` records a desired rule against a distinguished name or
an object category, `Test-DMAccessRule` walks every managed object and reports
drift, and `Invoke-DMAcl` converges it. That authoritative whole-domain model
is a non-goal here, because this module addresses one named target per
invocation and expresses desired state through per-object DSC resources. The
comparison below therefore covers only the directory mechanics inside that
engine.

### Ideas worth adopting

- Schema default permissions as a comparison baseline.
  `Get-AdcObjectDefaultPermission` reads `defaultSecurityDescriptor` from every
  `classSchema` object and caches it per object class, so drift reporting can
  subtract the descriptor Active Directory itself applied at creation from the
  explicit rules an operator added. Without that baseline an exact directory
  desired state must either restate every default ACE or accept all of them
  silently. ADMF derives a second result from it: a declared rule that merely
  repeats a schema default is reported as redundant configuration rather than
  as drift.
- Names for `ObjectType` and `InheritedObjectType`. `Convert-AdcSchemaGuid`
  maps schema class, attribute, and extended-right names to GUIDs and back, so
  a caller writes `User-Account-Control` rather than its GUID. This module
  already resolves the output direction under
  [ADR 0020](../specs/decisions/0020-enrich-directory-rules-over-the-bound-connection.md),
  and its public parameters still bind `[guid]` only.

### Behavior to avoid when adopting them

- `Convert-AdcSchemaGuid` emits nothing for a name it cannot resolve. A caller
  that feeds that result into an access rule turns a misspelled `ObjectType`
  into an empty GUID, so an ACE intended for one property silently becomes an
  ACE for every property. Name input has to fail closed: an unresolvable name
  throws instead of widening the grant.
- `Get-AdcObjectDefaultPermission` gathers the schema through PowerShell
  remoting to the schema master, because `SetSecurityDescriptorSddlForm`
  resolves the domain-relative aliases in `defaultSecurityDescriptor` against
  the calling machine's domain. Reading the schema over the already-bound LDAP
  connection avoids both the extra remoting trust boundary and the wrong-domain
  translation, provided those aliases are expanded against the target domain
  SID.

### Already covered here

- Orphaned ACE reporting. `Get-AdsOrphanAce` flags an explicit ACE whose SID
  does not translate. Every rule object in this module exposes `IsOrphaned`,
  and `Resolve-WindowsIdentity` returns the unresolved SID.
- `adminCount` awareness. ADMF substitutes the AdminSDHolder descriptor as the
  desired state of a protected object because SDProp overwrites it anyway.
  `Test-WindowsADProtectedTarget` rejects such a target outright, which is the
  stricter answer for a command-level module.
- Identity comparison by SID across domains, bounded parallel processing of
  many targets, and a session-cached schema lookup.

### Rejected

- Registered desired state, object categories, name-replacement tokens, and
  content modes belong to a configuration management product rather than to a
  securable-object command set.
- A tri-state `Present` value of true, false, or undefined only has meaning
  inside an engine that would otherwise delete an undeclared rule. Each DSC
  resource here owns one rule and never removes what it does not manage.

### Rights masks that no enum can name

`Register-DMAccessRule` binds `ActiveDirectoryRights` as `[string]`
deliberately, "to allow some invalid values that happen in the field and are
still applied by AD". A measurement on 2026-08-11 confirmed why that choice
exists and what it costs here: PowerShell rejects a numeric argument for a
`[Flags]` enum parameter when any bit has no name. Against the member list of
`WindowsActiveDirectoryRights`, `0x000F01FF` binds, while raw `GENERIC_ALL`
(`0x10000000`), `MAXIMUM_ALLOWED` (`0x02000000`), and reserved `0x00000200`
are all refused at argument transformation.

This module keeps the enum rather than a string. Refusing to author an
unnameable mask by name is the fail-closed direction, output already renders
those bits through `AccessRightsDisplay`, directory rights removal expands a
stored `GENERIC_*` bit before subtracting, and `Set-ADObjectSecurityDescriptor`
plus SDDL backup and restore carry an exotic mask unchanged. Where a family
must accept such a mask as input, the answer is an argument transformation
attribute that converts a numeric mask through `Enum::ToObject` and leaves
every name to the engine's own conversion, not a `[string]` parameter that
abandons name validation altogether.

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

## Expanded securable-object research

Microsoft defines a
[`SE_OBJECT_TYPE`](https://learn.microsoft.com/en-us/windows/win32/api/accctrl/ne-accctrl-se_object_type)
enumeration for files, services, printers, registry keys, shares, kernel
objects, window objects, directory-service objects, and WMI objects. The
[securable objects](https://learn.microsoft.com/en-us/windows/win32/secauthz/securable-objects)
reference confirms that named Windows objects and some unnamed objects,
including processes, can have security descriptors. Each family still has its
own rights, addressability, inheritance, lifetime, and safe test boundary.

### Current expansion families

| Family | Verified platform behavior | Release decision |
| --- | --- | --- |
| Registry key | Keys have security descriptors and inherit ACLs from parent keys. `KEY_QUERY_VALUE` and `KEY_SET_VALUE` govern values. | Ship local standard hives and 32/64-bit views. Do not invent registry-value ACLs. |
| Service | Named services and the SCM expose owner, group, DACL, and SACL through service security APIs. | Ship local services, driver/per-user services, and explicit SCM targeting. |
| Process | Processes have descriptors retrieved and changed through handle-based security APIs. | Ship local PID, process-object, module-object, and caller-owned-handle targets. Pin one instance and fail closed on exit or PID reuse. |

The registry evidence is
[Registry Key Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights).
It defines `KEY_SET_VALUE` as the right required to create, delete, or set a
registry value and describes security descriptors for keys, not values.

The service evidence is
[Service Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).
It identifies `READ_CONTROL`, `WRITE_DAC`, `WRITE_OWNER`, and
`ACCESS_SYSTEM_SECURITY` for descriptors and documents both service and SCM
security.

The process evidence is
[Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
It directs callers to `GetSecurityInfo` and `SetSecurityInfo`, documents
protected-process restrictions, and recommends requesting only required access.

On 2026-07-25, a disposable elevated local probe used the proposed native
boundaries and returned nonempty self-relative descriptors for all three new
families: 172 bytes for an HKCU scratch key, 136 bytes for a temporary service,
and 144 bytes for the current process. The key and service were removed in the
probe's `finally` block.

### Additional object-family recommendations

| Candidate | Recommendation | Evidence and rationale |
| --- | --- | --- |
| Scheduled tasks | Future | [`RegisterTaskDefinition`](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-registertaskdefinition) accepts task SDDL, but COM registration and task-folder inheritance need a dedicated adapter. |
| Printers | Future | [`PRINTER_INFO_3`](https://learn.microsoft.com/en-us/windows/win32/printdocs/printer-info-3) exposes a persistent descriptor; safe write tests need a disposable queue and port. |
| WMI namespaces | Future | [Each namespace has a descriptor](https://learn.microsoft.com/en-us/windows/win32/wmisdk/setting-namespace-security-descriptors), but a bad write can lock out management infrastructure. |
| SMB shares | Future | [`Grant-SmbShareAccess`](https://learn.microsoft.com/en-us/powershell/module/smbshare/grant-smbshareaccess) manages an independent share descriptor, so in-box commands already cover common workflows. |
| Event-log channels | Future | [`wevtutil`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) sets channel access SDDL; custom-channel lifecycle is a separate test boundary. |
| Certificate private keys | Future | [`CryptoKeySecurity`](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.cryptokeysecurity) covers classic key containers, but CAPI and CNG addressing differ across editions. |
| Named synchronization objects | Exclude | Events, mutexes, semaphores, and timers are securable but ephemeral and poor DSC targets. |
| Window stations and desktops | Exclude | They are local, session-scoped, high risk, and cannot use named security APIs because names are not unique. |
| Active Directory | Exclude for this release | Technically securable but an explicit signed non-goal. |

The
[synchronization-object security](https://learn.microsoft.com/en-us/windows/win32/sync/synchronization-object-security-and-access-rights)
reference confirms that synchronization ACLs come from the creator token and
that some synchronization primitives are not securable. The object-type
reference identifies window stations and desktops as local objects whose names
are not unique for named security APIs.

## Scope decisions

### Version 0.1

Version 0.1 covers files and directories:

- DACL and SACL rule construction, query, add, replace, remove, and clear
- owner and access or audit inheritance
- identity and orphaned-SID handling
- selected-section descriptor get, copy, JSON backup, and restore
- canonical-order diagnostics
- Authz effective access
- process token privilege inventory, query, enable, and disable

Registry, service, printer, process, share-level, POSIX, Central Access Policy,
and operating-system audit policy management were deliberately outside the 0.1
scope.

### WindowsAccessControl expansion

The accepted next release renames the unpublished module to
`WindowsAccessControl` and adds local registry-key, service/SCM, and live
process security. Scheduled tasks, printers, WMI namespaces, SMB shares,
event-log channels, and certificate private keys are future candidates.
Remote native APIs, registry-value ACLs, Active Directory, POSIX ACLs, cloud
IAM, Group Policy authoring, and graphical tooling remain non-goals.

The original scope contract is maintained in
[specification 0001](../specs/0001-vision-and-scope.md), and the signed expansion
is maintained in
[specification 0006](../specs/0006-windows-access-control-expansion.md).
Deferred enhancements are tracked in [open issues](../specs/open-issues.md).
