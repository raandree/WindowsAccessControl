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

PowerShell 7 has a narrower exception: `FileSystemAclExtensions` persisted SACL
ACE changes but dropped `SetAuditRuleProtection($false, ...)`. The in-memory
descriptor was unprotected before persistence and protected after reload.
Persist the selected ACL pointer together with `SACL_SECURITY_INFORMATION` and
`UNPROTECTED_SACL_SECURITY_INFORMATION` through `SetNamedSecurityInfoW`.
Passing only the control flag returns access denied. Use the same section-scoped
pattern for DACL control flags and never include an unselected ACL.

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

For a standalone Windows PowerShell 5.1 Pester run, prepend both
`output/module` and `output/RequiredModules` to `PSModulePath`. Without those
paths, behavior tests that import an explicit manifest can pass while QA fails
to autoload the built module, Sampler helpers, or ChangelogManagement.

## GitVersion error output with a zero exit code

GitVersion 5.12 could not infer a parent when the checkout contained only an
`ai/` branch and no `master` ref. It wrote `INFO` lines and an exception instead
of JSON but returned exit code zero. Sampler then failed when it passed the
leading text to `ConvertFrom-Json`.

Use Sampler's documented `ModuleVersion` environment override for deterministic
local validation until `GitVersion.yml` recognizes `ai/` branches without a
missing parent ref. Do not suppress the JSON error or classify it as a source
compilation failure.

## Cross-edition flags enums

Windows PowerShell 5.1 does not parse PowerShell enum declarations with an
explicit `: uint32` underlying type. Define flags enums with the default signed
underlying type and represent `GENERIC_READ` as `-2147483648`. Normalize a
rights mask with `[uint64]([int64]$value -band 0xFFFFFFFFL)` when an unsigned
mask is required.

PowerShell enum types declared inside a module require type accelerators for
direct caller use. Replace a conflicting accelerator only when importing, and
remove it in the module `OnRemove` handler only when it still points to the
module's own type; otherwise same-session upgrades or foreign modules can retain
stale types.

## Module-scoped script block arguments

`GetNewClosure()` creates a dynamic module and can bypass Pester mocks scoped to
the module under test. For security-descriptor reads and writes, keep the
script block in module scope and pass data through an explicit `ArgumentList`.
This preserves mocks, avoids hidden parameter capture, and is clearer for later
runspace dispatch.

## RawAcl expression enumeration

`RawAcl` implements enumeration. Assigning it from an `if` expression can
unwrap a one-ACE ACL into `CommonAce`, causing `InsertAce` or `RemoveAce` to be
invoked on the wrong type. Assign `SystemAcl` or `DiscretionaryAcl` directly
inside each branch so the mutable `RawAcl` object retains its identity.

An absent registry SACL needs both an empty `RawAcl` and the
`SystemAclPresent` control flag before binary serialization. Keep null DACLs
rejected because they represent unrestricted access rather than an empty ACL.

## .NET enum masks in Windows PowerShell

Windows PowerShell 5.1 throws `InvalidCastException` for bitwise operations on
several .NET ACL enum values that PowerShell 7 coerces. Convert operands to
integers, perform the mask operation, and cast back to `AceFlags`,
`AuditFlags`, or `ControlFlags` only when calling a typed API.

## Remote RegistryKey objects

`RegistryKey.OpenRemoteBaseKey()` returns an object whose `Name` is
indistinguishable from a local hive path. Before name normalization, inspect
the supported runtime's nonpublic remote marker (`_remoteKey`, `remoteKey`, or
`m_remoteKey`) and fail closed if it is true or unavailable. Otherwise an
intended remote operation can be redirected to a local key.

## Binary descriptor argument lists

PowerShell can enumerate a `byte[]` when it is inserted into a general
argument array before later values. Build script-block argument lists with a
`List[object]` and call `Add($byteArray)` so the descriptor remains one object;
otherwise `RawSecurityDescriptor` receives a single byte and reports that the
destination array is too short.
