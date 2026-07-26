---
status: current
last-verified: 2026-07-26
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

## ServiceController type loading

Windows PowerShell 5.1 may not resolve the `System.ServiceProcess.ServiceController`
type until `System.ServiceProcess` is loaded. Avoid a direct type literal in a
merged module resolver: resolve it through `PSTypeName`, load the in-box
assembly on demand, and use `Type.IsInstanceOfType()` for cross-edition target
recognition.

## SCM is not a named service

Plausible names such as `SCManager` and `ServicesActive` fail through
`GetNamedSecurityInfoW` as nonexistent services. Open the SCM explicitly with
`OpenSCManagerW`; close the returned service handle with `CloseServiceHandle`,
not `CloseHandle`.

## Process writes require read access

A process descriptor mutation reads the current selected sections and compares
the result before writing through the same pinned handle. A write handle that
contains only `WRITE_DAC`, `WRITE_OWNER`, or `ACCESS_SYSTEM_SECURITY` fails that
read. Include `READ_CONTROL` on every process write handle while retaining only
the section-specific write rights.

## Process privilege checks need a baseline

An elevated host can start with `SeDebugPrivilege` enabled even when the token
marks it as disabled by default. A final assertion that all scoped privileges
are disabled therefore reports a false leak. Capture each privilege's initial
enabled state before process operations and assert exact restoration afterward.

For PID targets, open and verify one handle against the expected creation
`FILETIME`, then reuse it for the complete operation. Do not re-open by PID for
the write because the original process may exit and the PID may be reused.

## Canonical descriptor record hashing

Do not hash JSON text directly because property order, whitespace, and numeric
representation vary by serializer and PowerShell edition. Write a domain tag,
fixed field order, length-prefixed UTF-8 strings, and fixed-width integers to a
binary stream. Format PID and creation `FILETIME` through `InvariantCulture`.
Keep a fixed process-record digest test in both supported editions.

An unkeyed digest detects corruption but an attacker can recompute it. The
adversarial signature test must replace both SDDL and digest while retaining the
old signature so it proves RSA verification, not only digest mismatch.

## Explicit absent SACL persistence

`RawSecurityDescriptor.GetSddlForm(Audit)` returns an empty string when the SACL
is absent. Portability output must normalize that selected absence to
`S:NO_ACCESS_CONTROL`. Native persistence may pass a null SACL pointer only when
`SystemAclPresent` is explicit; a merely omitted selected SACL fails closed.
Null DACLs remain rejected because they grant unrestricted access.

## Atomic backup replacement

PowerShell binds a null third argument to `File.Replace` as an empty path, which
Windows rejects. Use a unique same-directory rollback path, remove it in
`finally`, and keep cleanup warnings nonterminating so they cannot mask the
primary write outcome. Sign only after `ShouldProcess` approves the operation,
because hardware-backed keys can prompt or count usage under `WhatIf`.

## Isolated runspaces and shared target locks

One `PSModuleInfo` session state cannot be entered concurrently from multiple
runspaces; it can fail with `Stack empty`. Import an isolated module instance
through `InitialSessionState.ImportPSModule` for each worker. Module-local lock
registries are then insufficient for concurrent callers, so place only the
reference-counted canonical target lock state in an application-domain data
slot. Keep metrics module-local and recursion state in `ThreadLocal[bool]`.

PowerShell 5.1 can unwrap a one-item `if` expression even when each branch uses
array syntax. Wrap the complete normalization expression in `@(...)` before
using `.Count`; otherwise a one-target parallel throttle can calculate a zero
runspace-pool size.

`PowerShell.EndInvoke()` can wrap a terminating worker error in a
`MethodInvocationException`. Prefer the inner runtime exception's original
`ErrorRecord` when present, and retain the wrapper only as a fallback. Count
nonterminating error-stream records as target failures in both sequential and
parallel paths so metrics do not depend on throttle mode.

## PowerShell-relative evidence paths

`System.IO.Path.GetFullPath()` resolves relative paths against the process
working directory, which can differ from PowerShell's current provider
location. Join relative benchmark output to `(Get-Location).ProviderPath`
before normalization so a bare filename follows PowerShell location semantics.
