---
status: current
last-verified: 2026-07-28
owner: software-engineer
source: implementation and test evidence
---

# Debugging insights

## An array wrapper inside an if does not survive assignment

`$x = if ($c) { $a } else { @($b) }` discards the wrapper: the if-statement's
output is collected and a single-element result collapses to a scalar. A one-ACE
DACL comparison then indexed a string and compared it character by character,
and two descriptors that differed only in their single ACE were reported
equivalent. Write `$x = @(if ($c) { $a } else { $b })` so the wrapper is outside
the statement. A unit test caught this; inspection did not.

## A service certificate store is a different store location

`X509Store('NTDS\My', StoreLocation::LocalMachine)` cannot reach a domain
controller's NTDS store. A `LocalMachine` name resolves under
`HKLM\SOFTWARE\Microsoft\SystemCertificates`, while a service store lives under
`HKLM\SOFTWARE\Microsoft\Cryptography\Services\<service>\SystemCertificates`.
Only `CertOpenStore` with `CERT_SYSTEM_STORE_SERVICES` and a
`<Service>\<Store>` parameter reaches it. The location identifier is 5 shifted
left by 16, which is `0x00050000`; the neighbouring `0x00040000` is
`CERT_SYSTEM_STORE_CURRENT_SERVICE` and rejects a service-name prefix with
`E_INVALIDARG`.

Probed behavior on a workgroup host: an unknown service name opens an empty
collection rather than failing, an unknown store name under a known service
fails with `ERROR_FILE_NOT_FOUND`, and a completed enumeration always sets
`CRYPT_E_NOT_FOUND`, including for an empty store. A null return from
`CertEnumCertificatesInStore` therefore means finished or failed, so a gate that
does not check the last error reports a truncated list as a complete one.

## The Sampler build deletes the output directory

Working artifacts written under `output/` are destroyed by the build's clean
task, including an in-flight log the build itself is writing. Keep review
packages, reports, and job logs outside the repository.

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

## Parameter type attributes bind before the body runs

Windows PowerShell resolves a parameter's type attribute during binding, before
the function body executes. A private helper that declares
`[System.DirectoryServices.Protocols.LdapConnection]$Connection` therefore fails
with `Unable to find type` when it is the first directory call in a session,
even though a helper it calls would have loaded the assembly with `Add-Type`.
PowerShell 7 resolves the same type because the assembly is already present.
Load an on-demand assembly in the module prefix when any exported code path can
reach a typed parameter from it.

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

## Batch worker error tests

Pester mocks scoped to the module under test do not cross into the isolated
module instance imported by a batch worker. To test direct worker logic with a
module-scoped mock, set `WindowsAccessControlBatchWorker.Value` to true inside
`InModuleScope` and restore it in `finally`.

Public batch commands intentionally re-emit target-local failures as
nonterminating errors so independent targets continue. When an integration test
uses `Should -Throw` for one of those failures, pass `-ErrorAction Stop` on the
command under test. Do not make production errors terminating merely to satisfy
an assertion.

## PowerShell-relative evidence paths

`System.IO.Path.GetFullPath()` resolves relative paths against the process
working directory, which can differ from PowerShell's current provider
location. Join relative benchmark output to `(Get-Location).ProviderPath`
before normalization so a bare filename follows PowerShell location semantics.

## Exact DSC and system-derived ACL flags

Windows can add `DiscretionaryAclAutoInherited` or `SystemAclAutoInherited`
after an exact descriptor write. Comparing raw SDDL then reports permanent
drift even when ACEs and protection state match. Clone each descriptor, clear
only those two system-derived flags, and compare the selected canonical SDDL.

An explicitly absent selected SACL (`S:NO_ACCESS_CONTROL`) sets
`SystemAclPresent` but has no SACL pointer. Persist the selected Audit section,
but do not request native SACL protection; native protection persistence must
target only ACLs that are present.

## Desktop DSC module visibility

`Invoke-DscResource` delegates class-resource execution to the SYSTEM LCM,
whose module path does not inherit a workspace-only `PSModulePath`. Acceptance
tests temporarily install the exact built version under Program Files, refuse
to overwrite an existing installation, hide the duplicate workspace path from
DSC discovery, and remove the installation in `AfterAll`.

## SCM descriptor recovery

A previous restrictive sample (`D:(A;;CC;;;WD)`) had been persisted to the
singleton SCM and removed Administrators/SYSTEM control. Back up owner, group,
DACL, and SACL as SYSTEM before repair. Restore only the DACL from Microsoft's
documented account grants, preserve the original SACL, validate the full service
suite in both editions, and remove every scheduled-task/file backup artifact.
Retain a live `WhatIf` regression asserting that the restrictive sample never
changes the SCM descriptor.

## NTFS rule-presence mask normalization

The `FileSystemAccessRule` constructor adds `Synchronize` to allowed `Read`
rules but not denied rules. Exact desired-state matching must construct the
same .NET rule and compare its normalized mask. Raw requested masks otherwise
never converge for common allowed rules.

Windows can merge same-account, qualifier, and scope ACEs. A narrower exact
`Present` resource cannot coexist with an existing rights superset; document
that callers model the superset or use an exact-descriptor resource. Never
remove the superset when enforcing the narrower resource, because that would
destroy unrelated rights.

## Desktop secure-string test fixtures

In a standalone Windows PowerShell 5.1 Pester host, calling
`ConvertTo-SecureString` after module discovery can attempt to autoload
`Microsoft.PowerShell.Security` after its type data is already present. The
autoload then fails with duplicate `ObjectSecurity` members before the test
runs. For an ephemeral test credential, construct `SecureString` directly with
`AppendChar()` and `MakeReadOnly()` so the fixture does not depend on module
autoload. Production credential input remains a normal `PSCredential`.

Desktop Pester discovery can also lose ambient access to
`Import-PowerShellDataFile` after repository dependency paths are prepended.
Module-qualify it as
`Microsoft.PowerShell.Utility\Import-PowerShellDataFile` in QA tests, and
supply Sampler's `ProjectName` explicitly when running framework QA outside the
build.

## Sampler session contamination

A reused PowerShell session can retain a typed `System.Text.UTF8Encoding`
value and pass it to ModuleBuilder even though `build.yaml` specifies the valid
`UTF8` scalar. Run every Sampler workflow through the clean detached launcher;
the same package workflow then receives `UTF8` and succeeds without a
configuration change.

## ModuleBuilder does not parse what it writes

ModuleBuilder concatenates the source files and writes the merged `.psm1`
without parsing the result, so `build` reports success for a merged file that
cannot be imported. A missing newline between two statements produced
`Unexpected token 'if'` only when a later probe imported the module. Parse the
merged module explicitly after every build with
`[System.Management.Automation.Language.Parser]::ParseFile()`; single-file
analysis of `source/` cannot see the defect because each file parses on its own.

The build output can also stay locked for a moment after `Clean` deletes it, so
`Set-Content` fails with "used by another process". The next build succeeds;
treat one retry as normal rather than a source defect.

## Case-insensitive variable names collide with typed parameters

PowerShell variable names are case-insensitive, so a loop variable named
`$left` writes into a `[X509Certificate2]$Left` parameter and fails with
"Cannot convert value System.Byte[]". The stack trace points at the assignment
line, not at the parameter. Never differentiate a local from a parameter by
case alone.

## An if without else contributes zero array elements

`$token = if ($condition) { $value }` yields nothing when the condition is
false, and an array literal then silently loses that position. Every later
positional argument shifts, which surfaced as "Cannot bind argument to
parameter 'Certificate' because it is null" two frames away. Always give such
an assignment an explicit `else { $null }` when its result enters an array.

Related: `@($a, $arrayValue, $b)` flattens `$arrayValue`, shifting later
positions the same way. Wrap it as `(, $arrayValue)`.

## DSC class property value advertising

`Get-DscResource -Syntax` renders a `[string]{ a | b }` value list only for a
class property that is a real .NET enum or carries a `[ValidateSet()]`. A bare
`[string]` property such as `AppliesTo` shows only `[string]`. `AppliesTo` is a
friendly label over the `InheritanceFlags` and `PropagationFlags` pair (plus a
read-only `Custom`), so it has no single enum type; add a `ValidateSet` matching
the cmdlet surface to advertise and validate it. Single-file AST parsing and
`Invoke-ScriptAnalyzer` on one class file report `TypeNotFound` and
`DscResourceInvalidKeyProperty` for sibling-file types; the authoritative gate
is the ModuleBuilder compile plus `Get-DscResource`.

## Changelog QA test timing and git phantoms

The QA `Changelog has been updated` test compares `git diff HEAD --name-only`,
so update `CHANGELOG.md` before launching `-Tasks test`; editing it after the
run starts makes the test fail even though the entry exists. After a build, git
can mark many source files modified in `git status` while `git diff` is empty
(stat cache touched, content identical); trust `git diff --name-only` for the
true change set and stage only real changes.

## Untracked pre-rename stale files

Untracked pre-rename leftovers such as `Initialize-NTFSNativeType.ps1` and
`Elevated-NTFSPermission.Tests.ps1` can shadow the tracked renamed files and
fail the suite at discovery by importing the removed `NTFSPermission` module.
They are untracked, so they carry no git history; confirm the tracked renamed
equivalent exists and get an explicit decision before deleting them.

## Private-function tests must load the module at run phase

Importing the built module only in `BeforeDiscovery` can pass a private-function
test in isolation but fail it in the full suite with `No modules named
'WindowsAccessControl' are currently loaded`, because another file's `AfterAll`
removes the module before the run phase. Import in `BeforeAll`, capture
`$script:module = Get-Module WindowsAccessControl`, and invoke private functions
with `& $script:module { param(...) ... } $args` (the pattern the DSC contract
test uses). This avoids `InModuleScope`'s `Get-CompatibleModule` resolution and
is robust to cross-file load/remove ordering. A green isolated run is not
sufficient evidence for a private-function test; confirm it in the full suite.

## Desktop Pester coverage and PowerShell classes

Pester 5.7.1 `CodeCoverage.UseBreakpoints: false` selects its experimental
profiler tracer. Under Windows PowerShell 5.1, tracer-instrumented class-based
DSC construction can throw `ArgumentOutOfRangeException` after Desktop LCM
acceptance. The same LCM-plus-resource sequence passes without coverage and
with breakpoint coverage, using the original `Activator.CreateInstance`
fixture.

Keep `UseBreakpoints: true`. Prove the fix with the covered nine-test sequence
and the complete test workflow in both editions; do not skip the resource tests
or replace their constructor fixture to hide the tracer defect.

## Native and managed ACE enumeration

`GetInheritanceSourceW` returns one metadata entry for every native DACL ACE,
while `.GetAccessRules()` emits only `CommonAce` allow/deny rules. Never zip the
unfiltered arrays. Parse the same binary descriptor, filter native metadata to
the managed subset, retain a cardinality guard, and test object-ACE coexistence
plus mixed explicit and inherited sources. Skip the native hierarchy walk when
inherited rules are excluded.

## Domain-lab absence and CNG cleanup

Active Directory `-Identity` lookups for an absent OU, user, or group can emit
or throw object-not-found errors even with a nonterminating error preference.
Use a scoped LDAP search when absence is an expected idempotence state; keep
typed identity lookups terminating after the fixture must exist.

Task Scheduler reports a missing folder over WinRM as
`System.IO.FileNotFoundException` with HRESULT `0x80070002`, not necessarily as
`COMException`. Match the exact HRESULT and rethrow every other error.

Removing a certificate from `Cert:\LocalMachine\My` leaves its persisted CNG
private key openable. Assign lab keys a deterministic provider/container,
delete the attached `RSACng.Key` explicitly, and check the known container for
partial-cleanup recovery. Setup must also detect a matching certificate whose
key cannot be opened, remove that stale selector, and recreate the managed key.
When the selector is absent but the deterministic container remains,
`New-SelfSignedCertificate` fails with `NTE_EXISTS`; delete the known container
before creating the replacement selector. Retain live tests for both repair
directions and for capturing the unique key, tearing down the fixture, and
proving that `CngKey.Open` fails before restoring the ready lab.

## Domain controller impersonation acceptance

`New-LocalUser` on a domain controller creates an ordinary directory-backed
account, not an independent member-server local account. The default domain
controller security policy does not grant that account interactive logon, so
`LogonUser` with the module's interactive logon type returns
`ERROR_LOGON_TYPE_NOT_GRANTED`. Run disposable local-account impersonation
acceptance on a member server; do not weaken domain-controller logon policy or
change production impersonation semantics merely to make that host profile
green.

## Task Scheduler descriptor canonicalization

The Task Scheduler service can reorder ACEs and add `DACL_AUTO_INHERITED` after
a DACL write. Verify protection state and exact ACE identity rather than raw
SDDL, but do not ignore rights, qualifier, flags, or ACE multiplicity. Release
task, folder, and service COM objects in reverse order on every path.

## Unattended Pester result gates

A Pester result of `Passed` does not prove that any test was discovered or
passed, and skipped tests can still leave a profile superficially green. Gate
on positive total and passed counts, zero skips, exact suite result, and a
ready cleanup ledger. Capture helper script blocks before nested suites because
a suite can reload the harness module and replace private command visibility.

## Coverage threshold arithmetic

Evaluate coverage from integer covered and missed command counts, not a rounded
display percentage. With 5,306 executable commands, an 80 percent gate requires
at least 4,245 covered commands; 4,244 displays as 79.98 percent and remains
below threshold. Add behavior-rich branch coverage instead of lowering the
gate.

## Transient ModuleBuilder output locks

ModuleBuilder can occasionally lose a race with a generated module file in a
fresh output directory. Confirm the failure is an exclusive generated-file
lock, remove any module loaded from that output root, and rerun the same clean
build once. Do not alter source or suppress the build error.

## SMB share descriptor metadata preservation

`SetNamedSecurityInfoW` with `SE_LMSHARE` can clear a share description even
when only the DACL is selected. Capture the provider description before the
native write, restore it afterward, and aggregate restoration failure with the
primary operation failure. A DACL round trip alone is insufficient evidence.

Resolve share targets through the local SMB provider rather than accepting a
syntactically plausible UNC or wildcard. Provider topology is the authority for
whether an ordinary share is local and addressable by the native adapter.

## LDAP attribute and naming-context boundaries

PowerShell can enumerate a `DirectoryAttribute` as individual bytes instead of
returning its byte-array value. Read values by index and decode textual LDAP
attributes explicitly as UTF-8; do not rely on pipeline enumeration.

The Configuration and Schema naming contexts at a forest root lexically end in
the default naming-context DN. A suffix-only containment check therefore admits
excluded partitions. Read their RootDSE naming-context values and reject them
explicitly before applying the allowed-base check.

`AuthType.Negotiate` does not prove Kerberos because it can fall back to NTLM.
Use `AuthType.Kerberos` with an explicit FQDN server, signing, sealing, disabled
referrals, and bounded timeouts when the contract requires strict Kerberos.
