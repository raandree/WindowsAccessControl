---
status: current
last-verified: 2026-08-16
owner: software-engineer
source: implementation and test evidence
---

# Debugging insights

## DscResource.DocGenerator wants one DSC resource class per source file

Adding the DSC Community wiki tasks failed on the first one.
`Generate_Conceptual_Help` threw `Cannot bind argument to parameter 'Path'
because it is null` from inside `Get-CommentBasedHelp`. The task finds the
resource classes by parsing the built `.psm1`, then looks their source up as
`Join-Path $SourcePath ('Classes/*{0}.ps1' -f $className)` and runs
`Resolve-Path` on it. This module declares twenty resources in
`010.WindowsAccessControlExactDescriptorResources.ps1` and
`020.WindowsAccessControlAccessRuleResources.ps1`, grouped by behavior, so that
wildcard matches nothing, `Resolve-Path` yields `$null`, and the binding fails.
`Generate_Markdown_For_DSC_Resources` resolves the same way and fails the same
way.

Nothing in the message points at the file layout, so read the task source
rather than the error. The fix is either splitting `source/Classes` one class
per file, which is a source decision and not a pipeline one, or leaving both
tasks out of the workflow.

## platyPS cannot express a multi-line parameter default as YAML

With the conceptual-help tasks removed,
`Generate_External_Help_File_For_Public_Commands` failed with `Invalid yaml:
expected simple key-value pairs` on `Add-NTFSAccessRule.md`. `New-MarkdownHelp`
writes each parameter's metadata as a YAML block and puts the default value on
the `Default value:` line verbatim. `ThrottleLimit` defaults to `[Math]::Max(1,
[Math]::Min(8, [Environment]::ProcessorCount))` written across four lines, so
the continuation lines are not key-value pairs and `New-ExternalHelp` rejects
the block when it reads the markdown back.

The generated markdown itself is fine; only the MAML conversion fails. Fifty-six
commands declare that default. Writing it on one line would fix the conversion
and also stop `Get-Help -Full` printing a mangled default, but it is a change to
the module's public commands rather than to its pipeline.

## Running the docs workflow twice without a Clean collides on filenames

`build.ps1 -Tasks docs` on an `output/WikiContent` left over from an earlier run
fails with `Cannot create a file when that file already exists` in
`Prepare_Markdown_FileNames_For_GitHub_Publish`. That task renames
`Add-ADObjectAccessRule.md` to a non-breaking-hyphen spelling, which GitHub's
wiki needs, and the second run regenerates the ordinary spelling next to the
renamed one. No task empties the folder. It is not a defect: `docs` only ever
runs inside `pack`, after `build` has run `Clean`. Verify the workflow through
`pack`, not through `docs` alone.

## A hosted build agent reports TEMP in its 8.3 short form

Every `Build` run had failed since the workflow was added, always on the same
four tests and in both editions. A GitHub-hosted Windows runner sets `TEMP` to
`C:\Users\RUNNER~1\AppData\Local\Temp`, and `Get-Item(...).FullName` expands a
short component, so a fixture rooted at the raw variable and an assertion
against a module-returned path compare two spellings of one directory. Both
editions expand: .NET Framework and .NET normalize the same way, measured on
`C:\PROGRA~1` under `powershell.exe` and `pwsh`.

The failure reads as a module defect because the module is what returns the
unexpected string. It is a fixture defect: canonicalize a path-shaped fixture
root once, at creation, and derive everything from that.

Reproduce it without a hosted agent. `fsutil 8dot3name query C:` says whether
the volume creates short names; create a directory whose name exceeds 8.3, read
its alias from `Scripting.FileSystemObject`'s `ShortPath`, and point `TEMP` at
the alias for the run. That reproduced the same four failures locally and
proved the fix on the same command.

## A PowerShell 7 path in the machine PSModulePath breaks every DSC resource

`Invoke-DscResource` failed for every resource that reads an access control
list, with `The 'Get-Acl' command was found in the module
'Microsoft.PowerShell.Security', but the module could not be loaded.` The DSC
provider host is `WmiPrvSE` running as `SYSTEM`, and it reads the machine-level
`PSModulePath` rather than the caller's. That value had grown three PowerShell 7
entries (`...\Documents\PowerShell\Modules`, `C:\Program Files\PowerShell\Modules`,
`...\PowerShell\7\Modules`), so Windows PowerShell found PowerShell 7's
`Microsoft.PowerShell.Security\Security.types.ps1xml` and refused it: every
member it defines on `System.Security.AccessControl.ObjectSecurity` is already
present in Windows PowerShell.

A `SYSTEM` scheduled-task probe proved it in one step: with those paths present
`Import-Module Microsoft.PowerShell.Security` fails, and with them removed for
that process only both the import and `Get-Acl` succeed. Removing them from the
machine variable is safe because PowerShell 7 adds all three itself at startup.
The WMI service must then be restarted, because a provider host inherits the
environment of the service that spawns it. Clearing the DSC cache does not help;
the failure is environmental, not cached.

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

## A session runspace has a far smaller call-depth budget than a console host

Measured on the fixture domain controller: an AutomatedLab session runspace
allows 165 nested script frames, while a child console process on the same
machine allows 4694. The directory suites drive deep validation chains through
worker runspaces and already sit close to the session limit, so enabling code
coverage there failed six rejection tests with `ScriptCallDepthException`
instead of the rejection they assert. Both instrumentation mechanisms hit it:
breakpoint actions add frames per hit, and the tracer adds its own. The same
suites passed with coverage when run alone, which made the mechanism look
guilty until the budget was measured directly. Run work that needs depth in a
console process rather than trading instrumentation mechanisms.

## Pester renders JaCoCo names relative to the measured file, not absolutely

A JaCoCo document from Pester never contains an absolute path. The package name
is the leaf of the measured file's parent directory, the class name is that leaf
plus the file name without its extension, and the source-file name is the file
name. For a built module that means the package is the module version, so two
runs of the same version merge cleanly from different absolute paths. Two runs
of different versions silently produce disjoint packages instead.

## Requesting the SACL changes the DACL that Windows returns

`GetNamedSecurityInfo` clears `INHERITED_ACE` on every DACL ACE when the same
call also requests `SACL_SECURITY_INFORMATION`. Measured on one file, at one
moment, with `SeSecurityPrivilege` held: the DACL ACE flag bytes are `0x10` for
`SECURITY_INFORMATION` `0x4` and `0x7`, and `0x00` for `0xF`. The difference is
in the returned descriptor bytes, not in a serializer, because converting the
`0xF` descriptor with DACL-only information reproduces the cleared flags. Both
editions observe it, since both reach the same Win32 entry point.

A combined `Get-Acl -Audit` therefore reports inherited ACEs as explicit.
Replaying that SDDL writes them as explicit ACEs, Windows re-applies
inheritance on the unprotected DACL, and the object ends up with both copies,
so an exact descriptor never converges. Read the DACL without the SACL and
graft the SACL onto that descriptor.

The quirk only appears while the DACL has no `SE_DACL_AUTO_INHERITED` bit,
which is the state of an object that has never been written to. Any
`SetNamedSecurityInfo` write sets it, and the combined read is then correct.
A regression test whose fixture adds an inheritable ACE to the parent first
passes without the fix, because creating the child under a written parent sets
the bit. Use a file that no descriptor write has touched, and assert something
that proves the fixture still inherits so the comparison cannot go vacuous.

Grafting through `SetSecurityDescriptorBinaryForm` marks the grafted section
modified, and `SetAccessControl` then writes it, which was proved by making an
out-of-band SACL change between the read and the persist and watching it
disappear. Graft only a section the caller already selected.

`icacls` did not print `(I)` for the same inherited ACEs, which pointed at the
wrong component for a while. Two wrappers disagreeing is not evidence; go to
`GetNamedSecurityInfoW` and read the ACE header bytes.

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

## A PowerShell 7 numeric literal suffix hides as a DSC discovery failure

One `0xFFFFFFFFUL` in a public command made all twenty `Get-DscResource`
contract tests fail with `is not recognized as the name of a Resource`, while
the module imported cleanly, every other test passed, and the failing files were
ones the change never touched. `Get-DscResource` under PowerShell 7 resolves
class-based resources through the Windows PowerShell compatibility session, and
that parser rejects the `U`, `UL`, and related suffixes added in PowerShell 6.2.
A parse failure there yields no resources rather than an error naming the file.

The failure looked environmental because it was total and uniform, which is the
same shape a missing `PSModulePath` entry produces. Parse the built `.psm1` with
`[System.Management.Automation.Language.Parser]::ParseFile()` under
`powershell.exe` before blaming the environment; it names the line in one step.
Do the same for every changed file whenever a change is authored in PowerShell 7
and the module must load in both editions.

## A .NET rights enum renders nothing once one bit is unnameable

`Enum.ToString` on a flags enum abandons every name it already resolved and
returns the whole value as a signed integer as soon as one bit has no name, so
`FileSystemRights` shows `-536805376` rather than a partial list.

The value is a real ACE. Windows splits an inheritable entry that carries
`GENERIC_*` bits into an effective copy with the bits mapped through the object
type's generic mapping and an inherit-only copy that keeps the generic bits, so
every child of a volume root has two `Authenticated Users` entries for what the
Windows security dialog shows once. A PowerShell enum cast rejects such a value
outright; only `Enum.ToObject` boxes it, which is why `Get-Acl` can produce a
value that `[FileSystemRights]$mask` cannot.

Reproduce the enum's own greedy decomposition to find the residue, then let .NET
render the mask minus that residue. Naming the residue independently would drift
from .NET's choice among equal-valued members such as `AppendData` and
`CreateDirectories`. A sweep of every mask below `0x40000` plus random 32-bit
masks compared 2,302 nameable renderings with zero differences.

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

Measured on 5.1, the discriminator is the underlying type, not the enum family:
`AceFlags` and `AceType` are `Byte`, while `ControlFlags`, `AuditFlags`,
`ObjectAceFlags`, `AceQualifier`, `AccessControlSections`, `InheritanceFlags`,
and `PropagationFlags` are `Int32` and combine directly. Only a `Byte`-backed
enum needs the `[int]` operands. The string form
`[AceFlags]'ContainerInherit, InheritOnly'` is also safe.

## Get-Acl cannot take -LiteralPath for a registry key on 5.1

Windows PowerShell 5.1 `Get-Acl -LiteralPath 'HKCU:\Control Panel'` fails with
`GetAcl_PathNotFound` and returns nothing, so the next member access reports
"You cannot call a method on a null-valued expression" one line later.
`-Path` returns the `RegistrySecurity` for the same key, and PowerShell 7
accepts both. The filesystem commands are unaffected: `-LiteralPath` works
there in both editions. Use `-Path` for a registry key, or read the key with
`Get-Item` and call `GetAccessControl()`.

## PowerShell 7 module paths in the machine PSModulePath break autoloading on 5.1

If `C:\Program Files\PowerShell\7\Modules` is on the *machine* `PSModulePath`,
Windows PowerShell 5.1 resolves the in-box `Microsoft.PowerShell.*` modules to
PowerShell 7's `Core`-only copies first and cannot load them. Two symptoms,
one cause:

- `Microsoft.PowerShell.Security` fails with "The member Path is already
    present" for `System.Security.AccessControl.ObjectSecurity`, and the caller
    sees "The 'Get-Acl' command was found in the module
    'Microsoft.PowerShell.Security', but the module could not be loaded."
- `Microsoft.PowerShell.Utility` fails outright, and the caller sees "The term
    'Import-PowerShellDataFile' is not recognized", which aborts `build.ps1`
    while it imports the Sampler task modules.

Only a host that has to *autoload* the module is affected. The standard 5.1
console preloads both, so `powershell.exe -File build.ps1` succeeds while the
same command fails in the VS Code PowerShell Extension terminal, whose session
state does not preload them; `Invoke-DscResource` fails for the same reason.
Measured: dropping that one path entry makes both resolve to the Desktop copy
and succeed.

PowerShell 7's installer adds `%ProgramFiles%\PowerShell\Modules`, not its own
`$PSHOME\Modules`, so the entry is hand-added. Fix the machine variable; do
not work around it in module or test code. `Invoke-DscResource` reads the
machine environment through WmiPrvSE, so a process-level `PSModulePath` cannot
mask it.

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

A leftover Windows PowerShell 5.1 remoting host is a different and worse case.
A test that opens a session or a 5.1 job and does not dispose it leaves a
`powershell.exe -Version 5.1 -s` process behind that holds the built module
open for as long as it lives. That is not transient: it failed a whole test
container mid-run with the same message, reporting thirteen tests as failed for
a reason none of them caused. When the message appears outside the first build,
look for an orphaned host process before suspecting the build.

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

## Cold-lab timeouts corrupt the shared certificate fixture

A domain-lab acceptance started shortly after the Hyper-V host reboots runs
against cold machines. `Should repair a missing certificate whose managed CNG
key remains` allows the repair job only 30 seconds, and on timeout its `finally`
calls `Stop-Job`. Killing that job mid-flight leaves a certificate in
`LocalMachine\My` whose private key is gone, so `GetRSAPrivateKey` fails with
`Invalid provider type specified`.

That orphan poisons every later run. `Remove-WindowsAccessControlDomainLab` does
not match a certificate whose key it cannot read, so the orphan survives the
removal while `Initialize-WindowsAccessControlDomainLab` creates a fresh one
beside it. `Test-WindowsAccessControlDomainLab` still reports ready because it
finds one good certificate, but the next initialize throws `Multiple domain-lab
certificates have the same managed identity` and fails all four tests in the
first suite. Because the harness fails fast on the first failed suite, no later
suite runs at all.

Recovering needs a delete keyed on subject and friendly name alone, ignoring the
private key, followed by one rebuild and an explicit assertion that exactly one
certificate remains. Readiness is not a sufficient check; count the
certificates. Let the lab settle after a host reboot before starting an
acceptance, and read machine uptime rather than assuming the lab is warm.

## One shared session made the acceptance sensitive to test count

The acceptance ran all six suites through separate `Invoke-Pester` calls in one
Windows PowerShell session on the management domain controller. Scope depth
accumulated across suites, so adding four tests to the private-key suite made
the two Active Directory tests that call `New-ADOrganizationalUnit` fail with
`ScriptCallDepthException`. Those two are the only tests in that suite creating a
disposable organizational unit, and that cmdlet is CDXML-backed, so it carries
more script frames than a compiled cmdlet.

The symptom pointed away from the cause in three ways. The failing tests touched
none of the changed code. The Active Directory suite passed 12 of 12 twice when
run on its own. And the two tests immediately after the failures passed, which
ruled out simple monotonic exhaustion and made the failure look transient.

An A/B settled the trigger: with the committed three-test private-key suite the
full acceptance was green, and with the seven-test suite the Active Directory
suite failed, reproduced twice. Two candidate fixes were then tried and both were
withdrawn. Hoisting a per-test module import to suite scope did not help. Giving
each suite its own runspace did make the acceptance green, but only until it met
code coverage: a bare runspace has no host, so Pester's `Write-Host` throws
`NullReferenceException`, the acceptance fails outright, and the coverage
document records zero executed commands against a full analyzed count.

The fix that holds is the one OI-27 found independently: run the acceptance in a
child console process on the domain controller. A session runspace there allows
only 165 nested script frames against 4694 in a console host, so the frame budget
was the real constraint and per-suite isolation was only masking it.

Two lessons. When a test fails only in a longer sequence, suspect the runner
before the code, and prove it by varying the sequence rather than by reasoning
about it. And a harness fix is not done until it has run with every gate the
harness feeds; this one passed the tests and broke the coverage document.

## A version 4 certificate template packs its CNG settings into one attribute

`New-LabCATemplate -Version 4 -SourceTemplateName Machine` writes
`msPKI-Template-Schema-Version` 4 onto a copy of a version 1 template and stops
there. The certification authority then refuses every request for it with
`CERTSRV_E_UNSUPPORTED_CERT_TYPE` (0x80094800), and the request looks like a
permission problem until the Application log is read. The policy module states
the real cause:

```text
The WacLabRenewableComputer(v100.1): V4(0.0s) [msPKI-Asymmetric-Algorithm]
Certificate Template could not be loaded. Element not found. 0x80070490
```

There is no `msPKI-Asymmetric-Algorithm` attribute; setting one fails with
"the specified directory service attribute or value does not exist". A version 4
template carries those settings packed inside `msPKI-RA-Application-Policies` as
backtick-delimited name, type, and value triples:

```text
msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA256`
msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`
msPKI-Symmetric-Key-Length`DWORD`168`
```

Two more things are needed before a member server in a child domain can enroll.
`pKIDefaultCSPs` must name a key storage provider, or the client picks the
provider and the issued key may not be CNG. And the template's default enroll
grant names the forest root's `Domain Computers`, which does not contain a child
domain's computers, so the child domain's group needs the enroll and autoenroll
extended rights added. `Restart-Service CertSvc -Force` returns before the
service answers, so wait for `Running` and for `certutil -ping` before the next
request.

## Certificate enrollment in a WinRM session has no directory credential

`Get-Certificate -Template` inside `Invoke-Command -Session` fails with
`CertEnroll::CX509Enrollment::InitializeFromTemplateName ... 0x800704dc`
(`ERROR_NOT_AUTHENTICATED`). Initialization reads the enrollment policy from the
directory, and a network logon holds no credential for that second hop. The
error names authentication, not delegation, which points at the template
permissions rather than at the token.

The same call succeeds through `Invoke-LabCommand`, because AutomatedLab
delegates the credential. Do not conclude from that comparison that the template
is wrong.

A machine certificate is requested by the machine account, so the fix is to run
the request as `SYSTEM` exactly as autoenrollment does: register a scheduled
task with a `ServiceAccount` principal, have it write its result as JSON, and
read that file back. That needs no delegation and no stored credential.
