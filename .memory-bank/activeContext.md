---
status: current
last-verified: 2026-09-03
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

OI-31 is closed, and it was closed by reproducing the failure rather than by
arguing about it. The register had recorded `Expected
[WindowsServiceControlManagerRights], but got
[WindowsServiceControlManagerRights]` as a mechanism nobody had demonstrated,
with the duplicate-import explanation marked disproved and both affected
assertions weakened to a name-plus-`IsEnum` comparison.

The mechanism is a second compilation of the module file. PowerShell compiles a
module file into a dynamic assembly that carries every class and enumeration the
file declares, and caches the compiled script block keyed by file path and file
content. An import that reads the module file when the cache does not hold it
compiles the file again, so a second `PowerShell Class Assembly` goes live with
a second copy of every module-defined type.

What makes it unfixable from the assertion side is what happens next. The
module's own commands emit the new copy and its type accelerators are
re-registered onto it, but every script-side reference keeps resolving the
first copy: a type literal, a literal evaluated inside the module's own scope,
a script block bound to the module, `-as [type]`, a `[type]` cast, and
`Invoke-Expression` were each measured and all six were stale. There is no
expression a test can write that names the module's current type, so the only
repair is to stop reading the module file a second time.

The trigger that fired on 2026-08-11 is still unnamed, and the fix does not
depend on naming it. Three candidates were measured. The engine's own cache
drop above 1024 entries is real and is what the reproducer uses, but a real
`build, test` process peaked at 528 cached script blocks with no drop event and
a bare Pester run over the same suites peaked at 411, so the suite does not
reach it on this host. The `-ListAvailable` route in `tests/QA/module.tests.ps1`
and the `Get-ChildItem` route every other file uses produce byte-identical path
strings, so the cache key does not split. `Get-DscResource -Module
WindowsAccessControl` reuses the loaded instance in both editions rather than
reading a second copy. What is named is the precondition, a second read of the
module file, and removing every test-authored one closes every trigger the
test suite can reach. It does not close them all: the module's own
`Invoke-WindowsAccessControlBatch` imports the manifest into a runspace pool in
the same process on any bounded batch above a throttle limit of one. That read
was measured benign, because a full gate ends with one live copy, but it is why
the gate now asserts the copy count rather than trusting the rules.

The gate suites now do that. `tests/QA`, `tests/Unit`, and `tests/Integration`
import the module without `-Force`, which is a no-op once it is loaded, and no
longer unload it. The two places that genuinely test the load and unload cycle,
the type-accelerator lifecycle test and the QA module-control test, run it
inside `Start-Job`, where it happens in another process. Both strict assertions
are restored.

The earlier entry was half right rather than wrong. Repeated `-Force` imports
really are harmless while the cache holds, which is why three of them in a small
script never reproduced anything; the trigger is the cache miss and the import
is only what acts on it.

## What changed

- Restored `Should -BeOfType ([WindowsServiceControlManagerRights])` in
    `ServicePermissions.Tests.ps1` and
    `Should -BeOfType ([WindowsActiveDirectoryRights])` in
    `WindowsADSchemaDefaults.Tests.ps1`, and deleted the stale comment that
    still named the disproved duplicate-import cause.
- Dropped `-Force` from the module import in every gate test file and removed
    every in-process `Remove-Module` of the module under test.
- Moved the accelerator lifecycle test in
    `WindowsSecurityDescriptorEngine.Tests.ps1` and the QA `General module
    control` test into `Start-Job`. Each still proves what it proved before,
    now without compiling the module twice in the shared process.
- Added `tests/QA/TestSuiteModuleIdentity.Tests.ps1`, which walks the abstract
    syntax tree of every gate test file, fails on a forced import or an
    in-process unload of the module under test, and treats a call inside a
    `Start-Job` script block as out of process. Its third test pins the host
    behaviour the two rules exist for.
- Made `tests/QA/module.tests.ps1` refuse a process in which the module is
    loaded from its root module rather than its manifest. That is what a
    documentation task leaves behind, and the reset this suite used to perform
    is the thing OI-31 removes, so the condition is now named once instead of
    failing 750 discovery-driven quality gates one by one.
- Removed OI-31 from `specs/open-issues.md`; the register now has no open
    items.

## The one constraint this introduced

The `docs` and `test` workflows can no longer share a process. A documentation
task imports the built module from its `.psm1`, which exports all 267 functions
instead of the 105 the manifest names and applies no format data, and the QA
suite used to repair that with a `Remove-Module` plus a forced manifest import.
That repair is exactly the second read of the module file OI-31 is about, and it
is not safe to keep: if the repair misses the engine cache it creates the second
copy itself. `build.yaml` already puts `docs` in `pack` rather than in `test`,
and the CI workflow already runs `pack` and `test` as separate jobs, so nothing
shipping changes. A local `-Tasks build, docs, test` now fails immediately with
that explanation instead of cascading.

## Acceptance evidence

- The deterministic reproducer runs the two real test files after clearing the
    engine cache and re-importing: 2 live copies of the enumeration and the
    exact recorded failure text. The same files without that step: 1 copy,
    39 of 39 passing.
- Every type-resolution route was measured before and after a second
    compilation. Before: accelerator, literal, module-scope literal, bound
    script block, `-as [type]`, `[type]` cast, and `Invoke-Expression` all
    agree. After: only the accelerator and the module's own commands move to
    the new type.
- An instrumented gate run in one process sampled the engine script-block cache
    every 25 milliseconds. A bare Pester run over the three gate suites peaked
    at 411 entries; a real `./build.ps1 -Tasks build, test` process peaked at
    528. Neither recorded a drop event, and both ended with one live copy of the
    enumeration.
- The deterministic reproducer was repeated ten times in each mode: ten of ten
    poisoned runs produced two live copies and the recorded failure, and ten of
    ten clean runs produced one live copy and 39 of 39 passing.
- The guard was run against a throwaway worktree of pre-fix `main` with only the
    new suite copied in: 0 passed, 2 failed. It fails without the fix and passes
    with it.
- The full local gate passes: `./build.ps1 -Tasks build, test`, 17 tasks, 0
    errors, 0 warnings, 1,742 tests passed, 0 failed, 2 skipped, and 81.92
    percent asserted coverage over the 80 percent threshold.
- The focused suite, the two restored assertions plus the new QA suite, passes
    42 of 42 with 0 skips.

## Next step

Rerun the domain-lab acceptance when the lab is next available; it is unrelated
to this change but still measures the previous build.
