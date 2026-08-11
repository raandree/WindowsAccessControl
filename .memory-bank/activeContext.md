---
status: current
last-verified: 2026-08-11
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

Line coverage was 90.54 percent, so the remaining gaps were never unexecuted
lines: they were untested *inputs*. Five coverage prompts closed five of them on
real objects, and three of the five turned up behavior that had only ever been
assumed.

The largest was real: an access control entry carrying `GENERIC_*` bits could be
reported and never removed, because the public `FileSystemAccessRule` and
`FileSystemAuditRule` constructors reject any mask outside `FullControl`, and
`RemoveAccessRuleSpecific` rebuilds the rule through exactly that constructor
when no stored entry matches. That is the shape of the most-reported defect of
the module this one replaces.

The older thread below is unchanged.

## What changed

- NTFS rule construction runs through `New-NTFSFileSystemRule`, which uses the
    public constructor for a mask the enum can name and the rule factory for one
    it cannot, so `GENERIC_*`, `ACCESS_SYSTEM_SECURITY`, and an orphaned identity
    survive a round trip. `Remove-NTFSFileSystemRuleSpecific` matches the stored
    entry on the raw list for such a mask, so an exact removal that finds no
    match is a no-op instead of an argument-range error.
    `WindowsAccessRightsTransformAttribute` was written to let a raw numeric
    mask bind while keeping the enum type. Measurement on 2026-08-11 disproved
    the second half: a declared enum type adds the engine's
    `ArgumentTypeConverterAttribute`, which runs first and refuses the mask
    before the transform is consulted. The attribute is therefore still inert on
    every `FileSystemRights` parameter. OI-30 tracks the fix; the three
    directory mutators already use the shape that works.
- `Resolve-NTFSPath` refuses a Win32 device-namespace path and a bare drive
    specification. Both resolved to something other than what the caller wrote:
    `\\?\` bypasses normalization and yields a non-canonical target key, and
    `C:` resolves to the current location of that drive.
- A junction, a directory symbolic link, and a file symbolic link each carry
    their own descriptor. A write through the link changes the link, not the
    destination, which is what `Get-Acl`, `Set-Acl`, `icacls`, and `icacls /L`
    all do. The registry is the opposite: a registry symbolic link is followed.
    Both are recorded, in help and in ADR 0030 and ADR 0032.
- Five new suites: `NtfsGenericAndOrphanedAceRemoval`, `NtfsPathInputMatrix`,
    `NtfsReparsePointsAndLinks`, `NtfsIcaclsDifferentialOracle`, and the registry
    pair `RegistryTargetAliasMatrix` and `RegistryViewsAndRights`. Every one runs
    in both supported editions, and every genuine edition difference is asserted
    rather than skipped.

## Acceptance evidence

- `./build.ps1 -Tasks test` on 2026-08-11: 10 tasks, 0 errors, 0 warnings.
    Pester 1,666 passed, 0 failed, 2 skipped. Coverage 83.71 percent (6,615 of
    7,902 commands this profile can execute) over the 80 percent threshold.
- The five new suites also run standalone in both editions:
    generic and orphaned removal 25/25, path matrix 36/36, reparse points 10/10
    with one skip, `icacls` oracle 27/27, registry 61/61 with one skip.
- The coverage figure is local-only. Rebuilding the module invalidated the
    carried domain-lab document, and the build reports that rather than merging
    it. Rerunning the domain-lab acceptance against the rebuilt module restores
    the whole-module figure.

## Next step

Rerun the domain-lab acceptance against the rebuilt module so the merged
coverage document is current again. The remaining lab-specific gaps are
unchanged and listed at the end of this file.

## Earlier thread

Rule output has to be readable without inspecting the object. An access control
entry that carries `GENERIC_*` bits showed `-536805376` where the entry above it
showed `Modify, Synchronize`, because a .NET rights enum has no name for those
bits and abandons every name it already resolved as soon as one bit is
unnameable.

`Enable-WindowsPrivilege`, `Disable-WindowsPrivilege`, and
`Test-WindowsPrivilege` complete their `Name` argument from
`WindowsPrivilegeNameCompleter`. The parameter still validates by pattern, so a
constant outside the documented set stays usable; completion only removes the
need to recall the exact spelling.

The larger thread below is unchanged. The domain-lab acceptance now runs in both
supported PowerShell editions and covers a seventh suite for foreign and
orphaned principals. Before this, every enterprise claim rested on one Windows
PowerShell pass using one principal from the fixture domain.

## What changed

- `ConvertTo-WindowsAccessRightsDisplay` renders a mask that a rights enum
    cannot fully name. It repeats the enum's own greedy decomposition, lets .NET
    render the part it can name, and then names the four generic rights,
    `ACCESS_SYSTEM_SECURITY`, and `MAXIMUM_ALLOWED`, leaving any remainder as
    hexadecimal. Every rule object exposes the result as `AccessRightsDisplay`
    and both effective-access results as `EffectiveRightsDisplay`; the table
    views report those properties. NTFS rules also gained the `AccessMask`
    property the other object families already had.
- `tests/Lab/Invoke-WindowsAccessControlLabAcceptance.ps1` takes
    `-PowerShellEdition` and `-CoverageEdition`. It runs one complete pass per
    edition against the same fixture set, writes one evidence file per pass, and
    carries every artifact back before it fails the run. Only one pass arms
    coverage: instrumentation is the cost, and the second pass reaches no line
    the first cannot.
- `tests/Lab/ForeignPrincipalPermissions.Live.Tests.ps1` is new. It writes and
    reads an access control entry for a principal from another domain in the
    forest, from a trusted forest, and for a security identifier no lookup can
    resolve, across the share, task-folder, directory-object, and private-key
    families.
- `tests/Integration/ExactSecurityDescriptorDscLcm.Tests.ps1` gained a compile
    test for all ten enterprise resources and a discovery test asserting that
    `Get-DscResource` advertises every resource the manifest exports. The five
    enterprise pairs had only ever been converged by direct class instantiation.

## Acceptance evidence

- Two-edition lab acceptance green on 2026-08-08: 7 suites, 50 passed, 0 failed,
    0 skipped in each edition, `Result = Passed`, every suite `Ready = True`.
    Per suite: DomainLab 4, CertificatePrivateKey 7, TaskScheduler 8, SmbShare 7,
    ADObjectPermissions 12, ForeignPrincipal 5, ADObjectReplication 7.
- The instrumented Windows PowerShell pass took 22 minutes and the
    uninstrumented PowerShell 7 pass 5 minutes, which is the measurement behind
    the single-coverage-pass decision.
- `./build.ps1 -Tasks test` succeeds: 10 tasks, 0 errors, 0 warnings. Local
    Pester is 1,495 passed, 0 failed, 0 skipped.
- Domain-lab coverage 43.07 percent (3,422 of 7,945 commands),
    `Domain-lab evidence merged: yes`. Whole-module 90.51 percent (7,191 of
    7,945) reported; asserted scope 90.54 percent (6,952 of 7,678) over the 80
    percent threshold.
- `ExactSecurityDescriptorDscLcm.Tests.ps1` passes 5 of 5 in Windows PowerShell.

## Host fix that unblocked the DSC evidence

`Invoke-DscResource` failed for every resource that reads an access control
list. The machine-level `PSModulePath` had grown three PowerShell 7 entries, so
the DSC provider host running as `SYSTEM` loaded PowerShell 7's
`Microsoft.PowerShell.Security` and refused it as duplicate type data. The
machine value is now the two Windows PowerShell paths only, backed up at
`$env:TEMP\wac-machine-psmodulepath.backup.txt`, and the WMI service was
restarted so provider hosts inherit it. `debugging-insights.md` records the
proof.

## Environment notes

- `WindowsAccessControlLab` has 13 machines across three forests. After a host
    reboot they must be started before an acceptance run.
- `F1BDC1` and `F2DC1` are no longer reserved; the foreign-principal suite takes
    one principal from each. `forest1.net` holds bidirectional forest-transitive
    trusts to `forest2.net` and `forest3.net`, which is what makes the
    cross-forest case resolvable from `a.forest1.net`.
- A standalone Pester run must import Pester by explicit path or prepend
    `output/RequiredModules` to `PSModulePath`.
- The changelog QA check compares the working tree against the default branch,
    so a gate started before `CHANGELOG.md` is edited fails on that one test.

## Next step

The remaining lab-specific gaps, in order of the evidence they would add:
concurrent writers on the two writable controllers to prove `RequireUnchanged`
across replication; an enterprise certificate template plus a key-reusing
renewal to test specification 0017's thumbprint claim against a real issued
key; a second Active Directory site for inter-site replication; selective
authentication on the forest trust; a read-only domain controller; and running
the suites against the installed package rather than `output/module`.
