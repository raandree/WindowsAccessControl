---
status: current
last-verified: 2026-08-08
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

Reading a directory object's access control list should show what an operator
configured, not what the schema class hands every object of that class.
`Get-ADObjectSchemaDefaultAccessRule` returned that baseline and nothing
consumed it, so the comparison was done by hand.

Two register entries were also worked, and both turned out to be described
wrongly. The NTFS rights transform was not unreachable; it was bypassed for one
argument form. The duplicate module import does not create a second runtime
enumeration type at all.

## What changed

- `Get-ADObjectAccessRule` gained `-ExcludeSchemaDefault`, off by default. The
    matching rule lives in `Select-WindowsADNonDefaultAccessRule`, a pure
    function over two rule collections that takes no connection and does no
    directory work, so all four template cases are unit-testable without a
    domain controller. An explicit rule is dropped only when a template entry
    equals it on account, mask, access control type, inheritance, and both
    object type GUIDs; a template entry naming a creator placeholder drops
    nothing, and an inherited rule is never a candidate. ADR 0033 records the
    rule, the cases, and the bias toward reporting rather than hiding.
- The eight NTFS access and audit rights parameters and
    `New-NTFSFileSystemRule` no longer declare `[FileSystemRights]` next to the
    rights transform. Measured in both editions: an unnameable mask bound fine
    as a variable, a decimal literal, or a string, and only a **hexadecimal
    literal** failed, because the engine converts that one form to the declared
    type before the transform runs. Every existing unnameable-mask test passed a
    variable, which is exactly why the defect survived them.
- `specs/open-issues.md` lost OI-23, OI-29, and OI-30, and OI-31 now carries the
    measured disproof of its own explanation instead of the explanation.
- `WindowsAccessRightsTransformAttribute` is compiled through `Add-Type` in
    `Prefix.ps1` rather than written as a PowerShell class. A class instance
    carries the session state of the runspace that created it, and a pooled
    batch worker re-binding a decorated parameter invoked it with a null session
    state, which threw during parameter binding and silently dropped that
    worker's target.
- The NTFS bounded-batch test now captures the error stream of both batches, so
    the next time it loses a target the run says why instead of only that a
    count was wrong.

## Acceptance evidence

- Two-edition lab acceptance green on 2026-08-12 against the repaired build:
    8 suites, 85 passed, 0 failed, 0 skipped in each edition, `Result = Passed`,
    every suite `Ready = True`. Per suite: DomainLab 4, CertificatePrivateKey 7,
    TaskScheduler 8, SmbShare 7, ADObjectPermissions 12,
    ADSchemaDefaultAndObjectType 35, ForeignPrincipal 5, ADObjectReplication 7.
    The schema-default suite grew from 29 to 35 with the six live subtraction
    tests.
- Two consecutive full local gates green: 1,716 passed, 0 failed, 17 tasks,
    0 errors, 0 warnings, about 21 minutes each.
- The schema-default subtraction has 11 unit tests, proven red first with
    `CommandNotFoundException` before the matcher existed.
- The nine NTFS hexadecimal-literal regression tests were proven red (9 of 9)
    before the parameter change and green afterwards, each alongside a test that
    an unknown rights name is still refused.
- The batch target loss was measured before and after the attribute was
    compiled: over six instrumented Pester iterations each, five of six runs
    failed with 22 transformation faults before and none of six after.
- Measured on the lab: the `organizationalUnit` class template carries no
    creator placeholder and the `computer` class template carries several, and
    every `CO` entry reached a newly created computer object as an entry for
    that object's owner. That is what makes the placeholder refusal provable
    live without a skipped test.

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
- The acceptance runner calls `ShouldProcess`, so a detached non-interactive
    launch must pass `-Confirm:$false` or it fails on the prompt.
- A standalone Pester run must import Pester by explicit path or prepend
    `output/RequiredModules` to `PSModulePath`.
- The changelog QA check compares the working tree against the default branch,
    so a gate started before `CHANGELOG.md` is edited fails on that one test.

## Next step

OI-31 is the only register entry left and its mechanism is unknown. The two
weakened type assertions stay weakened until something reproduces a second live
runtime enumeration type; the batch test now captures the error stream that the
lost-target failure never reported.

The remaining lab-specific gaps, in order of the evidence they would add:
concurrent writers on the two writable controllers to prove `RequireUnchanged`
across replication; an enterprise certificate template plus a key-reusing
renewal to test specification 0017's thumbprint claim against a real issued
key; a second Active Directory site for inter-site replication; selective
authentication on the forest trust; a read-only domain controller; and running
the suites against the installed package rather than `output/module`.
