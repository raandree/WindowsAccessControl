# Lab acceptance: 2026-10-08

Live domain-lab acceptance of the candidate `bad1302` on the local branch
`ai/record-post-release-publication`. It routes two Active Directory reads
through the directory search function that every other directory read already
uses, and it gives a test to each of the 17 commands in the declared
domain-lab-only source files that no test had executed. The run followed the
[acceptance checklist](../tests/Lab/acceptance-checklist.md). The isolated
Desktop DSC-engine gate, all four full lab passes, and both local test and
coverage gates passed, and every one of the 17 commands now executes: the 13
that only the lab reaches in the fresh lab coverage, and the 4 that the source
change made unit-testable in the merged local coverage. A first built pass of
the previous commit, `938bdff`, stopped on the new confirmation case; `bad1302`
corrected the case, and every pass ran again. This record is not release
approval, and the candidate is not pushed.

A harness correction followed the same day. `a572d3d` stops arming member
coverage from changing the error preference of the member session; its built
pass and both local gates passed, as recorded under
[Harness correction](#harness-correction). It is not pushed either.

## Candidate and environment

- Commit: `bad130221f65b8064d8eba6d03c8325b4858ad18` with a clean worktree.
  It adds three commits to the records of the
  [2026-10-07 acceptance](lab-acceptance-2026-10-07.md): `4096d02` changes the
  module and its unit tests, `938bdff` adds the live cases, and `bad1302`
  corrects the confirmation case after the first built pass of `938bdff`
  stopped on it.
- Version: GitVersion 5.12.0, the same official standalone Windows release as
  on 2026-10-07 with a matching size and SHA-256, run read-only, computed
  `0.3.0-record-post-release-publication.1`, NuGet `0.3.0-record-post-rele0001`.
  The build received that value through `$env:ModuleVersion`, and Sampler
  built `0.3.0-record`, because it keeps only the first hyphen-separated part
  of a prerelease label. It is not a published version.
- A detached `pack` of `bad1302` built the module and the package: 22 tasks,
  zero errors, zero warnings. Its root module is byte-identical to the build
  of `938bdff` and to the development build that ran the focused green and
  red runs below; the manifests differ only in their version or in the build
  date of their release notes.
- Lab: the same isolated `WindowsAccessControlLab`, all thirteen VMs reused,
  with checkpoint `wac07-pre-938bdff-098b3392` taken before the first pass.
  After that pass stopped, the fixtures were verified intact and no checkpoint
  was restored, so the same checkpoint precedes the passes of `bad1302`.
  Readiness was proven at the protocol level before and after the checkpoint,
  before the passes of `bad1302`, and after the last pass: WinRM on all
  thirteen machines; signed and sealed Kerberos LDAP against both writable
  fixture controllers, each reporting `isSynchronized`; a ticket-granting
  ticket and `ldap` service tickets; ten marked baseline objects on both
  controllers with no leftover target; the member share with its marker, the
  Task Scheduler folder, and the lab key; and the published renewable CNG
  template.

## The commands no test executed

The 13 source files that `build.yaml` declares domain-lab-only held 17
commands that neither the unit profile nor the lab profile executed. Each now
has a test:

| Source file | Unexecuted commands | Now covered by |
| --- | --- | --- |
| `Set-SmbShareSecurityDescriptor` | The refusal of an SDDL without a DACL; the `-PassThru` read | Live: `Should refuse an SDDL without a DACL before writing`, `Should return the stored descriptor with PassThru` |
| `Remove-SmbShareAccessRule` | The refusal of an object that is not a rule from the share; the refusal of a rule whose canonical target differs | Live: `Should refuse a rule copy that was not read from the share before removing anything`, `Should refuse a rule whose canonical target names another server` |
| `Invoke-WindowsSmbShareCommandBatch` | The throttle of one that a confirmation requires | Live: `Should ask before writing and write nothing when the caller cannot answer` |
| `Get-WindowsADRuleEnrichment` | Both catch blocks, eight commands | Live: `Should report rules without an inheritance source when the source lookup fails`, `Should report object GUIDs without names when the schema-name lookup fails` |
| `Get-WindowsADRootDse` | The refusal of a response without one entry; the report of an absent root domain naming context | Unit, after the source change below |
| `Get-WindowsADEffectiveAccessRecord` | The refusal of a response without one entry; the zero for an absent `sDRightsEffective` | Unit, after the source change below; live: `Should report an object deleted after target resolution as not found` |

The SMB cases reach their paths with real objects: a rule restored from
serialized data, a rule reshaped by `Select-Object`, a rule whose canonical
target was edited, and a session that cannot answer a prompt. Three directory
conditions cannot be produced on demand, so they are injected. The two
enrichment lookups fail only on conditions no lab identity can create, because
the ancestor walk absorbs its own read failures and an identity that cannot
read the schema or configuration partition cannot read the rules either; a
module-scope Pester mock fails each lookup after the real descriptor read.
Nothing runs between target resolution and the effective-access read, so the
deletion case deletes a disposable organizational unit inside that read and
then sends the real request to the controller.

## Source change

`Get-WindowsADRootDse` and `Get-WindowsADEffectiveAccessRecord` sent their
LDAP requests straight to the connection, so no unit test could reach their
response checks, and both files were declared domain-lab-only. Both now call
`Send-WindowsADSearchRequest`, like every other directory read, and both
files left the domain-lab-only list, so the local gate asserts them. Six unit
cases replace the request at that function: a RootDSE response with zero or
two entries is refused, a RootDSE without `rootDomainNamingContext` reports
none, an effective-access response with zero or two entries is refused, and
an absent `sDRightsEffective` reports zero. They failed against the previous
code with "The LDAP server is unavailable", because that code bypassed the
function, and passed in both editions after the change.

One behavior changes. An object deleted between target resolution and the
effective-access read now fails with an `ItemNotFoundException` naming it.
A probe of the previous call on `F1ADC1` showed what it raised instead: a
`MethodInvocationException` wrapping a `DirectoryOperationException` with
result code `NoSuchObject`. The changelog and the
[specification](../specs/0018-active-directory-caller-effective-access.md#output-contract)
record it.

## Red evidence for the live cases

A copy of the development build with one change per guard ran the eight live
cases in both editions. Every case failed for the reason its guard names, and
the unchanged build passed all eight in both editions:

| Change to the module | Case | Result against the changed module |
| --- | --- | --- |
| The refusal of an SDDL without a DACL removed | SDDL without a DACL | The native helper refused it with its own message, which names `SetNamedSecurityDescriptor` |
| The `-PassThru` read removed | PassThru | No output |
| The non-rule refusal removed | Rule copy | The deserialized copy failed parameter conversion, and the reshaped copy removed the rule |
| The canonical-target refusal removed | Another server | The edited rule removed the grant |
| `ConfirmImpact` of `Set-SmbShareSecurityDescriptor` lowered to `Medium` | Confirmation | The write happened without a prompt |
| The inheritance-source catch made to rethrow | Inheritance source | The injected failure replaced the degraded report |
| The schema-name catch made to rethrow | Schema names | The injected failure replaced the degraded report |
| The effective-access read restored to the previous direct call | Deletion | No error, because the read never reached the search function |

The throttle of one that `Invoke-WindowsSmbShareCommandBatch` applies before a
confirmation has no observable effect for a single share, so the confirmation
case covers that line without testing it; the change that case is red against
is the one it exists for. These runs used the cases as `938bdff` wrote them;
`bad1302` changed only how the confirmation case opens its session and which
error preference it states, not what it asserts.

## Lab results

| Gate | Passed | Failed | Skipped | Cleanup | Completed UTC |
| --- | ---: | ---: | ---: | --- | --- |
| Desktop DSC engine | 5 | 0 | 0 | Temporary installation removed | 00:08:36 |
| Built module, Desktop with coverage | 109 | 0 | 0 | Eight ready entries | 00:39:05 |
| Built module, Core | 109 | 0 | 0 | Eight ready entries | 00:48:10 |
| Installed package, Desktop | 109 | 0 | 0 | Eight ready entries | 01:02:04 |
| Installed package, Core | 109 | 0 | 0 | Eight ready entries | 01:10:54 |

Every row is a run of `bad1302`. The four passes are four executions of the
same 109 live cases: the 101 of the 2026-10-07 follow-up plus the eight new
ones. Per suite: domain lab 6, certificate private key 8, Task Scheduler 9,
SMB share 15, Active Directory object 19, schema default and object type 35,
foreign principal 5, and replication 12. Every pass reported `Passed`, eight
suites, zero skipped tests, explicit native exit zero, and both readiness
flags in all eight cleanup entries. The DSC gate ran in an isolated Windows
PowerShell 5.1 process on the reserved member `F1AFile2`, staged with the
exact built module, and includes both actual `Invoke-DscResource` cases. The
installed-package pass installed the package at the `0.3.0` version directory
of the machine module path on `F1ADC1`, where its 25 module files matched the
candidate build and the runner's marker was present.

The first built pass, of `938bdff` on 2026-10-07, stopped in its Desktop
coverage edition. The confirmation case could not arm member coverage in its
own session, so the SMB share suite reported 14 of 15, and the runner ended
that edition after four of the eight suites, with 37 of 38 cases passing. Its
Core edition, which arms no coverage, passed all 109 cases, and a DSC-engine
gate of `938bdff` had passed 5 of 5 before it. The evidence of that pass is
retained. Before the rerun, the fixtures, the share's marker, the directory
baseline, and the service state were verified intact.

## Artifact identity

| Artifact | SHA-256 |
| --- | --- |
| Tested root module | `A9671FD086456978E4CE0CB5E01270B201C56FE7C1305BF7B77B9B9FB0E921CA` |
| Tested module manifest | `3D2C5E517ED6CD8DDDBCBA79A8F8C83786EA5B769F000AC0670A126B146BA768` |
| Tested package, `WindowsAccessControl.0.3.0-record.nupkg`, 276,055 bytes | `1E109787ECAB1A78D8118EC5A20CBEA20D9A7122AF6C202ADB17BA7207D4995E` |
| Fresh lab coverage | `E020309798847A35FF9AFBD7E2ABEA23FA2531CB0A9166BA945BC35CDEE397CA` |

The lab coverage measures 8,504 commands, of which the domain-lab profile
exercised 3,885 (45.68 percent); the harness reports 1,712 of them as reached
only in a member-server session. It is not the local or merged coverage
percentage. Each of the 13 commands that only the lab reaches is executed in
it, with no missed command on its line: the refusal of an SDDL without a DACL
and the `-PassThru` read in `Set-SmbShareSecurityDescriptor`, both refusals in
`Remove-SmbShareAccessRule`, the confirmation throttle in
`Invoke-WindowsSmbShareCommandBatch`, and the eight commands of the two
catches in `Get-WindowsADRuleEnrichment`. The confirmation case's own session
returned its hits as `SmbSharePermissions.Live.Tests.Confirmation.ps1`. The
document replaced the 2026-10-07 document `B3EE4313…6FD6`, reached the
configured coverage path from the instrumented Desktop pass, and matches the
guest original byte-for-byte.

## Local coverage gates

| Edition | Passed | Failed | Skipped | Asserted coverage | Whole-module coverage | Completed UTC |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Core 7.6.6 | 1,937 | 0 | 2 | 91.26% | 91.42% | 00:59:04 |
| Desktop 5.1.26100.33438 | 1,892 | 0 | 2 | 90.53% | 90.70% | 01:21:28 |

Both editions ran a fresh detached `build.ps1 -Tasks test` on `bad1302` with
the candidate's version, imported the fresh lab document, and reported
`Domain-lab evidence merged: yes`. They report the domain-lab-only coverage
as 100 percent, 154 of 154 commands over the 11 files that remain declared.
The two files that left the list are asserted now, and the four commands in
them that no test had reached are executed in the merged coverage by the six
new unit cases, which are also the six cases each edition gained over the
2026-10-07 gates. The 80 percent threshold was unchanged. Each ten-task
workflow completed with zero errors and two warnings from deliberately mocked
evidence-copy failures in the runner's unit tests, and each edition skipped
the mounted-volume case and the audit-rule read that needs an unavailable
privilege. The gates ran on the host while the installed-package pass used
the lab; they touch neither the lab nor its fixtures, and the pass used a
pinned copy of the package outside the build output.

## Observations

- A remote prompt goes to the host of the runspace that opened the session,
  not to the runspace that runs or receives the command. A job blocked on the
  prompt and received in a runspace without a user interface still asked the
  host of the console that opened the session, so an interactive run would
  have waited for a person. The confirmation case therefore opens its own
  session from a runspace without a user interface, and arms and returns
  member coverage for it under its own name.
- Such a session starts with remote debugging off, so no coverage breakpoint
  can be set in it. The first built pass stopped on exactly that in its
  Desktop coverage edition, which the focused runs, without coverage, could
  not show. The case now enables remote debugging on the session before
  arming coverage, and a focused Desktop run with member coverage armed proved
  that the confirmation's throttle line is recorded.
- Arming member coverage left the member session stopping on every error:
  `Enter-WindowsAccessControlMemberCoverage` set `$ErrorActionPreference` to
  `Stop` in a script block that a session runs at its top level, so the value
  persisted. Member suites therefore stopped on every error in the Desktop
  coverage pass and continued in every other pass. `a572d3d` corrects the
  harness, as recorded under [Harness correction](#harness-correction). The
  confirmation case still states `Continue`, so it does not depend on the
  preference of the session it runs in.
- A runner started with `-File` that sets `$ErrorActionPreference = 'Stop'`
  at its top level sets the global preference, which module functions
  inherit. The degraded enrichment error then stops the command, as a caller
  who stops on every error asked; with the default `Continue` the rules are
  returned with the error. The enrichment cases state `Continue`.
- The first confirmation prototype, which stopped a job that was blocked on
  the prompt and then wrote again in the same session, left the share's
  description empty with its DACL unchanged; its own error handling hid the
  failing step. The marker was restored. Four controlled replays, stopping the
  blocked job with and without a following write in each edition, wrote
  nothing until the following write, kept the description and the session's
  state, and released the target lock. The cause is not established, and the
  shipped case never stops a pending write.

## Cleanup and restoration

Before anything was removed, all evidence files on `F1ADC1` and `F1AFile2`
matched their host copies, both controllers answered signed and sealed
Kerberos LDAP, ten marked baseline objects remained with no leftover target,
the member fixtures were ready with the share's marker, and every directory,
KDC, DNS, ADWS, WinRM, and CA service ran. The runner's marker then decided
what was removed: the three payload roots, the marked `0.3.0` installation,
the six verified console logs, and both DSC stagings with their copied
evidence. The coverage plans of the two focused coverage runs were removed
after their contents were confirmed. A byte and ACL inventory of every module
path on `F1ADC1`, `F1DC1`, `F1AFile1`, and `F1AFile2` shows no difference in
any path, length, hash, security descriptor, reparse flag, or file time from
the state the 2026-10-07 follow-up left.

The prototypes of this round staged their module in their own `wac07`
directories, removed afterwards, and restored the share after each run. The
one described under Observations left the share's description empty; the
marker was restored before any pass ran.

At the maintainer's request, checkpoint `wac07-pre-livegaps-83cd16fa` was then
to be removed and `wac07-pre-938bdff-098b3392` kept. AutomatedLab's
`Remove-LabVMSnapshot` removes a checkpoint together with its children, and
the newer checkpoint was a child of the older one, so on ten VMs both were
removed; on the other three neither was. With the maintainer's agreement, a
new checkpoint, `wac07-after-bad1302-9d9776ca`, was taken on all thirteen
VMs, and the old checkpoints on the three were removed one at a time with
Hyper-V's own removal, which merges each into its child. All thirteen VMs keep
running with that one checkpoint, and the protocol-level readiness checks
passed after each step. The new checkpoint captures the lab after this round,
not before it.

## Harness correction

At the maintainer's request, the harness defect under Observations was then
corrected test-first in `a572d3d`, on the same branch. The remote block of
`Enter-WindowsAccessControlMemberCoverage` now runs its body in a child scope
that receives the values as parameters, so the `Stop` preference it sets ends
with the call, while the global list of armed breakpoints still outlives it.
The module itself did not change.

- A unit case runs the block at the top level of a separate runspace, as a
  member session does, and asserts one armed location and an unchanged
  `Continue` preference. It failed with `Stop` against the previous harness
  in both editions and passes after the change. The lab unit folder passes
  97 of 97 in each edition, PSScriptAnalyzer 1.25.0 reports nothing in the
  three changed scripts, and the QA specification and suite-identity tests
  pass.
- A live probe opened a member session from `F1ADC1` to `F1AFile1` and armed
  all 8,504 locations in each edition. With the previous harness the
  session's preference was `Stop` afterwards, and a non-terminating error
  ended the next call; with `a572d3d` it stayed `Continue`, and the call
  reached its next statement. The probe's staging was removed.
- GitVersion 5.12.0 computed the same `0.3.0-record-post-rele0001`, and a
  detached `pack` built 22 tasks with zero errors and zero warnings. The root
  module is byte-identical to the build of `bad1302`; the manifest differs
  only in the new release note.

| Artifact | SHA-256 |
| --- | --- |
| Root module, unchanged | `A9671FD086456978E4CE0CB5E01270B201C56FE7C1305BF7B77B9B9FB0E921CA` |
| Module manifest | `CF62149AB6151C8E8F51C023E0AFCA2CC9D20CB38AEF2A6EFFE41E6D6CA5D1FD` |
| Package, `WindowsAccessControl.0.3.0-record.nupkg`, 276,413 bytes | `89D45C0545A3EA9B2332C3469825191D828EE0C07797356F929B8E89B0B8B5A8` |
| Lab coverage | `E67DAAC331BFF1B8E80E2975FFCD284A61BB976385E2B9A6F1C5785F5F33554C` |

| Gate | Passed | Failed | Skipped | Cleanup or coverage | Completed UTC |
| --- | ---: | ---: | ---: | --- | --- |
| Built module, Desktop with coverage | 109 | 0 | 0 | Eight ready entries | 07:50:57 |
| Built module, Core | 109 | 0 | 0 | Eight ready entries | 07:59:19 |
| Local Core 7.6.6 | 1,938 | 0 | 2 | 91.26% asserted | 08:17:52 |
| Local Desktop 5.1.26100.33438 | 1,893 | 0 | 2 | 90.53% asserted | 08:40:51 |

The built pass used the payload root `C:\wac07-built5-a572d3d`. Its Desktop
edition is the only edition of a pass that runs the corrected code, because
member coverage is armed only where coverage is collected. The four member
suites that arm it, certificate private key, Task Scheduler, SMB share, and
foreign principal, passed there under the same error preference as in every
other pass. The coverage document measures the same 3,885 of 8,504 commands,
1,712 of them reached only in a member session, with the same missed and
covered counts on each of its 7,687 lines; it differs from `E0203097…97CA`
only in its two timestamps. The confirmation session again returned its hits
under its own name. Both local gates imported that document, reported
`Domain-lab evidence merged: yes`, and each gained exactly the new unit case
over the `bad1302` gates; domain-lab-only coverage stays at 100 percent, 154
of 154.

Readiness was proven at the protocol level before and after the pass, as for
`bad1302`. Before anything was removed, the guest evidence matched its host
copies, the fixtures and the directory baseline were ready, and both
installations on `F1ADC1` matched their state before the pass in root-module
hash, file count, write time, and ACL. The runner's marker then decided what
was removed: the payload root and its two console logs. After cleanup, the
inventory of every module path shows no difference in any path, length,
hash, or security descriptor from the state after this round's earlier
cleanup, and all thirteen VMs keep running with the one checkpoint
`wac07-after-bad1302-9d9776ca`.

The installed-package pass and the DSC-engine gate were not repeated, as an
agent decision for the maintainer's review: the installed pass collects no
coverage, so the corrected code does not run in it, and the DSC gate does
not load the lab harness, while the module bytes both test are unchanged. No
new checkpoint was taken, because the pass left the fixtures, the baseline,
and every module path as they were before it.

## Retention and remaining gates

Private evidence is retained under administrator `%TEMP%` in
`wac07-livegaps-83cd16fa7a4645cf95066e8e92330c0f`, in the profile's base TEMP
directory. It holds the pinned candidate files of `938bdff`, `bad1302`, and
`a572d3d`, the GitVersion download and its outputs, the readiness
inspections, inventories, checkpoint identity, native exit markers, raw
console logs, per-pass reports, the coverage documents, the focused green and
red results, the changed module the red runs used and the script that made
it, the prototypes and harness probes with their evidence, and the local test
results. Raw evidence is not sanitized for publication.

All requested acceptance gates for `bad1302` and for the harness correction
`a572d3d` are closed. A stable release still requires explicit authorization
to merge, tag, push, or publish.
