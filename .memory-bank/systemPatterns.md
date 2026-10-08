---
status: current
last-verified: 2026-10-08
owner: software-engineer
source: repository evidence
---

# System patterns

The [accepted ADRs](../specs/decisions/README.md) control architecture; earlier
rationale: `git show 124a356:.memory-bank/systemPatterns.md`.
Commands bind inputs; adapters own validation, native lifetime, selected-section
persistence, and typed output. Descriptor editing is detached.
QA checks catalogs; requirement references alone do not prove behavior.
Containment compares real DN components, and restore must retain the recorded
GUID through every target-resolution stage. Exact native ACE removal compares
the full ACE, not only SID, mask, flags, and qualifier. Test cleanup and the lab
runner need an ownership record before deleting what they staged. Fixtures
release obsolete cleanup entries after successful deletion; passing test bodies
do not override a failed Pester container or cleanup ledger. Acceptance requires
a nonempty edition set, explicit exit status, fresh per-run artifacts,
and a failure status when coverage finalization fails. A newly exercised
lab-only source file moves into asserted coverage; the threshold is unchanged.
Completer helpers use instance context, not a worker-bound static context, and
their regressions compare completion before and after a real bounded batch.
Flexible-mask parameters stay untyped; completers expose accepted enum names
while the transformation attribute preserves raw and unnamed mask bits.
Raw logs stay in administrator TEMP; only redacted JSON is shareable evidence.
Avoid extra provider reads after successful verification: return the bytes that
were already verified, and fault the next read in a real-provider regression so
an error-after-persistence path cannot return unnoticed. JaCoCo identity checks
only source-file and line coordinates; when candidate bytes change without
moving a measured line, withhold prior lab coverage explicitly rather than
letting structural identity treat it as current evidence.
Fresh acceptance means candidate-bound payloads and evidence, not a rebuilt
lab. Reuse healthy marked fixtures under a checkpoint; verify installation
bytes/ACL restoration and evidence hashes before removing run-owned staging.
Directory reads reach LDAP only through `Send-WindowsADSearchRequest`, the seam
unit tests replace. A live guard that no lab identity can reach is injected
with a module-scope mock after the real read, and a prompt test opens its own
session from a runspace without a user interface, with remote debugging on so
coverage can be armed there. A script block sent to a persistent session runs
at its top level, so harness code that sets a preference there sets it in a
child scope.
Process wrappers must drain redirected output while a child runs; waiting for
exit before reading can deadlock on a large Git commit summary. Treat a publish
workflow as non-atomic and inspect every external destination before rerunning
after a late-stage failure.
Keep wiki publication on the standard imported Sampler task, not a local
override. Compare initial imports with incremental updates and compare runner
platforms before replacing a dependency. Package and test this module on
Windows; publish the prepared artifacts on Ubuntu as the DSC Community
reference pipelines do. Run `34055979655` verified this split on 2026-09-06:
the standard task published `0.2.0-preview0002` and its generated wiki.
Cache only immutable enum data and bounded rendered masks per module
instance, never descriptors or identity lookups. Binary ACE keys need ordinal
comparison and duplicate counts, load-bearing for Base64 identities that can
differ only in case. Measure real PowerShell code in fresh processes: ordinal
`Hashtable` indexing beat `[ref]` dictionary lookups. Check artifact hashes and
output checksums before medians, prefer an isolated row over a warm-up-bound
mixed one, and do not read helper gains as faster native I/O.

The numbered Memory Bank decisions 1 to 79 are listed in the
[decision log](topics/decision-log.md).
