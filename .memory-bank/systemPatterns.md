---
status: current
last-verified: 2026-09-07
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
the full ACE, not only SID, mask, flags, and qualifier. Test cleanup needs an
explicit ownership record before deleting a staged installation. Fixtures
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

| Decision | Summary |
| --- | --- |
| 1 | Use the canonical Memory Bank base |
| 2 | Use only in-box runtime APIs |
| 3 | Keep destructive ACL semantics explicit |
| 4 | Preserve descriptor sections |
| 5 | Use versioned, validated JSON backups |
| 6 | Keep destructive modes separately testable |
| 7 | Batch only after identity prevalidation |
| 8 | Make privilege gaps executable and explicit |
| 9 | Keep specifications authoritative and help beside code |
| 10 | Persist ACL protection with the selected ACL |
| 11 | Scope required privileges to operations |
| 12 | Rename to WindowsAccessControl |
| 13 | Share one binary descriptor engine |
| 14 | Keep the release local and testable |
| 15 | Use object-specific public and DSC surfaces |
| 16 | Bound parallel target execution |
| 17 | Normalize and verify registry targets before native calls |
| 18 | Keep ACL masks and objects explicit across editions |
| 19 | Skip semantically identical named-descriptor writes |
| 20 | Address the SCM through a scoped native handle |
| 21 | Keep service and SCM rights distinct |
| 22 | Pin one live process handle per PID operation |
| 23 | Retry process access without broadening token authority |
| 24 | Use one integrity-protected descriptor envelope |
| 25 | Validate and prepare the complete restore before writing |
| 26 | Make absence and backup replacement explicit |
| 27 | Keep aggregate backup writes singular |
| 28 | Make exact DSC identity object-specific |
| 29 | Normalize only system-derived ACL flags in DSC |
| 30 | Give rule-presence DSC exact ACE identity |
| 31 | Normalize NTFS rule masks through .NET |
| 32 | Scope explicit credentials to local impersonation |
| 33 | Use breakpoint coverage across PowerShell editions |
| 34 | Align native ACE metadata with managed rule enumeration |
| 35 | Gate enterprise expansion on a disposable domain lab |
| 36 | Build once and test the same artifact in GitHub Actions |
| 37 | Version symbolic lab evidence, not infrastructure identity |
| 38 | Mark, compensate, and explicitly delete lab keys |
| 39 | Address SMB shares through local provider authority |
| 40 | Bind Active Directory operations to strict LDAP authority |
| 41 | Require schema version 2 for enterprise targets |
| 42 | Verify Task Scheduler DACLs semantically |
| 43 | Keep caller callbacks in one runspace |
| 44 | Make unattended suite success explicit |
| 45 | Separate CNG inspection from mutation |
| 46 | Fail closed on an unloaded descriptor section |
| 47 | Keep a descriptor projection consistent with its native object |
| 48 | Never let a post-write step throw |
| 49 | Default to the typed parameter set for descriptor input |
| 50 | Name rights after the operation, per object type |
| 51 | Evaluate the whole service token before a Task Scheduler write |
| 52 | Reject ACE types the Task Scheduler store re-revisions |
| 53 | Make inheritance scope part of ACE identity when adding |
| 54 | Re-read and compare before a staged descriptor write |
| 55 | Emit batched worker output outside the dispatcher's catch |
| 56 | Degrade registry provenance instead of losing the rules |
| 57 | Enrich directory rules over the bound connection |
| 58 | Discover and pin one domain controller |
| 59 | Scope a directory rule mutation by both object GUIDs |
| 60 | Expand a stored generic bit before subtracting rights |
| 61 | Refuse a directory DACL that leaves nobody able to manage it |
| 62 | Compare against the staging read before a directory write |
| 63 | Disclose a deny removal before the operator commits |
| 64 | Pin the backup record version to the object family |
| 65 | Qualify an SMB canonical target with its owning computer |
| 66 | Match a restored directory object by GUID, not by server |
| 67 | Keep directory credentials out of desired state |
| 68 | Defer directory effective access on measured evidence |
| 69 | Qualify a Task Scheduler target with its owning computer |
| 70 | Compare a Task Scheduler desired state semantically |
| 71 | Gate a suite on the Pester run result, not its failure count |
| 72 | Key the private-key binding gate on the key, not the certificate |
| 73 | Refuse a new deny ACE and any non-plain ACE on a private key |
| 74 | Compare a private-key ACE by type and payload, not by qualifier |
| 75 | Tag the GitHub release before the Gallery publish |
| 76 | Complete argument values from a class in the module |
| 77 | Build an NTFS rule through a mask-range helper |
| 78 | Refuse a path that does not name one canonical target |
| 79 | Address the object the caller named, per object family |
