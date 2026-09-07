---
status: current
last-verified: 2026-09-07
owner: software-engineer
source: current task evidence
---

# Active context

## Current task

Lab acceptance from `5991673` on `ai/test-gap-audit` is complete. The current
user forbids lab redeployment or removal, merging into main, publishing, and
pushing. This acceptance is not stable-release approval.
The existing thirteen-machine Hyper-V lab is isolated on its internal switch.
Checkpoint `wac-pre-5991673-884f8279` covers every machine. Both fixture
controllers passed signed and sealed Kerberos LDAP queries; WSMan, RSAT,
Pester 5.7.1, both editions, and the renewable CNG template are available.

## Current acceptance evidence

- Private host TEMP folder:
  `wac-acceptance-5991673-884f827956f442e0974735805d7d0d0c`.
- Rebuilt package: 22 tasks, zero errors or warnings. All 25 module payload
  files match the package, including all 20 DSC resource help files.
- Package SHA-256:
  `3D2A97578B142B3131283AF5D519302CE90DB9A6B036B867C0914A2B96505CA7`.
- The rebuilt module retains the audited SHA-256
  `A70F3C1E5347C8196D5A9656F785C91B9008316E54778C0A3ED389D2DAEF019D`.
- Isolated Desktop DSC on `F1AFile2`: five passed, zero skipped, including both
  actual engine invocation cases. Guest and host exit markers are zero; NUnit,
  full Pester results, and independent machine-module cleanup evidence agree.
- Initial instrumented Desktop run failed after 95 passing test bodies. The
  new GUID-reuse test left an obsolete DN in the suite cleanup list; deleting
  that absent object terminated `AfterAll` and left eight disposable OUs.
  The retained overall result is correctly `Failed`, not an acceptance pass.
- Fixed only the test cleanup registration after successful GUID deletion.
  Added three lifecycle cases: two failed before the fix; all three now pass
  in Core and Desktop. Both changed scripts pass static analysis.
- Captured the remaining OU GUIDs, DACLs, and creation times before cleanup.
  Exact-identity cleanup restored both controllers and the ten-object harness
  baseline. No checkpoint restore, lab removal, or redeployment was needed.
- The focused live replication rerun passed all twelve tests with zero skips
  and both cleanup boundaries ready; `replication-focused.exit` is zero.
- The repaired four-pass sequence finished at 11:40:16 UTC with exit zero.
  Built Desktop/Core and installed Desktop/Core each passed 95 tests with zero
  skips and eight ready cleanup entries. Both new live regressions passed in
  all four logs. Every pass deployed a fresh payload. Records are
  `accepted-sequence.log`, `accepted-*.json`, and `acceptance-verification.json`.
- Final local Core passed 1,805 tests with zero failures and two existing
  environment skips. Asserted coverage is 91.16 percent; whole-module coverage
  is 91.10 percent. The accepted coverage document was imported byte-for-byte.
  Two expected warnings come from mocked evidence and coverage copy failures.
- Final local Desktop passed 1,760 tests with zero failures and the same two
  environment skips. Asserted coverage is 90.41 percent; whole-module coverage
  is 90.38 percent. The accepted lab coverage was imported byte-for-byte.
  Both local ten-task workflows have zero errors and two expected mocked-copy
  warnings. `local-gates.exit` is zero and `LOCAL-GATES-DONE` is recorded at
  12:08:04 UTC. No acceptance or local validation process remains; monitoring
  is stopped. Full results and logs are retained in the evidence folder.
- The management controller's original `0.0.1` installation was restored with
  all four original file hashes and the directory ACL unchanged. Its `0.2.0`
  installation was not replaced. All 25 installed candidate files matched the
  package before restoration. The reserved DSC
  staging, focused replication staging, and preservation directories are now
  removed after verified host evidence collection.
- Final lab checks: thirteen VMs running, thirteen rollback checkpoints, both
  controllers answering signed/sealed Kerberos LDAP, zero leftover targets,
  ten marked baseline objects, and domain/member readiness true. Directory,
  DNS, KDC, ADWS, WinRM, and CA services are running. No lab test process or raw
  payload log remains. The fresh `C:\WacRepo` payload and checkpoints remain.

## Handoff and limits

[Acceptance record](../docs/lab-acceptance-2026-09-07.md) records the current
four-pass lab evidence, fixture repair, and final cross-edition coverage gates.
[Audit record](../docs/test-gap-audit-2026-09-06.md) contains the confirmed
findings, previous audit-host validation, and specific residual risks. The
[lab checklist](../tests/Lab/acceptance-checklist.md) covers a fresh payload,
both editions, an installed-package pass, evidence collection, and rollback.
Do not claim atomic LDAP writes, exhaustive native fault injection, or live
validation from unit tests. The final redundant CNG post-write read remains a
specific, unverified failure-injection follow-up. Independent security review
is recommended; the user has not enabled independent review.

## Previous verified milestone

Wiki publication is closed: `830a909`, hosted run `34055979655`, and
`0.2.0-preview0002` passed the standard Ubuntu publication workflow. Keep the
standard task and runner split; no local publisher override is needed.
