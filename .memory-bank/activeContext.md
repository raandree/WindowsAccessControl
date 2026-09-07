---
status: current
last-verified: 2026-09-07
owner: software-engineer
source: current task evidence
---

# Active context

## Current task

Reacceptance of the corrected `f5731f1` candidate is complete on
`ai/test-gap-audit`. All requested lab, installed-package, DSC, and fresh local
coverage gates passed. The module bytes remain identical to the independently
approved FIND-001 correction. The next step is the normal versioned release
workflow, only after explicit user authorization. No merge, tag, publication,
push, or git remote mutation is authorized or was performed.

## Current acceptance evidence

- Four full lab passes: built Desktop/Core and installed Desktop/Core each
  passed 95 tests, zero failed or skipped, with eight ready cleanup entries.
- Isolated Desktop DSC engine: five passed, zero skipped, including both actual
  engine invocations; its temporary machine-module installation was removed.
- Fresh local Core 7.6.5: 1,806 passed, zero failed, two environment skips,
  91.15 percent asserted coverage, completed at 18:35:18 UTC.
- Fresh local Desktop 5.1.26100.33296: 1,761 passed, zero failed, two environment
  skips, 90.41 percent asserted coverage, completed at 18:52:19 UTC.
- Both local ten-task workflows imported the exact fresh lab coverage hash;
  the 80 percent threshold was unchanged. Their two warnings each were from
  intentionally mocked evidence-copy failures. The mounted-volume and
  unavailable SACL-read privilege skips remain disclosed.
- Original installed module: all four original file hashes and directory ACL
  restored. Both controllers passed signed/sealed Kerberos LDAP after testing;
  zero targets remained and ten marked baseline objects were ready.
- All 38 guest evidence files matched host copies before the two run-owned
  remote staging directories were removed. No test console, member module
  staging, or temporary HTTP.sys binding remained. All thirteen VMs and
  checkpoints `wac-pre-f5731f1-b1fe0b1f` remain; no lab replacement was needed.
- All host, guest, and local terminal markers are zero. The processes exited
  and event-based monitoring finished. Do not restart the completed run.

Private host evidence is under administrator `%TEMP%` in
`wac-reaccept-f5731f1-b1fe0b1f50b042dd8a8b69223ed64375`. The
[reacceptance record](../docs/lab-reacceptance-2026-09-07.md) is the shareable
summary; raw logs and installation inventories remain private. The host
AutomatedLab wrapper rejected `ScriptFileName`, so the private driver used
validated persistent PSSessions and the unchanged console entry point.

Fresh lab coverage SHA-256 is
`D4A71389F9539CF05D4BBA5FFA8F318407D7A26E2A116B2E0EBC8D050EBC49AE`.
The configured coverage path contains this accepted document; the prior file
was preserved separately. No old lab coverage was reused for the new candidate.

## Corrected candidate

FIND-001 is resolved on `ai/test-gap-audit`. The source change replaces only
the redundant post-verification CNG descriptor read with the already verified
`$storedBytes`; non-enumerating output, critical-binding checks, verification,
and rollback remain unchanged. A fresh independent review approved the final
source and regression with no findings and no Blocker or Major.

The newline-only FIND-002 remains deferred and non-blocking. Prior packages and
lab evidence remain historical proof for their original hashes; the current
reacceptance establishes the corrected candidate's validation.

## FIND-001 verification

- Red: PowerShell 7 ran the new real-key regression against `fd07051`; helper
  read three raised the injected failure after an unmocked read confirmed the
  requested DACL was stored. Test cleanup had already verified key deletion.
- Green: the focused regression passed once in Core 7.6.5 and once in Desktop
  5.1.26100.33296 with zero skips. It asserts exactly two helper reads, exact
  returned bytes, a non-equivalent candidate, independent stored-DACL
  equivalence, and cleanup.
- The full 52-test CNG mutation file passed with zero failures or skips in each
  local edition. The focused live CNG mutation passed on `F1AFile1`; its
  descriptor returned byte-for-byte to SHA-256
  `473155193E7061B6357A560792023B2519B91B7349EB7701F13569541E933676`,
  and its HTTP.sys binding and staging directories were removed.
- Full local Core passed 1,806 tests with two environment skips and 83.00
  percent asserted coverage. Full local Desktop passed 1,761 tests with the
  same skips and 80.81 percent asserted coverage. Both explicitly report
  `Domain-lab evidence merged: no`.
- PSScriptAnalyzer 1.25.0 found nothing in the changed source or test. The built
  module SHA-256 is
  `A8E433469F06D54F7B71796A2DA1F6589F8705C3141641BD2EDEE589271D94D7`.
- The 22-task pack passed without errors or warnings. Package SHA-256 is
  `D93B2644B31A38B37F9FAC08DBD1D28C85AF8AD452D81E1428E0A3054530588C`,
  and its root module matches the tested module byte-for-byte.
- Private evidence is under
  `%TEMP%\wac-find001-6cf68f013c3948d0919d0f774a10f6b4`. The prior
  `%TEMP%\wac-acceptance-5991673-884f827956f442e0974735805d7d0d0c`
  directory remains unchanged.

## Prior candidate acceptance

The [prior acceptance record](../docs/lab-acceptance-2026-09-07.md) retains the
earlier candidate's hashes, fixture cleanup failure and repair, recovery, and
completed gates. Its private artifacts remain under
`%TEMP%\wac-acceptance-5991673-884f827956f442e0974735805d7d0d0c`.
Keep the historical failure separate from the successful rerun. Neither its
module hash nor its older coverage substitutes for the current reacceptance.

## Handoff and limits

[Reacceptance record](../docs/lab-reacceptance-2026-09-07.md) records the current
four-pass lab evidence, restoration, and final cross-edition coverage gates.
[Audit record](../docs/test-gap-audit-2026-09-06.md) contains the confirmed
findings, previous audit-host validation, and specific residual risks. The
[lab checklist](../tests/Lab/acceptance-checklist.md) covers a fresh payload,
both editions, an installed-package pass, evidence collection, and rollback.
Do not claim atomic LDAP writes, exhaustive native fault injection, or live
validation from unit tests. The final redundant CNG post-write read is a
resolved control-flow reliability defect (FIND-001); its full domain-lab,
installed-package, and current local coverage gates are complete. A properly
versioned release workflow still needs authorization. Focused reviews are
complete, but their outcomes
are not unconditional release approval. The original review ledger remains in
administrator TEMP under `wac-security-review-ce8512135436429ba24194450bba4877`.

## Previous verified milestone

Wiki publication is closed: `830a909`, hosted run `34055979655`, and
`0.2.0-preview0002` passed the standard Ubuntu publication workflow. Keep the
standard task and runner split; no local publisher override is needed.
