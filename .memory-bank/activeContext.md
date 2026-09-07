---
status: current
last-verified: 2026-09-07
owner: software-engineer
source: current task evidence
---

# Active context

## Current task

Audit the source and tests for missing edge cases and prepare the next live lab
run. Work is on `ai/test-gap-audit`. On 2026-09-07 the user explicitly requested
a commit and push of the candidate for testing on the other Hyper-V host.
The initial inventory covered 294 source and 186 test/support scripts.

## Implemented changes

- AD containment follows real parent-DN components, not escaped suffixes.
- Restore carries the recorded GUID through the optional
  `Set-ADObjectSecurityDescriptor -ExpectedObjectGuid` guard.
- Exact native ACE removal compares complete type and payload identity.
- DSC integration cleanup removes only directories the fixture created.
- Lab acceptance rejects empty edition lists, missing exit status, failed
  artifact collection, and failed coverage finalization. Remote artifacts and
  console logs have per-run identities; empty output is safe in Desktop.
- Added 30 local regression/characterization cases and two live AD cases.
- Removed the now locally exercised AD setter from the lab-only coverage
  exclusion. The threshold remains 80 percent.

## Validation and current execution

- Rebuilt security slice: 41 passed. Changed-script analyzer: zero findings
  across 17 scripts. The manifest still exports 105 public commands.
- Final Core Pester: 1,802 passed, zero failed, two environment skips.
- Core coverage assertion rerun after correcting the exclusion: 82.74 percent
  asserted, 80.04 percent whole-module, no domain evidence merged.
- Full Desktop: 1,755 passed, two failed, two environment skips. Both failures
  are actual DSC-engine calls blocked by stopped local WinRM (manual startup).
  `Test-WSMan localhost` independently reproduces the connection failure.
  No service, listener, or firewall setting was changed; the tests are intact.
  Log: `%TEMP%\wac-validation-Full-Desktop-5663611df8104b0ab5fb72e88b6d0850.log`.
  Exit marker: `%TEMP%\detached-02fadd535fa745fa841138fb6b7723f2.exit`.
- Eight live suites discover 95 tests. Discovery is not live acceptance.
- Packaging passed 22 tasks with zero errors or warnings. Candidate:
  `output/WindowsAccessControl.0.0.1.nupkg` (local fallback version).
  Package SHA-256:
  `9C8E22B13891CB52CACBE6EB7A226D8A108931604964FFEB7ED2E68127A78743`.
- The packaged module is byte-identical to the tested artifact, with SHA-256
  `A70F3C1E5347C8196D5A9656F785C91B9008316E54778C0A3ED389D2DAEF019D`.
  Archive inspection confirms command help, format data, and all 20 DSC help
  files. Actual installed-package acceptance remains a lab obligation.
- Raw validation evidence is retained under administrator TEMP in
  `wac-audit-evidence-20260906-fa1a1b90ee55445daa9608617d4c1a19`.
- The user authorized a handoff commit and push despite the local Desktop DSC
  prerequisite blocker. This is not release approval: live acceptance and
  independent security review remain pending. No lab execution or publication
  is part of the handoff.

## Handoff and limits

[Audit record](../docs/test-gap-audit-2026-09-06.md) contains the confirmed
findings and specific residual risks. The
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
