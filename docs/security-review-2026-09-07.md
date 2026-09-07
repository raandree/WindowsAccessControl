# Independent security review: 2026-09-07

Independent review requested with `review: on` after the
[lab acceptance](lab-acceptance-2026-09-07.md). The reviewer found no Blocker
or Major issue in the reviewed candidate. One Minor CNG reliability defect
and one newline Nit remain open. This is not unconditional release approval.

## Findings

### FIND-001: Minor - redundant read after a verified CNG write

Location:
[Set-WindowsCngKeySecurityDescriptor.ps1](../source/Private/Set-WindowsCngKeySecurityDescriptor.ps1#L161).
This is existing code in the explicitly requested additional review scope,
not a regression introduced by the audited commits.

The function writes the DACL, reads it back into `$storedBytes`, and verifies
that it matches the requested DACL. It then performs another provider read in
the return statement, outside the write/verification error handler. If that
last read throws, the public operation reports an error after the DACL was
already changed and verified. The earlier rollback handler is not entered.

All three public callers discard this helper's return value. The no-write
path already returns its previously read bytes without an additional read.
The unnecessary failure point is therefore not needed by the current callers.

The reviewer and controller confirmed the control-flow defect by inspection.
Neither performed new provider fault injection during this review. Existing
live success-path acceptance does not prove behavior when only that read fails.

Recommended correction: return the already-verified `$storedBytes`. First add
a regression that allows the initial and verification reads but rejects a
third read, exercises a real successful disposable-key write, and verifies
both returned bytes and stored DACL. Preserve tests for write/verification
failure and rollback. A code change still requires rebuild and validation;
the proposed correction is not declared risk-free because it is small.

Disposition: accepted, open. It does not invalidate the completed acceptance
of the audited diff. Resolve it and its regression evidence before stable
release approval. No runtime edit was made during this review.

### FIND-002: Nit - missing final newlines in two tests

Locations:
[DscLcmFixtureSafety.Tests.ps1](../tests/Unit/DSC/DscLcmFixtureSafety.Tests.ps1)
and
[Test-WindowsADDistinguishedNameWithinBase.Tests.ps1](../tests/Unit/Private/Test-WindowsADDistinguishedNameWithinBase.Tests.ps1).

Byte inspection confirms that both files lack a final newline. This violates
the text-file convention but does not change test behavior.

Disposition: accepted, deferred as non-blocking formatting cleanup. No test
file was modified during the review.

## Scope and assessment

- Base: `3321350f014dd37809b9d84dcbf607961c2eacf0`, local `main`.
- Candidate: `358651e0220e9c5027dad934d4dad1c5589893d0` on
  `ai/test-gap-audit`; commits `5991673` and `358651e`.
- The independent `security-reviewer` ran in fresh context over the pinned
  diff, relevant neighboring implementations, and retained acceptance evidence.
- Additional scope: the CNG persistence helper, its public callers, nearby
  tests, critical-binding guard, and write/verification/rollback paths.
- No candidate code, installed package, or lab state changed during review.
  No full test suite or lab profile was rerun.

| Axis | Assessment |
| --- | --- |
| Design | Changed paths reuse existing parsers, target resolution, native ACE equality, and fixture-ownership patterns. |
| Correctness | No new issue found in escaped-DN containment, recorded GUID propagation, exact ACE removal, DSC fixture ownership, or fail-closed lab evidence. FIND-001 remains in the additional CNG scope. |
| Complexity | The containment and exact-removal changes remove duplicated decision logic without adding unnecessary abstractions. |
| Tests | Cross-edition regressions and live acceptance cover the changed boundaries. Third-read CNG fault injection remains missing. |
| Clarity | Names and errors distinguish immutable identity from descriptor freshness. FIND-002 is cosmetic. |

Recommendation: accept the audited changes from this review's perspective,
with the Minor correction tracked before stable release. An absence of severe
findings is not proof of complete security or approval of untested scenarios.

## Evidence and controller reconciliation

The reviewer inspected existing evidence rather than rerunning completed
gates. The [acceptance record](lab-acceptance-2026-09-07.md) remains the
authority for artifact hashes, test counts, coverage, and cleanup: four lab
passes of 95 tests each, five isolated Desktop DSC checks, 1,805 local Core
passes at 91.16 percent asserted coverage, and 1,760 local Desktop passes at
90.41 percent. The two local environment skips remain disclosed.

The controller verified the CNG handler boundary and three callers, checked
the newline findings, and reconciled these inaccuracies in the raw report:

- The diff changes five production files, twelve PowerShell test/support
  scripts, and one test harness module. The additional CNG helper is separate.
- The audit added 30 local cases; acceptance added three fixture regressions,
  for 33 local additions in the combined candidate, plus two new live cases.
- The fixture's pre-fix failures were successful-deletion bookkeeping and
  replacement creation failure. The original-deletion-failure case passed.
- Cross-domain and cross-forest principal scenarios were exercised by
  [ForeignPrincipalPermissions.Live.Tests.ps1](../tests/Lab/ForeignPrincipalPermissions.Live.Tests.ps1).
  Read-only controllers, a second site, and selective-authentication trust
  profiles remain outside the lab evidence; cross-trust coverage is not absent.
- The raw report's approximate CVSS number had no supporting vector and is
  not adopted. The evidence supports the stated Minor reliability finding,
  not a quantified vulnerability score or a risk-free correction.

The original report, pinned diff, brief, and disposition ledger remain in
private administrator `%TEMP%` under
`wac-security-review-ce8512135436429ba24194450bba4877`. The original report was
not edited after delivery. Its SHA-256 is
`CB95CEC45BC6EE1AF5726CC4B8AA877B18CA3745789D6BE5257C06E621E233FA`.
Only this reconciled review record is intended for source control.

## Remaining release limits

Resolve FIND-001 with failing-before/passing-after evidence before stable
release. Broader native-failure injection, interrupted rollback, cancellation,
handle-growth soak tests, and unusual-ACE persistence remain unproven.
Do not infer atomic or globally serialized LDAP writes from GUID validation
or the tested two-controller behavior.

The completed independent review closes the review obligation for the pinned
candidate, not these follow-ups. Any subsequent runtime correction changes
the candidate and must be validated before publication. No merge, publish, or
push was authorized or performed as part of this review.
