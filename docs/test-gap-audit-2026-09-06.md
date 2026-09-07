# Test Gap Audit

Date: 2026-09-06. Scope: source, tests, and preparation for the next disposable
domain-lab acceptance run. This is a full-tree inventory and risk-directed
behavioral review, not an exhaustive proof that no defects remain.

## Method and scope

- Parsed all 294 source scripts and 186 test/support scripts present at the
  start of the audit, approximately 60,000 lines in total.
- Compared the test-call inventory and requirement traceability with the
  controlling mutation, identity, persistence, native-lifetime, DSC, and
  acceptance-runner paths. Dynamic contract tests and indirect coverage were
  not classified as missing merely because a direct call was absent.
- Reviewed the embedded native interop implementation separately. Pester
  command coverage does not measure branches inside its compiled C# code.
- Added deterministic regressions before changing production behavior. Used
  isolated processes, real in-memory security descriptors, disposable files,
  and mocked directory or lab transport boundaries.
- Prepared two additional live AD cases in the existing fixed-order suites.
  No domain-lab operation was performed during this audit.

The per-file parse reported unresolved sibling types in 21 class files. The
merged-module build, import, and test gates are the authoritative checks for
those files; they are not 21 independent source syntax defects.

## Confirmed findings

| Severity | Finding | Resolution and regression |
| --- | --- | --- |
| Major | An escaped comma could make an object outside the allowed OU pass a textual suffix check. | Walk real parent-DN components with the existing escape-aware parser. Ten boundary cases include three previously failing inputs. See [containment tests](../tests/Unit/Private/Test-WindowsADDistinguishedNameWithinBase.Tests.ps1). |
| Major | AD restore discarded the recorded object GUID between preparation and the public setter, permitting distinguished-name reuse in that interval. | Carry `ExpectedObjectGuid` through the setter and batch prevalidation. Retain a name-reuse regression and a positive controller-switch case in [enterprise backup tests](../tests/Unit/Private/WindowsEnterpriseBackupRecord.Tests.ps1). |
| Major | Shared exact ACE removal could remove a different callback or object ACE with matching SID, flags, mask, and qualifier. | Compare the complete native ACE, including type, object GUIDs, and opaque payload. Five DACL/SACL cases failed before the fix. See [exact-removal tests](../tests/Unit/Private/Invoke-WindowsAclRuleMutationEnterprise.Tests.ps1). |
| Major | DSC integration cleanup could delete an existing installed module after setup refused to overwrite it. | Reserve the test-owned directory, track ownership, and restore the environment in `finally`. Three isolated lifecycle cases cover refusal, partial copy, and cleanup failure in [fixture safety tests](../tests/Unit/DSC/DscLcmFixtureSafety.Tests.ps1). |
| Major | The host lab runner could accept no selected editions, coerce a missing exit code to zero, or emit stale local evidence after an artifact download failed. | Reject empty selections and missing exit status; fail on evidence or requested coverage collection errors. Cross-edition checks also caught the empty-console-output pipeline behavior in Windows PowerShell 5.1. See [host runner tests](../tests/Unit/Lab/Invoke-WindowsAccessControlLabAcceptance.Tests.ps1). |
| Major | A coverage-finalization error could leave retained guest evidence marked `Passed` despite a failing process. | Include finalization errors in the retained status. A regression runs all mocked suites successfully, fails finalization, and requires `Failed` evidence in [harness tests](../tests/Unit/Lab/WindowsAccessControl.DomainLab.Tests.ps1). |
| Minor | Atomic backup-write tests omitted concurrent destination creation and sharing violations. | Added characterization tests proving original content survives and temporary artifacts are removed. No production change was needed. See [backup-write tests](../tests/Unit/Private/Write-WindowsSecurityDescriptorBackupFile.Tests.ps1). |

## Validation record

Added 30 local test cases and two live cases. All 41 rebuilt-artifact security
checks pass; changed-script analysis reports no findings across 17 scripts.
The manifest retains 105 public commands and 20 DSC resources.

PowerShell 7.6.5: 1,802 passed, zero failed, two environment skips. The
coverage gate initially identified the newly exercised AD setter as wrongly
classified lab-only. Removing that exclusion expands asserted scope; rerunning
`Assert_Merged_Code_Coverage_Threshold` passes at 82.74 percent, with the
80 percent threshold unchanged. Whole-module coverage is 80.04 percent, and
no domain-lab coverage was merged.

Windows PowerShell 5.1: 1,755 passed, two failed, and two environment skips.
The full Desktop run encountered two actual DSC-engine invocation failures:
the local WS-Management endpoint is unavailable. Read-only inspection confirms
WinRM is stopped with manual startup, and `Test-WSMan localhost` fails with
the same connection error. MOF compilation, resource discovery, and direct
DSC resource tests passed. The two engine cases remain mandatory lab checks;
no service, listener, firewall, assertion, or skip policy was changed.
The Desktop coverage gate did not run after these failures; no passing
Desktop release-acceptance claim is made.

Raw logs, full Pester results, NUnit results, coverage, and the initial
source/test inventory are retained in administrator TEMP under
`wac-audit-evidence-20260906-fa1a1b90ee55445daa9608617d4c1a19`.
On 2026-09-07 the user authorized committing and pushing the candidate on
`ai/test-gap-audit` for testing on the other Hyper-V host. The blocked
validation gates remain open; the handoff is not release approval.

`build.ps1 -Tasks pack` passed 22 tasks with zero errors or warnings. The local
candidate is `output/WindowsAccessControl.0.0.1.nupkg` (275,495 bytes). This is
the local fallback version, not a new published release. Archive inspection
confirmed the root module, manifest, format data, MAML help, and all 20 DSC
help files. The packaged module is byte-identical to the tested artifact.

| Artifact | SHA-256 |
| --- | --- |
| NuGet package | `9C8E22B13891CB52CACBE6EB7A226D8A108931604964FFEB7ED2E68127A78743` |
| Tested and packaged module | `A70F3C1E5347C8196D5A9656F785C91B9008316E54778C0A3ED389D2DAEF019D` |

All eight live suites discover successfully: 95 tests, including the two new
cases. Discovery executes no lab setup and is not a live-test pass.

## Remaining risks and lab priorities

| Priority | Risk or unverified boundary | Required evidence |
| --- | --- | --- |
| Before release | The changed containment, identity, and exact-removal paths affect security decisions. | Independent review is recommended with `review: on`; no independent review was requested or dispatched. |
| Next lab run | Escaped-name containment and explicit expected-GUID rejection must also hold against real LDAP objects in both editions. | Run the two new cases plus all eight acceptance suites using the [lab checklist](../tests/Lab/acceptance-checklist.md). |
| Next lab run | Real provider, COM, LDAP, token, SACL, and cleanup behavior cannot be inferred from unit mocks. | Retain both edition results, every suite cleanup ledger, and current-build coverage. Exercise the installed package separately. |
| Follow-up | Read-then-write guards are not atomic transactions. The final LDAP revalidation and ModifyRequest remain separate operations; two controllers can still accept competing writes. | Keep the existing replication/outage tests, pin one controller, and do not claim transactional restore or global concurrency protection. |
| Follow-up | Callback/object-ACE byte identity is covered in memory, but store-specific persistence of unusual ACEs is not established by those tests. | Use disposable targets and an independent native descriptor read before admitting any additional ACE/store combination. |
| Follow-up | Native allocation failures, interrupted writes, rollback failures, abrupt process cancellation, and handle/resource growth are not exhaustively fault-injected. | Dedicated failure-injection and soak runs, with before/after descriptor and resource inventories. |
| Known lab limit | The lab has no read-only controller, second site, or selective-authentication trust profile. | Do not infer support from the current topology; see [known gaps](../tests/Lab/README.md#known-gaps). |

The source scan also identified a redundant CNG descriptor read after a
successful verified write in
[Set-WindowsCngKeySecurityDescriptor](../source/Private/Set-WindowsCngKeySecurityDescriptor.ps1).
A failure of that last read could report an error after the DACL changed.
Provider fault injection for this path was not performed; this remains a
specific review and lab follow-up, not a verified failure or a fixed claim.

## Compatibility and rollback

`ExpectedObjectGuid` is an optional, backward-compatible AD setter parameter.
Unified restore supplies it automatically. It checks object identity, not DACL
freshness or multi-controller convergence. No backup schema or manifest version
was changed.

The fixture and runner changes deliberately turn previously misleading success
paths into failures. Resolve the missing evidence or failed cleanup instead of
bypassing the guard. Keep prior artifacts for comparison, but never count them
as evidence for the current run.

Run only in the disposable lab. Take a checkpoint before acceptance, preserve
raw diagnostics in administrator TEMP, and share only redacted evidence.
Do not redeploy, remove an existing lab, publish, or push as part of this
preparation without separate authorization. The branch handoff was separately
authorized on 2026-09-07; no lab operation or publication was requested.
