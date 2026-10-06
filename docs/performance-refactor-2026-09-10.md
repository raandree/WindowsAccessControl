# Performance refactor evidence

This pass reduces repeated work in the shared descriptor helpers and all seven
batch adapters. It preserves the 105 public commands, 20 DSC resources, runtime
dependencies, selected-section persistence, native resource ownership,
confirmation behavior, and target locking. It does not rewrite every file or
claim that every workload is faster.

The measurement, validation, and identity sections dated 2026-09-10 are
historical: they compare against `5991673`. The change was later ported onto
the integration branch and measured again; see the
[2026-10-06 addendum](#addendum-re-measurement-on-2026-10-06).

## Changes

- Cache immutable rights-enum metadata per module instance and at most 128
  rendered masks per enum. Additional masks are calculated normally. Security
  descriptors, account lookups, tokens, and handles are not cached. Each
  parallel worker runspace imports its own module instance, so a parallel
  batch warms the cache once per worker; the gain is for masks repeated within
  one runspace, such as many rules on one target or a sequential batch.
- Apply the NTFS access and audit SID filters before account translation and
  rule formatting. Resolve requested identities as before, and use a SID set
  for membership checks.
- Count retained Active Directory ACE identities with ordinal hash lookups
  instead of searching and shrinking a list. Preserve full binary identity,
  duplicate counts, and the original order of removed ACEs. The comparer has to
  stay ordinal: those identities are Base64, where two distinct entries can
  differ only in letter case, so a case-insensitive map would merge them and
  report a removed entry as retained.
- Sort CNG comparison keys using ordinal .NET array sorting. Keep ordered
  desired-state comparison distinct from unordered post-write comparison. Every
  component of a private-key ACE key is a SID string, a decimal or uppercase
  hexadecimal number, a lowercase GUID, or a fixed literal, each formatted
  deterministically, so two keys cannot differ only in case and the ordinal
  sort is defensive rather than a behavior fix.
- Replace pipeline-based metric-parameter counting with Boolean checks and
  replace per-target parameter-copy loops with shallow hashtable clones in
  NTFS, registry, service, process, SMB, AD, and Task Scheduler adapters.

## Historical measurements, 2026-09-10

These figures are kept for comparison; the current ones are in the
[addendum](#addendum-re-measurement-on-2026-10-06).

Measured on Windows build 26200 with eight logical processors, PowerShell
7.6.5 and Windows PowerShell 5.1.26100.9168. The baseline artifact matches the
original implementations of all 13 changed functions at commit `5991673`.
Each artifact ran in a fresh process without concurrent tests or builds.

The [descriptor benchmark](../tests/Performance/Measure-DescriptorProcessingPerformance.ps1)
warms each workload, alternates workload order, records every elapsed time and
checksum, and reports medians. Ordinary rows use 50 operations, seven measured
runs, and 256 ACEs where applicable. Core CNG uses an isolated 200-operation,
nine-run comparison because the mixed-workload runs were noisy. Candidate ran
before baseline in that isolated comparison. All paired output checksums match.

| Workload | Edition | Before (ms) | After (ms) | Time reduction |
| --- | --- | ---: | ---: | ---: |
| Repeated rights display | Core | 3.56 | 1.20 | 66.4% |
| Repeated rights display | Desktop | 4.10 | 2.69 | 34.4% |
| Removed-ACE calculation | Core | 702.65 | 250.35 | 64.4% |
| Removed-ACE calculation | Desktop | 738.91 | 39.63 | 94.6% |
| Single-target dispatch | Core | 8.30 | 7.11 | 14.4% |
| Single-target dispatch | Desktop | 21.65 | 12.18 | 43.8% |
| CNG equivalence, isolated | Core | 864.71 | 742.22 | 14.2% |
| CNG equivalence | Desktop | 1224.83 | 1122.51 | 8.4% |

The [NTFS benchmark](../tests/Performance/Measure-NtfsBatchPerformance.ps1)
uses 256 disposable files, seven runs per mode, and a parallel throttle of
eight. Its averages were effectively unchanged for sequential owner reads:
477.24 to 478.01 ms on Core and 543.91 to 548.23 ms on Desktop. Parallel owner
reads changed from 531.58 to 520.40 ms on Core and 647.86 to 625.82 ms on
Desktop. These small differences are not evidence of a general I/O speedup.

Rights-cache results represent repeated-mask workloads, not cold or mostly
unique masks. Pure-helper timings do not measure LDAP latency, CNG persistence,
or every public command. There are no timing assertions in the unit suite.

## Historical validation, 2026-09-10

- Added nine regression and characterization cases in existing test files.
  Both NTFS filter tests failed before the change because excluded accounts
  reached conversion, then passed after rebuilding. The other cases pin enum
  isolation, cache overflow, duplicate ACEs, removal order, and exact payloads.
- Full Core Sampler `test`: 1,811 passed, zero failed, two environment skips.
  Asserted coverage is 82.64% against the unchanged 80% gate. Whole-module
  coverage is 79.96%; no domain-lab evidence was merged. The final packaged
  module was used, and the module-identity gate observed one compilation.
- Full Desktop QA, unit, and integration run: 1,764 passed, two failed, two
  environment skips. Only the two DSC-engine calls failed, both with
  `HRESULT 0x80338012` because local WinRM is stopped. This is the previously
  recorded host prerequisite blocker, not a green Desktop acceptance result.
- After the final analyzer annotation and packaging, all 145 focused tests
  passed in each edition against the exact packaged module bytes.
- PSScriptAnalyzer 1.25.0 checked the entire source tree and changed tests.
  Changed files have zero findings. Three warnings in unchanged helpers match
  their `HEAD` versions: callback use of `DomainSid` in
  `ConvertTo-WindowsADAbsoluteSddl`, and `ShouldProcess` heuristics for the
  in-memory helpers `New-NTFSFileSystemRule` and
  `Remove-NTFSFileSystemRuleSpecific`. Standalone DSC analysis requires the
  compiled `WindowsAccessControlDscReason` type to be registered in that
  isolated analyzer process.
- Sampler `pack`: 22 tasks passed, zero errors or warnings. Archive inspection
  confirmed matching module bytes, all 20 DSC help files, and MAML help. Source
  and built manifests validate. The local version remains the existing
  GitVersion fallback `0.0.1`; this is not a published release.

## Historical artifact identity, 2026-09-10

| Artifact | SHA-256 |
| --- | --- |
| Original module | `A70F3C1E5347C8196D5A9656F785C91B9008316E54778C0A3ED389D2DAEF019D` |
| Final module | `358158116D14787E5EF82D3C129D987F2587A973D7671E8ECFDC012900428B16` |
| Final package | `8197CC5A89C12D571628E24D3A6D9EC06ED310ED796968E694B822C26FBFD8E3` |

Raw logs, NUnit results, coverage, before/after JSON measurements, and the
comparison receipt remain in the administrator's local
`%TEMP%/wac-performance-c2da0d57f81549c186fae225009431f1` directory. They are not
part of the repository or lab payload.

## Reproduction and remaining gates

Build through the repository's isolated Sampler workflow, then run each
benchmark in a fresh PowerShell process. Both accept `ModuleManifestPath` to
select an explicit artifact and `OutputPath` for JSON evidence. Match the
parameters above and compare the recorded module hashes and output checksums
before comparing times. The descriptor benchmark leaves its module loaded
until process exit to preserve the module-identity invariant.

No migration is needed. Rollback means reverting the focused refactor commit
and rebuilding; no persisted format or runtime dependency changed. Host WinRM,
service configuration, and remoting settings were not changed for validation.
Live domain-lab and installed-package acceptance were not performed. This diff
was reviewed for security and quality in the session that wrote it, with no
Blocker or Major finding; that is not independent review, which stays
recommended for the shared batching and ACE-comparison changes. A later
repository-wide review requested changes for findings in other, unchanged
files, so acceptance is gated on those as well as on the runs above.

## Addendum: re-measurement on 2026-10-06

The 2026-09-10 figures compare against `5991673`. On 2026-10-06 the change was
ported onto the integration branch `ai/post-release-fixes`, which by then also
carried the FIND-001 private-key correction and the lab-runner, Task
Scheduler, SMB share, and Active Directory corrections. Both benchmarks ran
again against that branch: the baseline is the branch just before the ported
`perf:` commit, and the candidate is the branch just after it.

### Method

- Both artifacts were built with `.\build.ps1 -Tasks build` in PowerShell 7
  and copied out of `output` before the next build, so every run names one
  fixed module.
- Every measurement ran in its own fresh process, one at a time, with no
  concurrent tests or builds, on Windows build 26300 with eight logical
  processors, PowerShell 7.6.6, and Windows PowerShell 5.1.26100.9444.
- The parameters match the 2026-09-10 runs: 256 ACEs, 50 operations, and seven
  measured runs for the descriptor benchmark; 256 files, seven runs per mode,
  and a parallel throttle of eight for the NTFS benchmark; and 200 operations
  with nine runs for the isolated Core CNG comparison.
- Each edition ran the descriptor and NTFS benchmarks twice per artifact in
  the order baseline, candidate, candidate, baseline, so drift during the
  session cannot favor one artifact. The isolated CNG comparison started with
  the candidate, as on 2026-09-10, and then reversed the order.
- Each figure is the median of every measured run of one artifact: 14 runs
  per row, and 18 for the isolated row.

### Identity and output checks

These checks passed before any time was compared:

- All 20 result files record the module hash of the artifact they were meant
  to measure.
- Every paired output checksum matches in every run of both artifacts and
  editions: rights display 1,860, removed ACEs 3,200, CNG equivalence 50 (200
  in the isolated runs), and dispatch 50.
- Every NTFS run returned all 256 owners; the benchmark fails a run with any
  other count.

| Artifact | Commit | `WindowsAccessControl.psm1` SHA-256 |
| --- | --- | --- |
| Baseline | `8b67058` | `28DCBE2F9C899547A1AD04FAA41FDFAB45A817595A95E412979CF95AAA04CFB4` |
| Candidate | `fbced95` | `8DCEC9CBFCF71359D253E536A7E30AF90DCE1B7D154E589DF571F58AA6B3F371` |

A later rebuild of the candidate reproduced the same hash.

### Results

| Workload | Edition | Before (ms) | After (ms) | Time reduction |
| --- | --- | ---: | ---: | ---: |
| Repeated rights display | Core | 4.10 | 1.27 | 69.0% |
| Repeated rights display | Desktop | 4.96 | 3.31 | 33.1% |
| Removed-ACE calculation | Core | 883.21 | 297.27 | 66.3% |
| Removed-ACE calculation | Desktop | 866.64 | 47.59 | 94.5% |
| Single-target dispatch | Core | 9.56 | 7.83 | 18.1% |
| Single-target dispatch | Desktop | 25.25 | 14.68 | 41.9% |
| CNG equivalence, isolated | Core | 1001.34 | 855.25 | 14.6% |
| CNG equivalence | Desktop | 1469.56 | 1410.93 | 4.0% |

Every row keeps the direction and roughly the size it had on 2026-09-10. The
Desktop CNG gain is the smallest: 4.0% against 8.4%.

The mixed-workload Core CNG row, which the 2026-09-10 table also replaced with
the isolated comparison, went the other way: 295.42 ms before and 325.51 ms
after, 10.2% slower. In every process its first two iterations took 510 to
785 ms. From the fourth iteration on, the baseline took 258 to 355 ms and the
candidate 216 to 337 ms, medians of 265 and 228 ms; the candidate's third
iterations, 477 and 376 ms, were still warming up. A seven-run median
therefore lands inside the warm-up. The isolated comparison runs four times as
many operations per iteration and moved by less than 1% between rounds:
1,005.37 and 998.59 ms before, 855.39 and 855.11 ms after. It remains the Core
CNG figure.

The NTFS owner-read benchmark was again unchanged within noise. Mean
sequential reads took 568.10 ms before and 571.99 ms after on Core, and
597.15 and 599.81 ms on Desktop. Mean parallel reads took 613.41 and 597.60 ms
on Core, and 704.16 and 714.31 ms on Desktop.

The ported change keeps the 2026-09-10 gains on the current baseline, and the
release notes in `CHANGELOG.md` now cite these figures. The 20 raw result
files and the comparison output stay in `%TEMP%\wac03-perf` on the development
machine; they are not part of the repository.

### Validation and review

- The nine ported tests pass in both editions, and the whole private-key
  mutation test file passes 54 of 54 in both, so the FIND-001 returned-bytes
  behavior and the ported multiset comparison hold together.
- Two new tests pin the batch layer: the dispatcher rejects `CommandName` or
  `ObjectFamily` without the other before any target runs, and an NTFS adapter
  worker copies the parameters every runspace shares before it writes its
  target. Each failed in both editions with its guard removed from source and
  passed with it restored.
- Full Core `test` on the final commit: 1,917 passed, zero failed, two
  environment skips. Asserted coverage is 83.11% (6,910 of 8,314 executable
  commands) against the unchanged 80% gate.
- Full Desktop `test` on the same module: 1,870 passed, two failed, two
  environment skips. Only the two DSC-engine calls failed, because local WinRM
  is stopped, so that build stops before its coverage assertion. Coverage
  computed from its JaCoCo document with the repository's own scoping
  functions is 80.95% (6,730 of 8,314).
- No domain-lab-only source file ran locally: 0 of 192 commands over 13 files.
- PSScriptAnalyzer 1.25.0 reports no finding in any of the 22 changed
  PowerShell files.
- Sampler `pack`: 22 tasks, zero errors or warnings. The package SHA-256 is
  `858945AB6DFD168D1AEAE9A965299AF6F93153EFDEE802523E1A33A46529F007`, and its
  module is the candidate measured above.
- One independent security and quality review of the finished diff approved it
  with one Minor and three Nits and no Blocker or Major. It found no input for
  which the rewritten comparisons or parameter copies diverge from the code
  they replace. The Minor asked for the adapter test above; the Nits corrected
  this report's private-key key description and cache scope, and which
  release-note figures use 256 entries.

This addendum supersedes the review and gate statements in the 2026-09-10
sections. Rollback is unchanged: revert the `perf:` commit and rebuild. Live
domain-lab and installed-package acceptance of the change remain open; they
belong to the next lab acceptance run.
