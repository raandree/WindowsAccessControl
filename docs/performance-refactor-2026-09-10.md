# Performance refactor evidence

This pass reduces repeated work in the shared descriptor helpers and all seven
batch adapters. It preserves the 105 public commands, 20 DSC resources, runtime
dependencies, selected-section persistence, native resource ownership,
confirmation behavior, and target locking. It does not rewrite every file or
claim that every workload is faster.

## Changes

- Cache immutable rights-enum metadata per module instance and at most 128
  rendered masks per enum. Additional masks are calculated normally. Security
  descriptors, account lookups, tokens, and handles are not cached.
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
  component of a private-key ACE key is uppercase hexadecimal or a fixed
  literal, so two keys cannot differ only in case and the ordinal sort is
  defensive rather than a behavior fix.
- Replace pipeline-based metric-parameter counting with Boolean checks and
  replace per-target parameter-copy loops with shallow hashtable clones in
  NTFS, registry, service, process, SMB, AD, and Task Scheduler adapters.

## Measurements

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

## Validation

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

## Artifact identity

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
