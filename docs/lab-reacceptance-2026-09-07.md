# FIND-001 lab reacceptance: 2026-09-07

Current-candidate evidence for the correction in `f5731f1`, following the
[FIND-001 review](security-review-2026-09-07.md). All four full lab passes and
the isolated Desktop DSC-engine gate passed, followed by both fresh local
coverage gates. This closes the requested acceptance of the corrected
candidate, not authorization to publish or a claim of exhaustive validation.

## Candidate and environment

- Commit: `f5731f1f431e9619444fda0b045fee6f3a73ddf1` on
  `ai/test-gap-audit`. Source, tests, and build inputs remained unchanged
  throughout acceptance; only acceptance records were updated.
- The module and package are the exact pair built and verified for FIND-001.
  Their local version is the GitVersion fallback `0.0.1`, not a release version.
- Reused all thirteen existing VMs in the isolated domain lab. No VM removal,
  redeployment, checkpoint restoration, or topology change was needed.
- Created `wac-pre-f5731f1-b1fe0b1f` on all thirteen VMs. Both writable fixture
  controllers passed signed/sealed Kerberos LDAP; the ten marked domain
  objects, member fixtures, and renewable CNG certificate template were ready.
- Used persistent PSSessions and fresh console processes with the unchanged
  repository acceptance entry point. The installed AutomatedLab wrapper failed
  its read-only `ScriptFileName` parameter probe, while PSSession transport
  passed its independent disconnect/reconnect and exit-status check.
- Every lab pass received a fresh payload directory. Each installed-package
  pass extracted and installed the pinned package, with all 25 payload files
  hash-checked before and after testing. Test assertions were not changed.

## Lab results

| Gate | Passed | Failed | Skipped | Cleanup | Completed UTC |
| --- | ---: | ---: | ---: | --- | --- |
| Desktop DSC engine | 5 | 0 | 0 | Temporary installation removed | 17:38:58 |
| Built module, Desktop with coverage | 95 | 0 | 0 | Eight ready entries | 18:02:54 |
| Built module, Core | 95 | 0 | 0 | Eight ready entries | 18:10:19 |
| Installed package, Desktop | 95 | 0 | 0 | Eight ready entries | 18:18:02 |
| Installed package, Core | 95 | 0 | 0 | Eight ready entries | 18:25:33 |

These are four executions of the same 95 live cases, not 380 unique tests.
Every full pass reported `Passed`, eight suites, zero skipped tests, explicit
native exit zero, and both domain/member readiness in all eight cleanup entries.
The host completion marker was zero at 18:25:35 UTC. The five DSC cases include
both actual `Invoke-DscResource` tests.

## Artifact identity

| Artifact | SHA-256 |
| --- | --- |
| Tested module | `A8E433469F06D54F7B71796A2DA1F6589F8705C3141641BD2EDEE589271D94D7` |
| Tested package | `D93B2644B31A38B37F9FAC08DBD1D28C85AF8AD452D81E1428E0A3054530588C` |
| Fresh lab coverage | `D4A71389F9539CF05D4BBA5FFA8F318407D7A26E2A116B2E0EBC8D050EBC49AE` |

The new lab coverage measures 8,496 commands, of which 3,854 were exercised by
the domain-lab profile. It is not the local or merged coverage percentage.
Prior coverage and accepted artifacts were preserved before this run. The new
document was installed at the configured coverage path only after all four
passes, DSC, and installation restoration were verified. Both local workflows
confirmed importing this exact hash before their merged coverage was accepted.

## Local coverage gates

| Edition | Passed | Failed | Skipped | Asserted coverage | Whole-module coverage | Completed UTC |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Core 7.6.5 | 1,806 | 0 | 2 | 91.15% | 91.10% | 18:35:18 |
| Desktop 5.1.26100.33296 | 1,761 | 0 | 2 | 90.41% | 90.38% | 18:52:19 |

Both imported lab coverage documents match the new hash byte-for-byte. The
configured 80 percent threshold and asserted source scope were unchanged.
NUnit counts, per-edition JSON, native exit markers, and final workflow markers
agree. Each ten-task workflow completed with zero errors and two warnings from
deliberate mocked evidence-copy failures, not actual acceptance collection.
Each edition skipped the mounted-volume and unavailable SACL-read privilege
cases. Neither skip concerns the corrected CNG write path.

The final local gate completed at 18:52:19 UTC. Both processes exited, and the
event-based completion watcher finished; no validation process remains running.

## Independent cleanup checks

The management controller's original `0.0.1` installation was restored with
all four original file hashes and its directory ACL unchanged. Post-run native
checks verified both controllers' signed/sealed Kerberos LDAP responses, zero
remaining targets, ten marked baseline objects, and ready domain/member
fixtures. The temporary member module staging and HTTP.sys binding were absent.

All 34 management-controller evidence files and four DSC evidence files matched
their host copies before the two run-owned staging directories were removed.
No acceptance console remained on the management controller. All thirteen VMs
were running and all thirteen new rollback checkpoints remained after cleanup.
The existing accepted payload and unrelated module installations were not
replaced. Only this run's staging was removed.

## Retention and remaining gates

Private evidence is retained under administrator `%TEMP%` in
`wac-reaccept-f5731f1-b1fe0b1f50b042dd8a8b69223ed64375`. It includes pinned
candidate files, preflight, checkpoint identities, native exit markers, raw
console logs, per-pass reports, fresh coverage, restoration inventories, and
independent cleanup checks. Raw evidence is not sanitized for publication.
The [prior acceptance](lab-acceptance-2026-09-07.md) remains a separate record
for its original module hash.

All requested candidate acceptance gates are closed. The module bytes are
unchanged from the independently approved FIND-001 correction. Prior
local-only results were not substituted for the current merged gates.
Release preparation still requires a properly versioned pipeline build and
explicit authorization to merge, tag, push, or publish. No such operation was
performed during this acceptance. Broader native
fault injection, interrupted rollback, cancellation, soak tests, unusual-ACE
persistence, and untested topology profiles remain documented limits, not
claims established by these runs. FIND-002 remains cosmetic and deferred.
