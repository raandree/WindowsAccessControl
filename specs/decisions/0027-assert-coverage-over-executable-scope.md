# Assert the coverage threshold over the executable scope

- Status: Accepted
- Date: 2026-08-02
- Deciders: user, software-engineer agent

## Context and problem statement

[ADR 0025](0025-fix-coverage-measurement-not-threshold.md) kept the 80 percent
threshold and fixed the measurement by merging the domain-lab acceptance
coverage into the locally measured run. That merge only exists on a host that
can run the lab. GitHub Actions has no Hyper-V host, no three forests, and no
Kerberos delegation, so `Import_DomainLab_Code_Coverage` writes an empty
document and the threshold falls back to the locally measured number. The
repository ended up with one verdict it trusts locally and a different verdict
in the hosted build, and only one of them measured the module.

Two measurements taken for this decision show that neither verdict is stable.

- A full local run on 2026-08-02 measures 6,379 of 7,938 commands, which is
  80.36 percent. The hosted gate therefore passes by 0.36 points, by accident
  rather than by design. One new Active Directory command drops it back under.
- The committed domain-lab document measures 4,720 lines the current build does
  not have, because it was produced against an earlier built module. The
  identity guard refuses it, as it should, so the merged verdict the repository
  says it trusts does not currently exist either.

The merged gate is green only between a lab run and the next source change, and
the hosted gate is green only while the code it cannot execute happens not to
grow. Neither is a verdict a build can stand behind.

The mechanism ADR 0025 lacked now exists. ModuleBuilder brackets every merged
source file with `#Region '<source path>'` and `#EndRegion '<source path>'`
comments, so each measured line of the single built `.psm1` can be attributed to
the source file it came from. The attribution is exact rather than approximate:
all 7,938 measured commands of the local run map onto 254 source files with none
left over.

Fifteen source files measure zero executed commands locally and belong to the
two families whose live evidence is a `tests/Lab` suite that needs a domain
controller and a delegated member server. `SmbSharePermissions.Live.Tests.ps1`
resolves a domain user through the `ActiveDirectory` module and drives the
module through a Kerberos session against the disposable member server, so the
SMB share family needs the lab for the same reason the Active Directory family
does.

| Scope | Executed | Analyzed | Covered |
| --- | ---: | ---: | ---: |
| Whole module | 6,379 | 7,938 | 80.36% |
| Asserted scope | 6,379 | 7,671 | 83.16% |
| Declared domain-lab-only | 0 | 267 | 0.00% |

## Decision

- Keep the enforced threshold at 80 percent, unchanged.
- Assert it over the commands the running test profile can execute. Every
  measured line of the merged document is attributed to its source file, and the
  source files listed in `build.yaml` under
  `CodeCoverage: DomainLabOnlySourcePath` are subtracted from both sides of the
  ratio.
- Declare a source file only when the local test profile executes no command of
  it at all. That rule keeps every command of real local evidence inside the
  gate, and the build enforces it: a declared file whose locally measured
  document reports an executed command fails the build with that file named. The
  check reads the locally measured document rather than the merged one, because
  the merged one would accept anything the lab happens to cover.
- List exact source paths, not globs. A glob is matched case-insensitively and
  can silently take in a file added later; an exact path cannot.
- Keep everything else in scope by default. A line the source map cannot
  attribute, and every source file added later, is asserted. A declared path
  that matches no source file fails the build, so the scope cannot quietly
  shrink through rot.
- Leave the eight further files that also measure zero locally inside the
  asserted scope. Five are Task Scheduler and three are certificate or CNG key
  files, and a local profile can create a task folder, a scheduled task, and a
  software key, so a zero there is an untested reachable path rather than an
  unreachable one.
- Report the whole-module number and the domain-lab-only number on every run,
  say whether domain-lab evidence was merged into that run, and assert neither.
  Asserting the whole-module number would recreate the split verdict this
  decision removes, because only a host that ran the lab can meet it.
- Treat a domain-lab document that cannot be read or cannot merge as absent,
  with a warning, instead of failing the build. Stale evidence is missing
  evidence, no contributor can refresh it without the lab, and the asserted
  scope no longer depends on it. The document is still never merged, so a union
  of disjoint line sets remains impossible.

## Consequences

- One rule runs everywhere. The hosted build asserts 83.16 percent of 7,671
  commands against the same 80 percent threshold, and a host that has run the
  lab asserts the same scope with more evidence inside it.
- 267 commands over 15 source files leave the asserted scope, and the local
  profile executes none of them, so no measured evidence is discarded. They are
  gated by the domain-lab acceptance profile, which fails on any skip and on any
  suite with zero passing tests.
- The declaration cannot be widened quietly. Adding a file the local profile
  executes fails the build, and adding a path that matches nothing fails the
  build. Removing a file from the declaration only ever makes the gate stricter.
- Adding the first local test for a declared file fails the build until that
  file is removed from the declaration. That is the intended direction: the
  asserted scope grows as coverage does.
- A regression in NTFS, registry, service, process, certificate private-key, or
  Task Scheduler code still trips the threshold, and so does a regression in the
  Active Directory and SMB share code the local profile does execute.
- The build no longer forces a domain-lab rerun after a source change. The
  reported numbers say whether lab evidence was merged, and the acceptance
  profile remains the gate for the families it covers.
- The asserted number is not comparable across environments. A run with lab
  evidence merged reports a higher in-scope percentage than a run without it,
  because the lab also executes code that stays in scope.

## See also

- [Fix the coverage measurement instead of the coverage threshold](0025-fix-coverage-measurement-not-threshold.md)
- [Verification and traceability](../0005-verification-and-traceability.md)
- [Stage enterprise expansion behind a domain lab](0014-stage-enterprise-expansion-behind-domain-lab.md)
