---
status: current
last-verified: 2026-07-29
owner: active-agent
source: repository evidence
---

# Tech context

## Stack

- PowerShell module built with Sampler 0.120.0, ModuleBuilder 3.2.18,
  InvokeBuild 5.14.23, Pester 5.7.1, and PSScriptAnalyzer 1.25.0.
- GitHub Actions builds one Sampler artifact on Windows and tests it with
    PowerShell 7 and Windows PowerShell 5.1.
- In-box `Microsoft.PowerShell.Security` commands and
    `System.Security.AccessControl` types at runtime, plus narrowly scoped
    Unicode `advapi32` and `kernel32` interop.
- In-box `System.DirectoryServices.Protocols` for Active Directory LDAP work,
    loaded at module import because Windows PowerShell resolves parameter type
    attributes before a function body runs, and `System.DirectoryServices` for
    on-demand writable domain-controller discovery.

## Environment

- Windows development host.
- Build orchestration runs in PowerShell 7.
- PowerShell 7.6.1 and Windows PowerShell 5.1 are available.
- Git default branch is `main`; the CI migration branch is
    `ai/github-actions-build`.

## Constraints

- Runtime behavior is Windows-only and must fail clearly elsewhere.
- Support Windows PowerShell 5.1 and PowerShell 7 without AlphaFS or another
    third-party runtime dependency.
- Preserve unrelated security descriptor sections during mutation.
- Use local targets only and reject native remote syntax, except for Active
    Directory commands, which address one validated and pinned domain
    controller over signed and sealed LDAP.
- Pin process instances by handle and creation identity.
- Keep caller-owned handles open and close every module-owned native resource.
- Bound parallel target execution and serialize same-target writes.
- Import one isolated module instance per worker runspace and keep shared
    coordination in the parent/application domain.
- Run Pester and Sampler only through the detached PowerShell launcher.

## Validation

- `Test-ModuleManifest` for the source and built manifests.
- Pester unit and live NTFS, registry, service, process, and DSC tests in
    detached processes.
- `Invoke-ScriptAnalyzer` for source, tests, and build scripts.
- Sampler build and test workflows in detached processes.
- An 80 percent executable coverage threshold on the merged module.
- NUnit, environment/privilege inventory, benchmark, and cleanup evidence for
    privileged release acceptance.
- Repeatable benchmark evidence without hard timing assertions.
