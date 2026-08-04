---
status: current
last-verified: 2026-08-03
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

The continuous integration pipeline now publishes the module. The `publish`
workflow and the GitHub Actions `publish` job were adapted from the
`CopilotAtelier` repository, which already runs the same Sampler release flow.

## What changed

- `build.yaml` gained `Publish_Release_To_GitHub` in front of
    `Publish_Module_To_Gallery`, and a `GitHubConfig` section with
    `GitHubFilesToAdd: CHANGELOG.md`, the commit identity, and
    `UpdateChangelogOnPrerelease: false`.
- The build job runs `-Tasks pack` rather than `-Tasks build`, because
    `Publish_Release_To_GitHub` attaches `output/<ProjectName>.<version>.nupkg`
    to the release and only `package_module_nupkg` produces it.
- The workflow gained a `publish` job that needs `build` and `test`, verifies
    both release secrets, runs `-Tasks publish`, and then runs
    `Create_ChangeLog_GitHub_PR`.
- Push triggers gained the stable `v*` tags and exclude `v*-*`, so a pre-release
    tag the release task creates itself cannot start another build.
    `paths-ignore: CHANGELOG.md` stops the changelog pull request from doing the
    same.
- A release run is no longer cancelled by a newer one, so nothing can stop
    between the GitHub release and the Gallery publish.

## Why both secrets are required

Both Sampler release tasks carry an `-if` on their own token and skip silently
when it is empty. A missing `GitHubToken` alone would therefore still publish to
the Gallery, but without the `v*` tag GitVersion anchors the next pre-release
number on. The next build would recompute an already-published version and the
Gallery would reject it with HTTP 409. The `Verify release secrets` step fails
first instead.

## Acceptance evidence

- `./build.ps1 -Tasks pack` succeeds: 9 tasks, 0 errors, 0 warnings, and it
    writes `output/WindowsAccessControl.0.0.1.nupkg`, which is the exact asset
    name `Publish_Release_To_GitHub` looks for.
- `./build.ps1 -Tasks publish` resolves both task names and reports
    `/publish/Publish_Release_To_GitHub skipped` and
    `/publish/Publish_Module_To_Gallery skipped` with no token set, exit code 0.
    That is the proof that the renamed task references bind, since Invoke-Build
    matches task names case-insensitively.
- Both YAML documents parse with `powershell-yaml`, and the workflow resolves to
    the jobs `build`, `test`, and `publish`.
- `tests/Unit/Build/DomainLabCodeCoverage.Tests.ps1`, the only test that reads
    `build.yaml`, passes 16 of 16.

## Repository setup still required

The `publish` job needs two repository secrets under Settings > Secrets and
variables > Actions: `GitHubToken` and `GalleryApiToken`. Until both exist, the
job fails on its verification step rather than publishing a partial release. The
module manifest still has no `LicenseUri` and no `ProjectUri`; the Gallery
accepts the package without them but shows no links.

## Environment notes

- The development host is the Hyper-V host and is a workgroup machine. The
    module pins Kerberos for its LDAP bind, so the enterprise suites run inside
    the lab through AutomatedLab credential delegation.
- `WindowsAccessControlLab` has 13 machines across three forests. After a host
    reboot the machines must be started before the acceptance runs, and the
    member fixture reports not ready for a short time while its services start.
- A standalone Pester run must prepend `output/module` and
    `output/RequiredModules` to `PSModulePath`. Without them, 36 DSC discovery
    and Sampler-dependent tests fail for a reason none of them caused.
- The certificate private-key unit tests remain flaky here because they
    exercise the live key storage provider.
- The committed domain-lab coverage document still measures a module the current
    `main` build does not produce, so the merged whole-module verdict is
    reported rather than asserted until the lab acceptance is rerun.

## Next step

Add the two repository secrets, then let one `main` build publish a pre-release
end to end and confirm that the tag, the GitHub release, and the Gallery version
agree.

No specification is in `Draft` and no focused issue is open. The remaining
operational candidate is to rerun the domain-lab coverage document so the merged
whole-module number can be reported with lab evidence again.

Every other candidate (SMB-6, AD-7, directory audit rules, directory
inheritance and owner/group mutation, CAPI) is a written deferral and needs a
new accepted scope decision before implementation.
