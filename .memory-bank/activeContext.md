---
status: current
last-verified: 2026-08-14
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

The module is being prepared for its first release. The engineering was ready;
the packaging was not. The manifest declared `All rights reserved` and carried
no `LicenseUri` and no `ProjectUri`, so the package could not be distributed and
its Gallery entry would have named neither the terms nor the origin. The README
documented building from source only, so a reader arriving from the Gallery had
no supported way to install what they had just found.

Three commits are on `origin/main`. The remaining step is the release tag, and
nothing has been published yet.

Before that, three of the six lab-specific gaps recorded on 2026-08-12 were
closed with live evidence. The other three cannot be closed by lab work at all:
read-only domain controllers and inter-site replication scheduling are stated as
outside specification 0016, and selective authentication answers no accepted
requirement. They need a scope decision before a lab change, not the other way
round.

The first gap also turned out to be described wrongly. It read "prove
`RequireUnchanged` across replication", but no Active Directory command has
`RequireUnchanged`; that gate belongs to the file-system and registry families.
What the lab could prove is what actually happens, and it is worse than a stale
write being refused: the write is accepted and one of the two edits disappears.

## What changed

- The module is MIT licensed. `LICENSE` holds the terms, the copyright statement
    names them instead of reserving all rights, and `LicenseUri` and
    `ProjectUri` reach the built manifest.
- `SECURITY.md` gives a private reporting route, which a module that writes
    security descriptors had no business shipping without. It separates a defect
    from the behavior the specifications deliberately refuse, so a recorded
    refusal is not filed as a vulnerability.
- `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` follow the DSC Community layout but
    carry only what is specific here: a behavior change starts in a
    specification, what belongs in each test folder, why coverage is asserted
    over the executable scope, that the domain lab is not required for a pull
    request, and that the commit message decides the next version. The code of
    conduct is the Contributor Covenant 2.1 rather than an adoption of the DSC
    Community document, because that document routes enforcement to an
    organization that does not govern this repository.
- The README gained install, contributing, security, and license sections.
- Concurrent directory writers are measured rather than assumed. A security
    descriptor is one replicated attribute, so two entries written from one
    baseline through the two writable controllers converge to exactly one
    survivor and the losing write is discarded whole. The same suite proves the
    two mechanisms a caller does have: `ConcurrencyToken` is content derived, so
    one converged descriptor reports one token through both controllers and a
    write on the other controller changes it; and two writes serialized through
    one pinned controller both survive. Specification 0016 records the contract,
    a unit test refuses a `RequireUnchanged` parameter on all five directory
    write commands, and a QA test pins the statement.
- The lab publishes an enterprise certificate template that issues a CNG key and
    requires the same key on renewal, and the acceptance enrolls from it and
    renews. Two thumbprints, one key container, one canonical target, and a
    portability record captured before the renewal still relocates the key and
    restores its DACL although the thumbprint it recorded now matches no
    certificate. That is specification 0017's thumbprint claim measured on a
    real issued key.
- The acceptance can run against the installed package. Every suite resolves its
    module through `Resolve-WindowsAccessControlLabModuleRoot.ps1`, which
    returns the build output unless `WAC_LAB_MODULE_ROOT` names an installed
    module and fails rather than falling back when that variable is wrong.
    `-ModuleSource Installed` expands the packaged module into the machine
    module path of the management domain controller and points the run at it.
    Coverage is refused in that mode, because it instruments the built module.

## Acceptance evidence

- Two-edition lab acceptance green on 2026-08-13: 8 suites, 92 passed, 0 failed,
    0 skipped in each edition, `Result = Passed`, every suite `Ready = True`.
    Per suite: DomainLab 6, CertificatePrivateKey 8, TaskScheduler 8, SmbShare 7,
    ADObjectPermissions 12, ADSchemaDefaultAndObjectType 35, ForeignPrincipal 5,
    ADObjectReplication 11.
- Installed-package acceptance green on the same suites and counts, with the
    module loaded from
    `C:\Program Files\WindowsPowerShell\Modules\WindowsAccessControl\0.0.1`.
- Local gate green: `-Tasks test` 10 tasks, 0 errors, 0 warnings, 1,722 passed,
    0 failed. Domain-lab coverage 45.07 percent merged, whole-module 91.03
    percent reported, asserted scope 91.09 percent over the 80 percent
    threshold.
- The three failures on the way were proved before they were fixed rather than
    reasoned about: the concurrent-writer case reported one survivor on its
    first run, the renewal failed with `ERROR_NOT_AUTHENTICATED` until the
    request ran as SYSTEM, and the certificate template was refused by the
    certification authority until its version 4 settings were packed into
    `msPKI-RA-Application-Policies`.
- The lab was left clean: the member store holds only the two certificates it
    held before the run, and no enrollment task survives.

## Environment notes

- `WindowsAccessControlLab` has 13 machines across three forests. After a host
    reboot they must be started before an acceptance run.
- AutomatedLab does not load in Windows PowerShell on this host; start the lab
    from PowerShell 7.
- The acceptance runner calls `ShouldProcess`, so a detached non-interactive
    launch must pass `-Confirm:$false` or it fails on the prompt.
- Passing several editions to a detached launcher through `Start-Process` binds
    only the first one and sends the rest to the next free positional parameter.
    Split the list inside the wrapper instead.
- A standalone Pester run must import Pester by explicit path or prepend
    `output/RequiredModules` to `PSModulePath`.
- The changelog QA check compares the working tree against the default branch,
    so a gate started before `CHANGELOG.md` is edited fails on that one test.

## Next step

The first release is not cut. `GitVersion.yml` tags `main` as `preview` with
`next-version: 0.1.0`, so a build of `main` publishes a prerelease and the
stable release needs its own `v0.1.0` tag. No tag exists on the remote yet, and
`Publish_Release_To_GitHub` creates one on a successful main build, so the
absence of a tag is the signal that the publish job has not completed. Check the
workflow run before tagging, and confirm the `GitHubToken` and `GalleryApiToken`
secrets exist, because the job fails closed on a missing secret rather than
publishing a version without the tag the next build anchors on.

`IconUri` is still unset; the owner is producing an icon. The Gallery needs a
direct image URL rather than a repository page.

OI-31 is still the only register entry and its enumeration-identity half is
still unexplained. The two weakened type assertions stay weakened until
something reproduces a second live runtime enumeration type.

The three remaining lab additions are scope decisions rather than lab work: a
second Active Directory site, selective authentication on the forest trust, and
a read-only domain controller. Specification 0016 excludes the first and the
third by name, and nothing in the accepted contracts asks for the second, so
each needs an accepted requirement before the lab grows to carry it.
