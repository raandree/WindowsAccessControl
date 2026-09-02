---
status: current
last-verified: 2026-09-02
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

The usage guide had become the thing it was written to prevent. One file had
grown to roughly a thousand lines across ten object families, so a reader who
managed one of them scrolled past the other nine, and `docs/` itself listed
four files with nothing to say which was which. The guide is now the entry
point and seventeen pages under `docs/usage/` carry the detail, with
`docs/README.md` as the folder index.

Splitting it exposed what the single file had stopped tracking. It still
described the certificate private-key family as read-only, which specification
0015 superseded: the mutation commands, the gates that refuse a write, the
key-addressed parameter set, and the two desired-state resources were
undocumented outside comment-based help. `Get-ADObjectSchemaDefaultAccessRule`
and `ExcludeSchemaDefault` were undocumented as well, which is the difference
between seeing the delegation an operator configured and seeing every entry a
schema class applies to a new object.

Every command, parameter, and enumeration value written into the new pages was
read out of `source/` rather than carried over from the old text.

Before that, `Add-ADObjectAccessRule`'s comment-based help carried one basic
example, the same gap its sibling mutators had. Each of `Add-`, `Set-`,
`Remove-`, and `Clear-ADObjectAccessRule` now also demonstrates a multi-account
write, an attribute- or extended-right-scoped ACE (including the Reset Password
delegation the Delegation of Control wizard grants), an explicit deny rule,
and, where the command supports it, `RemovalMode Rights` subtraction or a
piped multi-target batch. `Get-ADObjectAccessRule` already carried three
varied examples and was left as-is. The QA suite's per-command SYNOPSIS,
DESCRIPTION, and EXAMPLE checks (629 tests) pass unchanged against the rebuilt
module.

Before that, the generated documentation was completed. Three tasks had been
left out of the `docs` workflow, each for a measured reason, and all three now
run. The wiki carries a page per DSC resource beside the page per command, the
module ships the matching `about_<ResourceName>.help.txt` conceptual help, and
it ships a MAML external help file, so `Get-Help` behaves the way it does for
any other published module.

Two source changes unblocked them. `source/Classes` is split one class per file,
because both DscResource.DocGenerator documentation tasks resolve a resource's
source as `Classes/???.<ClassName>.ps1` or `Classes/<ClassName>.ps1`, and this
module had declared its twenty resources in two files grouped by behavior. And
the `ThrottleLimit` default is written on one line in the 56 commands that had
spread it over four, because platyPS puts a parameter default on the
`Default value:` line verbatim and a multi-line expression is not valid YAML.

The classes also gained the comment-based help both generators read. That was
not optional cosmetics: `New-DscResourcePowerShellHelp` indexes
`$commentBasedHelp.Parameters`, so a class with no help block at all fails the
task outright. All 125 DSC properties are described.

Before that, the release readiness of the repository was assessed. The module
and its packaging are ready; the release itself has never been cut. No tag
exists locally or on the remote, and `Publish_Release_To_GitHub` creates one on
a green main build, so nothing has been published.

Before that, the build produced the repository wiki for the first time. A reader
arriving from the PowerShell Gallery had no browsable reference: the only
per-command documentation was the comment-based help, which has to be installed
and run to be read.

Before that, the GitHub Actions build was fixed. It had never been green: every
`Build` run on `main` failed, and both test jobs failed on the same four tests.
The cause was not in the module. A hosted Windows runner reports `TEMP` in its
8.3 short form, `C:\Users\RUNNER~1\AppData\Local\Temp`, and the module reports
the expanded name, so two suites that root their fixtures at that variable
compared two spellings of the same directory. Each fixture root is now
canonicalized once.

The release step is what this unblocks. The publish job is `needs: [build,
test]`, so it had been skipped on every run, which is why no tag exists on the
remote.

Before that, the module was prepared for its first release. The engineering was
ready; the packaging was not. The manifest declared `All rights reserved` and
carried no `LicenseUri` and no `ProjectUri`, so the package could not be
distributed and its Gallery entry would have named neither the terms nor the
origin. The README documented building from source only, so a reader arriving
from the Gallery had no supported way to install what they had just found.

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

- `source/Classes` holds one class per file, named `NNN.<ClassName>.ps1`. The
    split was verified line for line against the two files it replaced before
    they were deleted: 1,068 non-empty lines, identical and in the same order,
    so the merged module carries the same code in the same sequence.
- Every DSC resource class carries comment-based help with a synopsis, a
    description, and a `.PARAMETER` entry for each of its DSC properties. The
    block has to be the first `<#` in the file, above the `[DscResource()]`
    attribute, or `Get-CommentBasedHelp` will not find it.
- The `docs` workflow is the canonical `Generate_Wiki_Content` order again, with
    `Generate_Conceptual_Help` ahead of it. That task writes into the built
    module rather than into `source`, so it has to run after `build` and before
    `package_module_nupkg`; `docs` sits exactly there inside `pack`.
- `build.yaml` gives the resource pages a `DSC resources` sidebar category.
    Without the metadata the sidebar generator files all twenty under its
    `General` default, next to Home.
- The `ThrottleLimit` default is one line in all 76 commands that declare it.
    Fifty-six were changed; the twenty enterprise commands already wrote it that
    way.
- The two integration suites that keep fixtures outside `TestDrive` canonicalize
    their root before deriving anything from it, so an assertion compares the
    path the module returns against the path the fixture created rather than
    against the environment variable it was read from. The four failing tests
    were fixture defects, not module defects: expanding a short name is what a
    canonical target should do.
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
- The README gained install, contributing, security, and license sections, and
    then the five status badges a Gallery-facing repository is judged by, plus a
    `Releases` section that says why two of them report a version.
- `.github/` carries the contribution surface a public repository is read
    through: three issue templates, a pull request template whose task list
    names this repository's own gates, `CODEOWNERS`, and a Dependabot
    configuration for the pinned action versions. Blank issues are disabled and
    the chooser links the private security route and the specifications, so a
    vulnerability is not filed in public and a recorded refusal is not filed as
    a defect.
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

Cut the first release. `GitVersion.yml` tags `main` as `preview` with
`next-version: 0.1.0`, so a build of `main` publishes a prerelease and the
stable release needs its own `v0.1.0` tag. No tag exists on the remote yet, and
`Publish_Release_To_GitHub` creates one on a successful main build, so the
absence of a tag followed from the test job failing rather than from a publish
problem. Confirm the `GitHubToken` and `GalleryApiToken` secrets exist before
the first green main build, because the job fails closed on a missing secret
rather than publishing a version without the tag the next build anchors on.

The wiki has to exist before the first publish. `Publish-WikiContent` clones
`https://github.com/raandree/WindowsAccessControl.wiki.git`, and GitHub creates
that repository only when the first wiki page is saved, so enabling the feature
alone is not enough. The clone is anonymous; only the push carries the token.

Three Dependabot pull requests for the pinned action versions failed on the same
four tests and should pass once the temp-path fix is on `main`.

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

The brand assets added on 2026-08-14 need no follow-up in code. The steps the
repository cannot take for itself are all repository settings: uploading
`assets/social-preview.png` under the social preview setting, enabling private
vulnerability reporting, without which the advisory link in `SECURITY.md` and in
the issue chooser resolves to nothing for a reporter, and enabling the wiki and
creating its first page, without which `Publish_GitHub_Wiki_Content` cannot
clone it and the publish job fails.
