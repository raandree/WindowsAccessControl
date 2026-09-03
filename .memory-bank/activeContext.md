---
status: current
last-verified: 2026-09-02
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

The Active Directory family gained the one read it had been telling people to
run by hand. A usage page ended with a fenced `Get-ADObject -Identity $dn
-Properties allowedAttributesEffective, ...` under the heading "Why there is no
directory effective-access command", which is a workaround printed in
documentation rather than a boundary.

`Get-ADObjectCallerEffectiveAccess` wraps it. One base-scope request names the
three constructed attributes explicitly, because a wildcard attribute request
never returns a constructed attribute, and the result carries the directory
family's usual target identity plus sorted name lists, their counts, the raw
`sDRightsEffective` mask, and the same mask typed as
`WindowsSecurityDescriptorSection`.

The generated documentation is now complete as well. The wiki carries one page
per DSC resource beside its command pages, and the module ships conceptual help
for all twenty resources plus MAML external help for its public commands.
`source/Classes` is split one class per file so DscResource.DocGenerator can
resolve each resource, all 125 DSC properties have comment-based help, and the
56 multi-line `ThrottleLimit` defaults are now one-line expressions that platyPS
can serialize as YAML. These are documentation-enabling mechanical changes; the
module surface and class order remain unchanged.

ADR 0022 is not reopened by this. Its consequences already allowed "a
caller-scoped constructed-attribute reader ... because that result answers a
different and honestly labeled question", and its alternatives list the same
three attributes as not rejected on correctness, only deferred pending a
specification. Specification 0018 is that specification.

Honest labeling drove two decisions. The command is not named
`Get-ADObjectEffectiveAccess`, because that name invites the reading ADR 0022
exists to prevent, and it exposes no `Account` parameter at all, because a
domain controller answers only for the identity that bound the session and
`Credential` is the only way to ask about a different one. The specification
also states what the three attributes cannot say: nothing about read access,
nothing about extended rights such as Reset Password, creation only for child
classes, and one controller at one moment.

Before that, the host-side domain-lab acceptance runner gained the ability to
reuse the repository payload already present on the management domain
controller. The canonical switch is `-SkipPayloadDeployment`; `-SkipPayload`
remains a compatibility alias and `-SkipDeployment` is the concise interactive
spelling.

The skip switch controls payload deployment, not confirmation for the
acceptance run. The runner still changes disposable fixtures, so it retains its
high-impact confirmation. Pass `-Confirm:$false` for an unattended run. The
confirmation action is skip-aware and no longer claims that the build will be
deployed when deployment is skipped.

Lab installation remains a separate operation owned by
`Deploy-WindowsAccessControlLab.ps1`. The acceptance runner imports an existing
lab, optionally refreshes its payload, runs each requested PowerShell edition,
and copies evidence back to the host.

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
- Added `Get-ADObjectCallerEffectiveAccess` and specification 0018 for the
    controller-computed, caller-scoped constructed attributes.
- Made lab payload deployment optional through `-SkipPayloadDeployment`, with
    compatibility aliases and a focused contract test. The focused suite passes
    3 of 3 after the documentation merge, and the change is ready to commit as
    its own lab-runner feature.

## Acceptance evidence

- The documentation branch passed `-Tasks build, docs`: 20 tasks, 0 errors,
    0 warnings, 20 resource pages, 20 conceptual-help files, and one MAML help
    file.
- Its test gate passed 1,722 tests with 0 failures and 2 skips; asserted local
    coverage was 82.42 percent.
- The AD caller-effective-access increment passed the full local gate with 1,739
    tests, 0 failures, 2 skips, and 82.45 percent asserted coverage.

## Next step

The next domain-lab acceptance must deploy the payload because this merge
changes source and built help artifacts. Use `-SkipPayloadDeployment` only on a
later run whose repository payload is already current.
