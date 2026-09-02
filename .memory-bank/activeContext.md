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

- Renamed the runner's internal switch to `SkipPayloadDeployment` and guarded
    the existing reset/copy block with it.
- Preserved `SkipPayload` as an alias so existing automation keeps working.
- Added `SkipDeployment` as an equivalent alias matching the operator's intent.
- Documented the canonical command in the script help and lab README.
- Added a focused Pester contract test for parameter metadata and the guarded
    payload deployment block.
- Made the `ShouldProcess` action skip-aware and documented
    `-SkipPayloadDeployment -Confirm:$false` as the unattended invocation.

## Acceptance evidence

- Red: the focused suite failed 2 of 2 because the canonical parameter and its
    guard did not exist.
- Green: the focused suite passed 3 of 3 after implementation, including the
    skip-aware confirmation action.
- PSScriptAnalyzer reports 0 errors and 0 warnings for both changed PowerShell
    files.
- VS Code reports no diagnostics in the runner, focused test, or lab README.

## Next step

Run the acceptance with `-SkipPayloadDeployment` when the remote repository
tree is already current. Omit the switch whenever source, tests, or the built
module changed and must be copied into the lab.
