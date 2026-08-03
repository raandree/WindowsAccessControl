---
status: current
last-verified: 2026-08-03
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

`Should reconverge all NTFS descriptor sections together` is fixed. It was not
environmental and not a privilege gate. `GetNamedSecurityInfo` clears
`INHERITED_ACE` on every DACL ACE when the same call also requests the SACL, so
`-Sections All` reported inherited ACEs as explicit ones. ADR 0028 records the
ruling and the fix.

## The failing test was a real defect

- The leading hypothesis was falsified immediately: the token is elevated and
    holds `SeSecurityPrivilege`, and the failure was not an exception. `Set()`
    completed and `Test()` still reported drift, which is a convergence defect
    rather than an access failure.
- Root cause was isolated by reading the ACE header bytes from
    `GetNamedSecurityInfoW` directly. The DACL ACE flag bytes are `0x10` for
    `SECURITY_INFORMATION` `0x4` and `0x7`, and `0x00` for `0xF`, on one file at
    one moment with the privilege held. Both editions see it.
- The blast radius was wider than the test. Replaying an `All` capture wrote
    inherited ACEs as explicit ACEs, so `Copy-NTFSItemSecurityDescriptor`,
    `Backup-NTFSItemSecurityDescriptor`, and restore silently detached a target
    from its parent ACL.
- `Get-NTFSSecurityDescriptorForItem` now takes the DACL from a read that omits
    the SACL and grafts the audited SACL on. Grafting marks only the audit
    section modified, which was measured rather than assumed, so ADR 0003 stays
    intact for `Access`-only and `Audit`-only work.
- The scenario is now privilege gated per NFR-7 as well, because it genuinely
    needs `SeSecurityPrivilege` in the token even though that was not the cause.

## Acceptance evidence

- All unit and integration suites pass 857 of 857 in PowerShell 7 with no
    skips, and the previously failing scenario passes.
- `Get-NTFSItemSecurityDescriptor.Tests.ps1` guards the invariant directly: the
    DACL reported with `-Sections All` must equal the DACL reported with
    `-Sections Access` for an inherited ACE. Measured pre-fix, those two differed.
- Two wrappers disagreed during diagnosis. `icacls` printed no `(I)` for ACEs
    that `Get-Acl` reported as inherited, which pointed at the wrong component
    until the raw descriptor bytes settled it.

## Two findings worth keeping

- The committed domain-lab document measures 4,720 lines the module built from
    `main` does not have. It was produced against an earlier built module, so the
    merged 90.34 percent verdict recorded when OI-27 closed does not currently
    exist. The identity guard caught it, which is the behavior that decided the
    document should be reported rather than depended on.
- The `-f` format operator binds tighter than `+`, so
    `'a {0}' + 'b {1}' -f $x, $y` silently leaves `{0}` unformatted. One such
    message shipped into the failure branch and was found by forcing the branch
    rather than by reading it.

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

## Next step

No specification is in `Draft` and no focused issue is open. One operational
candidate remains: rerun the domain-lab coverage document so the merged
whole-module number can be reported with lab evidence again.

Every other candidate (SMB-6, AD-7, directory audit rules, directory
inheritance and owner/group mutation, CAPI) is a written deferral and needs a
new accepted scope decision before implementation.
