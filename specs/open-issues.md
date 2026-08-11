# Open issues

This register tracks agreed validation gaps and deferred extensions to the
accepted specifications. When an item ships, remove it here and record the
change in `CHANGELOG.md`. Rejected out-of-scope ideas remain in the research
note rather than this list.

## OI-23: Add CAPI private-key capability and mutation

Specification: 0008. Tasks: KEY-1 to KEY-4 and KEY-7.

`KEY-1` is complete for CAPI and the rejection boundary is closed and tested in
both PowerShell editions. ADR 0024 records the cross-edition probe: current
Windows routes a legacy CSP key through the CNG legacy bridge, so the separate
managed CAPI object this issue assumed is never returned, the bridge still
reports the CAPI provider name, and the bridged key cannot serve a descriptor at
all. The implementation half is withdrawn.

Only reopen this issue with a concrete requirement for the legacy
`CryptAcquireContext` plus `PP_KEYSET_SEC_DESCR` surface, which needs its own
handle lifetime, rights model, and fail-closed gates. Do not infer CAPI key-file
paths or reuse CNG assumptions.

## OI-29: Subtract the schema default from reported directory entries

Specification: 0009. Depends on `Get-ADObjectSchemaDefaultAccessRule`.

The baseline exists but nothing consumes it. A caller still has to compare by
hand to see which explicit entries an operator actually added. The intended
shape is a filter on `Get-ADObjectAccessRule` that drops every explicit entry
the target's structural class already grants.

The matching rule is the whole problem and is why this did not ship with the
baseline. A schema default is a template: `CO` becomes the creating principal
and `PS` stays `SELF` on the created object, so matching by SID alone
under-matches for the first and over-matches for the second. Windows can also
add auto-inherited flags after creation, and a later schema update changes the
template without touching objects created before it. Decide and record what
counts as the same entry before implementing, and prefer reporting an entry that
might be a default over hiding one that is not.

## OI-30: Reach the rights transform from the file system commands

Specification: 0003.

`WindowsAccessRightsTransformAttribute` is declared on the eight NTFS access and
audit rule parameters, and on `New-NTFSFileSystemRule`, but never runs there:
each of those parameters also declares `[System.Security.AccessControl.FileSystemRights]`,
which adds the engine's `ArgumentTypeConverterAttribute`, and that converter
runs first and refuses a mask carrying an unnameable bit. Measured on
2026-08-11 in PowerShell 7.6.3: `Add-NTFSAccessRule -AccessRights 0x10000000`
fails at argument transformation with the converter on the stack.

The directory mutators already use the working shape, which is to drop the enum
type and let the attribute own the conversion. Applying the same change to the
file system family needs its own regression test per command, because the enum
type is currently what rejects an unknown name there.

## OI-31: Stop the intermittent assertion failures in whole-suite runs

Specification: 0005.

Two tests fail intermittently in a full `./build.ps1 -Tasks test` run and pass
when their file runs alone:

- `Service access rules.Get-ServiceAccessRule should expose typed SCM rights`
    reports `Expected the value to have type [WindowsServiceControlManagerRights]
    ... but got ... with type [WindowsServiceControlManagerRights]`. A type that
    fails `-is` against a literal of its own name is two runtime types with one
    name, which is what happens when a script module defining PowerShell classes
    is imported more than once in a process: each import creates the types
    again, and a value made under the earlier import no longer matches a literal
    resolved under the later one.
- `NTFS batch execution.Should mutate multiple independent targets with bounded
    execution` returned one rule instead of two once, then passed on rerun and in
    isolation.

Neither reproduces reliably, and neither has been traced to a product defect.
Both were observed on 2026-08-11 with unrelated changes in the tree. Find the
import that recreates the types, or make the suites share one import, before
treating either as a product bug. A gate that fails at random teaches everyone
to rerun it, which is how a real failure gets waved through.

## See also

- [Specification index](README.md)
- [NTFSSecurity comparison](../docs/research.md#detailed-ntfssecurity-comparison)
