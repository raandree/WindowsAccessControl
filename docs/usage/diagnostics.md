# Diagnostics, batching, and metrics

This page covers the commands that answer questions rather than change state,
plus the bounded parallel execution model and the in-process counters.

## Resolve an identity

Normalize account names and SIDs before using them in automation:

```powershell
'BUILTIN\Users', 'S-1-1-0' | Resolve-WindowsIdentity
```

Resolution both ways is useful in a report: a SID that no longer translates
usually means a deleted account, but a temporarily unreachable domain
controller produces the same symptom.

Find rules whose SID no longer translates:

```powershell
Get-NTFSAccessRule -LiteralPath 'C:\Data' -Orphaned
```

Confirm domain connectivity before acting on that result.

## Check effective NTFS access

`Get-NTFSItemEffectiveAccess` calls the Windows Authz API with
`MAXIMUM_ALLOWED`, expands groups for a valid user SID, and returns both the
raw access mask and `FileSystemRights`:

```powershell
Get-NTFSItemEffectiveAccess -LiteralPath 'C:\Data' `
    -Account 'CONTOSO\Alice' `
    -AccessRights Modify
```

This is the command to reach for when a DACL "looks right" but access still
fails, because it accounts for group membership, deny rules, and ACE order in
one answer.

Two limits matter:

- The context is derived from a SID, not from a live logon token, so it can
  omit logon-specific groups such as `Interactive` or `Network`.
- Share permissions are not intersected. Evaluate the share layer separately
  with `Get-SmbShareEffectiveAccess`; see [SMB shares](smb-shares.md).

## Check ACL health

Windows evaluates a DACL in order, and a non-canonical order can let an allow
ACE take effect ahead of a deny ACE that was supposed to win:

```powershell
Test-NTFSItemAcl -LiteralPath 'C:\Data' -Section All -PassThru
```

The command reports ordering problems. It does not repair them. Rewrite the
descriptor deliberately when it reports one; see
[Descriptor editing and concurrency](descriptor-editing.md).

## Process bounded batches

Pass a target **array** to use bounded parallel processing. The default limit
is the smaller of eight and the logical processor count, and valid values are 1
through 64:

```powershell
$paths = @(
    Get-ChildItem -LiteralPath 'C:\Data' -File |
        Select-Object -ExpandProperty FullName
)

Get-NTFSAccessRule -LiteralPath $paths -ThrottleLimit 8
```

Rules that govern the batch:

- Pipeline records retain streaming semantics and are dispatched separately.
  Build an array first, as above, when several targets should share one
  concurrent batch.
- Each array is normalized and case-insensitively deduplicated by canonical
  target before dispatch.
- Mutations of the same canonical target are serialized across concurrent
  module instances in the hosting process.
- Interactive confirmation forces sequential execution so prompts do not
  overlap.
- Parallel output is emitted in completion order. Use `ThrottleLimit 1` for
  deterministic input order.

Bounded batching is available on the file system, registry, service and SCM,
and process families.

## Inspect metrics

Redacted aggregate counters are kept for the current module instance:

```powershell
Get-WindowsAccessControlMetric -ObjectFamily FileSystem
Get-WindowsAccessControlMetric -CommandName Get-NTFSAccessRule
```

Each entry reports:

| Property | Meaning |
| --- | --- |
| `OperationCount` | Operations invoked |
| `TargetCount` | Targets processed |
| `SuccessCount` | Targets that succeeded |
| `FailureCount` | Targets that failed |
| `ElapsedMilliseconds` | Total elapsed time |
| `LastUpdatedUtc` | When the counter last changed |

Metrics contain no descriptors and no account secrets, and they reset when the
module instance ends. They are a diagnostic aid for a long-running session, not
a telemetry pipeline.

## Benchmark a read workload

The repository ships a repeatable NTFS read benchmark that produces a JSON
result instead of a flaky timing assertion:

```powershell
.\tests\Performance\Measure-NtfsBatchPerformance.ps1 `
    -TargetCount 512 `
    -Iterations 3 `
    -OutputPath .\output\testResults\NtfsBatchBenchmark.json
```

## Commands on this page

| Area | Commands |
| --- | --- |
| Identity | `Resolve-WindowsIdentity` |
| Effective access | `Get-NTFSItemEffectiveAccess`, `Get-SmbShareEffectiveAccess` |
| ACL health | `Test-NTFSItemAcl` |
| Privileges | `Get-WindowsPrivilege`, `Test-WindowsPrivilege` |
| Metrics | `Get-WindowsAccessControlMetric` |
| Certificate bindings | `Test-CertificatePrivateKeyCriticalBinding` |

## See also

- [Troubleshooting](troubleshooting.md)
- [Safety, preview, and privileges](safety-and-privileges.md)
- [SMB shares](smb-shares.md)
