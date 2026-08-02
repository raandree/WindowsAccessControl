# Open issues

This register tracks agreed validation gaps and deferred extensions to the
accepted specifications. When an item ships, remove it here and record the
change in `CHANGELOG.md`. Rejected out-of-scope ideas remain in the research
note rather than this list.

## OI-28: Give the hosted build a coverage verdict it can stand behind

Specification: 0005. Decision: ADR 0025.

The `test` workflow asserts the 80 percent threshold over the local document
merged with the domain-lab document. GitHub Actions has no domain lab, so
`Import_DomainLab_Code_Coverage` writes an empty document, the merge changes
nothing, and the gate fails at the locally measured number. On the build this
issue was opened against that number is 79.41 percent, 6,101 of 7,683 commands,
against 90.34 percent merged on a host that can run the lab.

This is not a regression. Before the merge landed the same workflow failed at
the same number through `Pester_if_Code_Coverage_Under_Threshold`. What is new
is that the repository now has a verdict it trusts locally and a different
verdict in the hosted build, and only one of them measures the module.

Three facts already established by evidence must shape the answer:

- The lab needs a Hyper-V host, three forests, and Kerberos delegation. A
  hosted runner cannot produce the document.
- A merge only combines documents that measure the same built module. The
  package name is the module version and `Import_DomainLab_Code_Coverage`
  refuses a document that measures a source file or a line the local run does
  not. Committing a document to the repository therefore does not work as a
  general answer: it is refused as soon as the source changes, which is the
  correct behavior and not a bug to work around.
- ADR 0025 already rejected excluding files from measurement, because
  ModuleBuilder emits one merged file and coverage has exactly one file to
  exclude.

Options worth weighing rather than a decided design: publish the document from
a self-hosted runner that has the lab; keep the enforcing gate on the host that
can run the lab and make the hosted coverage report informational; or enforce a
threshold in the hosted build over only the commands that profile can execute,
which needs a mechanism ADR 0025 does not have.

Do not lower the threshold and do not add synthetic tests over code the live
suites already exercise. ADR 0025 settled both.

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

## See also

- [Specification index](README.md)
- [NTFSSecurity comparison](../docs/research.md#detailed-ntfssecurity-comparison)
