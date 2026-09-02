# WindowsAccessControl documentation

This folder holds the task-oriented documentation for
`WindowsAccessControl`. It explains how to use the module. It is not the
normative contract: the numbered [specifications](../specs/README.md) define
what the module does, and comment-based help defines every parameter.

## Start here

| If you want to | Read |
| --- | --- |
| Learn the module from scratch | [Usage guide](usage-guide.md) |
| Install and run a first command | [Getting started](usage/getting-started.md) |
| Find the command for a task | [Command reference](usage/command-reference.md) |
| Move an existing script over | [Migration from NTFSPermission](migration-from-ntfspermission.md) |
| Fix a failing operation | [Troubleshooting](usage/troubleshooting.md) |

## Documents in this folder

| Document | Covers | Audience |
| --- | --- | --- |
| [usage-guide.md](usage-guide.md) | Entry point and map of every task page | Everyone |
| [migration-from-ntfspermission.md](migration-from-ntfspermission.md) | Package, command, and output type changes after the rename | Existing `NTFSPermission` and `NTFSSecurity` users |
| [research.md](research.md) | Source review, platform API semantics, and the comparison that informed the specifications | Contributors and reviewers |
| [domain-lab-inventory.md](domain-lab-inventory.md) | Machines, forests, and roles of the disposable acceptance lab | Contributors running the lab suites |

## The usage guide

The usage guide is split into focused pages under [usage/](usage/). Each page
is self-contained, so you can read only the object family you manage.

### Foundations

- [Getting started](usage/getting-started.md)
- [Safety, preview, and privileges](usage/safety-and-privileges.md)
- [Descriptor editing and concurrency](usage/descriptor-editing.md)

### Object families

- [File system](usage/file-system.md)
- [Registry keys](usage/registry.md)
- [Services and the SCM](usage/services.md)
- [Live processes](usage/processes.md)
- [SMB shares](usage/smb-shares.md)
- [Active Directory objects](usage/active-directory.md)
- [Task Scheduler](usage/task-scheduler.md)
- [Certificate private keys](usage/certificate-private-keys.md)

### Cross-cutting workflows

- [Auditing and SACLs](usage/auditing.md)
- [Backup, restore, and copy](usage/backup-and-restore.md)
- [Diagnostics, batching, and metrics](usage/diagnostics.md)
- [Desired State Configuration](usage/dsc.md)
- [Troubleshooting](usage/troubleshooting.md)
- [Command reference](usage/command-reference.md)

## Conventions used in these pages

- Every example targets the local computer. The module has no remote target
  parameters; see [Getting started](usage/getting-started.md#targets-are-local).
- Mutating examples are shown with `WhatIf` first. Run the same command without
  it once the preview is what you expect.
- Sample accounts and paths such as `CONTOSO\Analysts` and `C:\Data` are
  placeholders. Replace them with targets from your own environment.
- Headings use sentence case and lines wrap at 80 characters, which keeps
  diffs of these files readable.

## Other sources of truth

| Source | Answers |
| --- | --- |
| [Specifications](../specs/README.md) | What the module guarantees, and what it deliberately refuses |
| [Architecture decisions](../specs/decisions/README.md) | Why a cross-cutting design choice was made |
| Comment-based help (`Get-Help <command> -Full`) | Every parameter, input, and output of one command |
| [Project wiki](https://github.com/raandree/WindowsAccessControl/wiki) | The same help as browsable pages, regenerated on each release |
| [Change log](../CHANGELOG.md) | What changed in each version |
| [Contributing guide](../CONTRIBUTING.md) | How to build, test, and propose a change |
| [Security policy](../SECURITY.md) | How to report a vulnerability privately |

## See also

- [Project overview and command catalog](../README.md)
- [Lab guide](../tests/Lab/README.md)
