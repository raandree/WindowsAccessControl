---
status: current
last-verified: 2026-07-25
owner: shared
source: repository evidence
---

# Product context

## Problem

PowerShell exposes whole security descriptors through `Get-Acl` and `Set-Acl`,
but routine NTFS permission operations require verbose and error-prone .NET
method calls. Established convenience modules are dormant or depend on
archived libraries.

## Users

- Windows administrators.
- PowerShell automation authors.

## Core workflows

1. Inspect and filter access or audit rules across pipeline input.
2. Add, replace, or remove precise rules with preview and confirmation support.
3. Inspect or change ownership and inheritance without losing unrelated
     descriptor sections.
4. Copy, back up, and restore security descriptors.
5. Resolve identities and inspect effective access or ACL health.

## Experience goals

- Make safe operations concise and composable in the pipeline.
- Make destructive semantics explicit in command names and parameter sets.
- Emit structured objects suitable for filtering, export, and further module
    commands.
