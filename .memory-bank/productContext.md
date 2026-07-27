---
status: current
last-verified: 2026-07-25
owner: shared
source: repository evidence
---

# Product context

## Problem

PowerShell exposes inconsistent whole-descriptor surfaces across Windows
object families. Routine file-system, registry, service, and process permission
operations require verbose and error-prone managed or native calls. Established
convenience modules are dormant, narrowly scoped, or depend on archived
libraries.

## Users

- Windows administrators.
- PowerShell automation authors.
- DSC operators.
- Security auditors.
- Identity and directory-service administrators.

## Core workflows

1. Inspect and filter access or audit rules across object-specific pipelines.
2. Add, replace, or remove precise rules with preview and confirmation support.
3. Inspect or change owner, group, and supported inheritance without losing
     unrelated descriptor sections.
4. Copy, back up, verify, and restore unified descriptor records.
5. Resolve identities, scope privileges automatically, and inspect effective
     access, ACL health, or operation metrics.
6. Converge exact descriptors or individual rules through class-based DSC.
7. Secure scheduled workloads and software-backed certificate private keys
     without exporting key material or replacing unrelated ACEs.
8. Manage SMB-share authorization separately from backing NTFS permissions and
     delegate Active Directory object access with schema-aware rules.

## Experience goals

- Make safe operations concise and composable in the pipeline.
- Make destructive semantics explicit in command names and parameter sets.
- Emit structured objects suitable for filtering, export, and further module
    commands.
- Keep object-specific rights discoverable while centralizing high-risk native
     descriptor behavior.
- Make server, domain-controller, credential, authentication, and consistency
     context explicit whenever an operation crosses a machine or directory
     boundary.
