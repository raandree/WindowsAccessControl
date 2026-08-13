# Security policy

`WindowsAccessControl` writes Windows security descriptors. A defect in it can
grant access that an operator did not intend, so a vulnerability report is
treated as a release blocker rather than as a backlog item.

## Reporting a vulnerability

Report privately through
[GitHub security advisories](https://github.com/raandree/WindowsAccessControl/security/advisories/new).
Do not open a public issue, and do not attach a descriptor from a production
system.

Include the module version, the PowerShell edition, the command and parameters,
the object family, and what access the result granted against what you
expected. A minimal reproduction on a disposable object is worth more than a
description of the production system it was found on.

## Supported versions

The most recent released version is supported. There is no long-term support
branch.

## What is in scope

- A command that grants, keeps, or removes access other than the access its
  contract states.
- A gate that fails open: a check whose input cannot be evaluated and that
  permits the write anyway.
- A bounded target boundary that reaches an object outside it, including the
  allowed organizational unit for Active Directory writes and the
  local-on-target rule for SMB shares, Task Scheduler, and private keys.
- Loss of a security descriptor section the command did not select.
- Credential, key, or descriptor material reaching a log, an error message, a
  backup document, or a metrics record.

## What is out of scope

- Behavior the specifications state and refuse. `specs/0004` records the
  security and persistence contract, and the decision records under
  `specs/decisions` record what is deliberately unsupported. Remote and combined
  effective access, directory effective access, and audit rules on families
  where they are excluded are refusals, not defects.
- A privileged caller using the module to change access it is already permitted
  to change. The module is a tool for an administrator, not a confinement
  boundary around one.
- The disposable acceptance lab under `tests/Lab`. It is deliberately
  permissive, holds no production data, and must never be attached to a
  production network.

## See also

- [Security and persistence contract](specs/0004-security-and-persistence.md)
- [Safety model](README.md#safety-model)
