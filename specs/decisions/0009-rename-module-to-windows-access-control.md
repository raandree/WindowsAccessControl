# Rename the module to WindowsAccessControl

- Status: Accepted
- Date: 2026-07-25
- Deciders: user, software-engineer agent

## Context and problem statement

`NTFSPermission` describes only the original filesystem scope. The accepted
product now manages Windows security descriptors for registry keys, services,
the Service Control Manager, and processes as well. The old package is
unpublished and has no known external consumers.

## Decision

- Rename the package, source manifest, root module, format data, output type
  prefix, documentation, and repository-facing product name to
  `WindowsAccessControl`.
- Preserve the existing module GUID because this is a continuation of the same
  project rather than an unrelated package.
- Keep `NTFS` in filesystem-specific command nouns and use object-specific nouns
  for registry, service, and process commands.
- Rename cross-domain identity and privilege commands to `Windows` nouns.
- Do not ship an old-package shim without evidence of an external consumer.
- Maintain a migration map. If external use is discovered before release, build
  a separately tested compatibility package rather than mixing aliases into the
  new manifest.

## Consequences

- The package name matches the expanded domain and remains discoverable.
- Existing local scripts must update cross-domain command and output type names.
- No speculative compatibility surface must be maintained during initial
  development.
- Git history and the module GUID retain project lineage.

## Alternatives considered

- Keep `NTFSPermission`: rejected because it misrepresents most of the accepted
  scope.
- Use a generic `SecurityDescriptor` package name: rejected because it omits the
  Windows platform boundary.
- Always ship aliases and a compatibility module: rejected because there are no
  published consumers and every alias would become a long-term contract.

## See also

- [Expansion design](../0006-windows-access-control-expansion.md#rollback)
