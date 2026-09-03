---
status: current
last-verified: 2026-09-03
owner: active-agent
source: current task evidence
---

# Active context

## Current focus

The flexible `AccessRights` parameters now offer enumeration-name completion
without giving up raw 32-bit access masks. Eight NTFS rule commands and three
Active Directory rule commands use an argument transformation attribute because
their enum cannot name every valid mask. Those parameters must remain untyped:
declaring the enum can let PowerShell convert a hexadecimal literal before the
transformer sees it. Dedicated completers now enumerate the same filesystem or
directory rights type while the existing transformer continues to own binding.

## What changed

- Added shared filesystem-rights and Active Directory-rights completers backed
    directly by the accepted enumerations.
- Applied completion metadata to every public parameter carrying
    `WindowsAccessRightsTransformAttribute`: eight NTFS commands and three
    Active Directory commands.
- Added a table-driven regression suite that exercises real `TabExpansion2`
    output for all eleven commands and inventories transformed parameters so a
    future command cannot omit completion metadata.

## Compatibility constraint

Do not type these transformed parameters as their rights enum merely to obtain
native completion. Completion and conversion are separate concerns here: the
completer offers names, while the untyped parameter lets the transformer retain
unnamed and generic access-mask bits from hexadecimal literals.

## Acceptance evidence

- The new suite failed 12 of 12 before the implementation: all eleven commands
    returned no rights completion and the metadata inventory found none.
- The final focused run passes 58 of 58. It covers all eleven completion cases,
    the inventory guard, raw hexadecimal masks, unknown-name rejection, and the
    Active Directory contract that transformed rights parameters stay untyped.
- The full `build, test` gate passes 17 tasks with 0 errors and 0 warnings:
    1,754 tests passed, 0 failed, 2 skipped, and executable-scope coverage is
    81.93 percent over the 80 percent threshold.

## Next step

No implementation work remains. No remote operation was requested.
