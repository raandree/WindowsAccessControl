# Document the API contract in specs and reference help in code

- Status: Accepted
- Date: 2026-07-25
- Deciders: user, software-engineer agent

## Context and problem statement

The public surface needs one holistic, reviewable contract, while each cmdlet
also needs exhaustive parameter descriptions and examples. Maintaining both in
handwritten specifications would duplicate content and drift from the code.

## Decision

Split API documentation into two layers:

1. `specs/0003-public-api.md` owns command existence, parameter-set shape,
   pipeline contracts, output types, safety conventions, and error policy.
2. Comment-based help in `source/Public` owns exhaustive parameter reference
   and examples and is available through `Get-Help`.

The API specification does not reproduce every parameter table.

## Consequences

- The complete surface can be reviewed without reading 28 function files.
- Parameter details stay next to their implementation.
- QA must require help and require the API contract to name every export.

## Alternatives considered

- Put every parameter in the specification: rejected as duplicate maintenance.
- Keep only comment-based help: rejected because no holistic design contract
  would exist.
- Use the Memory Bank as the API contract: rejected because it is a summary,
  not a durable specification.

## See also

- [Public API specification](../0003-public-api.md)
- [Verification specification](../0005-verification-and-traceability.md)
