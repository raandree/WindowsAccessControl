# Use bounded parallel target execution

- Status: Accepted
- Date: 2026-07-25
- Deciders: user, software-engineer agent

## Context and problem statement

The supported operating point includes approximately 10,000 independent targets.
Sequential descriptor reads and writes can be unnecessarily slow, while
unbounded concurrency can exhaust handles, race same-target writes, and corrupt
privilege restoration.

## Decision

- Normalize, prevalidate, and deduplicate a complete invocation before dispatch.
- Process different canonical targets with bounded parallelism by default.
- Default `ThrottleLimit` to the smaller of eight and the logical processor
  count; `ThrottleLimit 1` requests deterministic sequential execution.
- Serialize writes for the same canonical target and persist each descriptor
  once per target.
- Reference-count automatic privilege scopes across workers.
- Stream completed results and structured errors in completion order; do not
  promise input ordering for parallel execution.
- Buffer one target's results and emit them after that target's dispatch scope
  closes, so streaming granularity is per target rather than per object.
- Keep global validation terminating and target-local failures nonterminating.

## Consequences

- Large independent batches complete faster without unbounded handle or memory
  growth.
- Parallel output order is intentionally nondeterministic.
- Same-target aliases cannot race one another after canonical deduplication.
- A terminating error raised by a command downstream of the dispatcher reaches
  the caller instead of being reported as a target failure, because no pipeline
  write happens inside the dispatcher's target `catch`.
- A downstream command observes the batch-worker flag as false and therefore
  dispatches and locks its own targets normally.
- Aborting a batch mid-loop stops remaining workers, but a worker already
  blocked on a target semaphore can still complete its mutation before it
  observes the stop.
- Runspace isolation, privilege state, error aggregation, and cleanup need
  explicit cross-edition tests.

## Alternatives considered

- Sequential writes only: rejected by the signed performance requirement, but
  remains available through `ThrottleLimit 1`.
- Unbounded thread creation: rejected because target count can be large.
- Parallelize without canonical target locks: rejected because aliases can
  address the same descriptor and lose updates.

## See also

- [Expansion performance contract](../0006-windows-access-control-expansion.md#performance)
- [Identity batching decision](0006-prevalidate-and-deduplicate-identities.md)
