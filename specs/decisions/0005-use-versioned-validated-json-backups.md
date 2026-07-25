# Use versioned validated JSON backups

- Status: Accepted
- Date: 2026-07-25
- Deciders: user, software-engineer agent

## Context and problem statement

Permission backups must be portable across PowerShell editions, preserve exact
Windows descriptor semantics, and remain safe to parse. Restore must not write
early records before discovering a malformed later record.

## Decision

Store backups as non-executable JSON with schema version 1. Each record carries
the canonical path, item type, selected section mask, and SDDL. Restore validates
all records and prepares all in-memory descriptors before the first filesystem
write.

Backups refuse to overwrite an existing file unless `Force` is explicit.

## Consequences

- Backup content is portable data rather than serialized executable objects.
- Unknown schemas, malformed SDDL, duplicate targets, and item-type mismatches
  fail before persistence.
- A later filesystem I/O failure can still produce a partial runtime restore;
  the validated backup can be rerun after correcting the condition.
- Because backups select target paths, they are trusted administrative input.

## Alternatives considered

- PowerShell object serialization: rejected as edition-sensitive and broader
  than the required portable contract.
- Apply records while reading: rejected because malformed later data would
  cause avoidable partial restoration.
- Silently overwrite backups: rejected because it destroys recovery evidence.

## See also

- [Security and persistence](../0004-security-and-persistence.md)
- [Requirements FR-10 and NFR-8](../0002-requirements.md)
