# Require backup schema version 2 for enterprise targets

- Status: Accepted
- Date: 2026-07-28
- Deciders: user, software-engineer agent

## Context and problem statement

Backup schema version 1 identifies local object families by local canonical
target metadata. SMB shares require explicit server identity. Active Directory
objects require forest/domain authority, selected DC, immutable object GUID,
and current distinguished name. Adding those fields changes canonical identity,
replay, omission, and downgrade behavior.

## Decision

- Do not encode SMB-share or AD-object records as schema version 1.
- Design schema version 2 as a separately accepted envelope contract before
  either family participates in unified backup or restore.
- Bind version 2 records to object family, explicit authority, immutable target
  identity where available, selected descriptor sections, and downgrade rules.
- Retain version 1 read compatibility for existing local families.
- Ship the first DACL-management increment without enterprise backup/restore.

## Consequences

- Existing backups remain stable and cannot be reinterpreted as remote targets.
- The first SMB and AD commands are useful without weakening replay or
  completeness guarantees.
- Enterprise backup, DSC, and migration work remains independently reviewable.

## Alternatives considered

- Add optional fields to version 1: rejected because old consumers could ignore
  authority and immutable identity fields while still accepting the record.
- Store only a UNC or distinguished name: rejected because names can alias,
  move, or be replayed against a different authority.

## See also

- [Security and persistence](../0004-security-and-persistence.md)
- [SMB share and Active Directory DACL management](../0009-smb-share-and-active-directory-dacl-management.md)
