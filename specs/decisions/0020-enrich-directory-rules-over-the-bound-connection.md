# Enrich directory rules over the bound LDAP connection

- Status: Accepted
- Date: 2026-07-29
- Deciders: user, software-engineer agent

## Context and problem statement

`Get-ADObjectAccessRule` reported `IsInherited` without naming the ancestor an
ACE came from, while `Get-NTFSAccessRule` and `Get-RegistryKeyAccessRule` both
expose `InheritedFrom`. It also emitted raw `ObjectTypeGuid` and
`InheritedObjectTypeGuid` values such as
`4c164200-20c0-11d0-a768-00aa006e0529`, which name a property set or class only
after a schema lookup.

Both enrichments have a Windows-supplied source that ignores the server this
module is already bound to.

A live probe established the constraint for provenance.
`GetInheritanceSourceW` does support `SE_DS_OBJECT` and `SE_DS_OBJECT_ALL`: for
a lab user object it returned `DC=contoso,DC=com` with a generation gap of 3 for
every inherited ACE and a null ancestor for every explicit ACE. It rejects a
server-qualified object name with `ERROR_FILE_NOT_FOUND`, takes no credential,
and locates its own domain controller through the calling computer's domain
context. ADR 0015 requires that an Active Directory command name its authority
and consistency point explicitly, so a second implicitly located domain
controller cannot supply part of one result.

The same asymmetry applies to schema names. `System.DirectoryServices` and the
`ActiveDirectory` module resolve schema and extended-right GUIDs through an
implicit binding rather than the bound connection.

## Decision

- Resolve inheritance provenance by walking the object's ancestor chain over the
    same signed and sealed connection that returned the descriptor, up to and
    including the default naming context head.
- Match an inherited ACE to the nearest ancestor that holds an equivalent
    *explicit* inheritable ACE. Compare security identifier, unsigned access
    mask, qualifier, and both object GUIDs, and ignore propagation flags because
    Windows rewrites them during propagation.
- Reject an ancestor candidate that is not container-inheritable, that is itself
    inherited, that carries `NoPropagateInherit` more than one level above the
    object, or whose propagation flags cannot produce the inherited ACE actually
    observed on the object. Consume each matched ancestor ACE once so a
    duplicated inherited ACE resolves to the next ancestor rather than
    collapsing onto one.
- Stop collecting ancestors above a protected DACL, because nothing above it can
    propagate through it.
- Truncate the walk at the first ancestor the caller cannot read and report no
    source beyond it, rather than naming a more distant ancestor that may be the
    wrong origin.
- Resolve `ObjectTypeGuid` and `InheritedObjectTypeGuid` to `ObjectTypeName` and
    `InheritedObjectTypeName` through one schema-partition search and one
    extended-rights search over the same connection, cache only resolved names
    per forest schema for the session, and keep the GUID properties unchanged.
    An unresolved GUID is not cached, because it can be unresolved only for the
    caller who looked it up.
- Degrade either enrichment through a non-terminating error when its lookup
    fails, instead of discarding a successful descriptor read.
- Skip the ancestor walk entirely when `ExcludeInherited` is requested.

## Consequences

- Directory provenance is inferred, unlike the filesystem and registry families
    that call a Windows API. ADR 0019 forbids inference for the registry because
    a usable native call exists there; no usable native call exists here.
- The inference agrees with the native oracle on the reference object: both
    resolve all 26 inherited ACEs of the lab user to `DC=contoso,DC=com`.
- Provenance and names come from the same domain controller, credential, and
    channel as the descriptor, so one result has one authority.
- A delegated caller who cannot read an ancestor sees an empty `InheritedFrom`
    for ACEs that originate above it. That is the already-defined "source cannot
    be identified" state, so no new output contract is introduced.
- A concurrent ancestor change between the object read and the ancestor walk can
    still return a source that no longer matches the reported ACE.
- Reading inherited rules costs one base search per ancestor plus at most two
    schema searches per distinct GUID set. Repeat calls in one session reuse the
    GUID cache.
- Two identical explicit ACEs on one ancestor and its parent are distinguished
    only by ACL order, which is the order Windows propagates them in.
- Degradation uses the same non-terminating error the registry family uses, so a
    caller who sets `ErrorAction` to `Stop` still loses the target, and batch
    metrics count an enrichment failure as a target failure.

## Alternatives considered

- Call `GetInheritanceSourceW` with `SE_DS_OBJECT`: rejected because it silently
    binds to a locally located domain controller, ignores `Server` and
    `Credential`, and would mix two consistency points in one result.
- Report the immediate parent as the source: rejected because Windows reports
    the container that holds the explicit ACE, which is usually higher.
- Resolve schema names through the `ActiveDirectory` module: rejected because it
    adds a runtime dependency and binds outside the module's channel contract.
- Read the whole schema once: rejected because a targeted filtered search per
    distinct GUID set is smaller and already cached.

## See also

- [SMB share and Active Directory DACL management](../0009-smb-share-and-active-directory-dacl-management.md)
- [Enterprise authority decision](0015-use-local-smb-and-signed-sealed-ldap.md)
- [Registry provenance decision](0019-report-null-registry-provenance-for-wow64-views.md)
