# Desired State Configuration

The module exports class-based DSC resources for every supported object family
in two shapes:

- An **exact-descriptor** resource owns a complete selected DACL or SACL.
- An **access-rule** resource owns one explicit ACE and preserves unrelated
  rules.

Compile and apply classic Windows PowerShell DSC configurations from Windows
PowerShell 5.1.

## Choose a resource shape

| Question | Use |
| --- | --- |
| Should DSC own the whole ACL and remove anything else? | Exact-descriptor resource |
| Should DSC guarantee one grant and leave the rest alone? | Access-rule resource |

## Exact-descriptor resources

- `WindowsAccessControlNtfsSecurityDescriptor`
- `WindowsAccessControlRegistryKeySecurityDescriptor`
- `WindowsAccessControlServiceSecurityDescriptor`
- `WindowsAccessControlServiceControlManagerSecurityDescriptor`
- `WindowsAccessControlProcessSecurityDescriptor`
- `WindowsAccessControlSmbShareSecurityDescriptor`
- `WindowsAccessControlADObjectSecurityDescriptor`
- `WindowsAccessControlTaskFolderSecurityDescriptor`
- `WindowsAccessControlScheduledTaskSecurityDescriptor`
- `WindowsAccessControlCertificatePrivateKeySecurityDescriptor`

```powershell
Configuration ContosoFilePermissions {
    Import-DscResource -ModuleName WindowsAccessControl

    Node localhost {
        WindowsAccessControlNtfsSecurityDescriptor DataDacl {
            Path     = 'C:\Data'
            Sections = 'Access'
            Sddl     = 'D:P(A;;FA;;;SY)(A;;0x1301BF;;;BA)'
        }
    }
}
```

Capture the desired SDDL from the corresponding `Get-*SecurityDescriptor`
command rather than writing it by hand.

Each resource owns only its selected sections. System-maintained DACL and SACL
`AUTO_INHERITED` flags are ignored during comparison, while protection flags
and every ACE remain exact.

Two conventions avoid surprises:

- Prefer a protected (`D:P`) descriptor when a resource owns an access ACL, so
  parent inheritance cannot add ACEs after convergence.
- Use a protected empty SACL (`S:P`) when audit inheritance must remain empty.
  `S:NO_ACCESS_CONTROL` represents an absent SACL that can inherit later.

## Access-rule resources

- `WindowsAccessControlNtfsAccessRule`
- `WindowsAccessControlRegistryKeyAccessRule`
- `WindowsAccessControlServiceAccessRule`
- `WindowsAccessControlServiceControlManagerAccessRule`
- `WindowsAccessControlProcessAccessRule`
- `WindowsAccessControlSmbShareAccessRule`
- `WindowsAccessControlADObjectAccessRule`
- `WindowsAccessControlTaskFolderAccessRule`
- `WindowsAccessControlScheduledTaskAccessRule`
- `WindowsAccessControlCertificatePrivateKeyAccessRule`

```powershell
WindowsAccessControlNtfsAccessRule AnalystsRead {
    Path              = 'C:\Data'
    Account           = 'CONTOSO\Analysts'
    AccessRights      = 'Read'
    AccessControlType = 'Allow'
    AppliesTo         = 'ThisFolderSubfoldersAndFiles'
    Ensure            = 'Present'
}
```

Behavior worth knowing:

- `Ensure` defaults to `Present`.
- The composite key identifies one exact explicit ACE by target, account,
  rights, allow or deny qualifier, and inheritance scope where supported.
- `Absent` removes every duplicate exact ACE without purging unrelated rights
  or the opposite qualifier.
- Account aliases are normalized by SID, and rights masks remain unsigned
  across both PowerShell editions.
- For NTFS allow rules, comparison includes the `Synchronize` bit that .NET
  adds when it materializes the ACE.

### When a narrower rule cannot converge

Windows can merge ACEs that share an account, qualifier, and scope. If a
broader superset ACE already exists, a narrower exact `Present` rule cannot
coexist with it and stays noncompliant. Model the desired superset explicitly,
or manage the whole DACL with an exact-descriptor resource.

## Family-specific requirements

### Registry resources

Registry view is part of resource identity, so a `Registry32` resource and a
`Registry64` resource manage different targets.

### Service and SCM resources

Declare at most one SCM exact-descriptor resource per node.

### Process resources

Process resources require both the PID and the creation `FILETIME`, so PID
reuse fails closed. Desired state is intentionally ephemeral and is valid only
while the pinned instance is alive. Use them for long-lived process instances.

### SMB share resources

The SMB share resources manage the access section only.

### Active Directory resources

```powershell
WindowsAccessControlADObjectAccessRule AnalystsReadProperty {
    DistinguishedName            = 'CN=Contoso App,OU=Apps,DC=contoso,DC=com'
    AllowedBaseDistinguishedName = 'OU=Apps,DC=contoso,DC=com'
    Account                      = 'CONTOSO\Analysts'
    AccessRights                 = 'ReadProperty'
    AccessControlType            = 'Allow'
    Ensure                       = 'Present'
}
```

- They manage the access section only.
- `AllowedBaseDistinguishedName` is required, so a configuration states its own
  destructive boundary.
- `Server` and `TimeoutSeconds` are optional.
- They take **no credential**. The Local Configuration Manager binds LDAP as the
  node's own identity, so a MOF never carries directory credentials.
- Supply `ObjectGuid` on `WindowsAccessControlADObjectSecurityDescriptor` when
  the configuration must fail rather than converge a recreated object that
  reuses the same distinguished name.

### Task Scheduler resources

```powershell
WindowsAccessControlTaskFolderAccessRule OperatorsTraverse {
    Path              = '\Operations'
    AllowedRootPath   = '\Operations'
    Account           = 'CONTOSO\Operators'
    AccessRights      = 'ReadAndTraverse'
    AccessControlType = 'Allow'
    AppliesTo         = 'ThisFolderSubfoldersAndTasks'
    Ensure            = 'Present'
}
```

They manage the access section only and require `AllowedRootPath`. Their
compliance check ignores ACE order, because the Task Scheduler service
canonicalizes a stored DACL after every write; protection state and every ACE
stay exact.

Windows evaluates a DACL in order, so these resources cannot detect or correct
a reordering that promotes an allow ACE above a deny ACE. Do not make them the
sole drift control for an order-sensitive deny ACE.

### Certificate private-key resources

```powershell
WindowsAccessControlCertificatePrivateKeyAccessRule WebServiceRead {
    ProviderName      = 'Microsoft Software Key Storage Provider'
    KeyName           = 'WorkloadKey'
    KeyScope          = 'Machine'
    Account           = 'CONTOSO\WebService'
    AccessRights      = 'Read'
    AccessControlType = 'Allow'
    Ensure            = 'Present'
}
```

- Both resources address the key by provider, key name, and key scope, so a MOF
  never carries a thumbprint that a renewal would invalidate, and never carries
  key material.
- `Sections` must be `Access` on the descriptor resource. Any other selection
  fails closed.
- `Ensure = 'Present'` with `AccessControlType = 'Deny'` is refused, for the
  same reason the write boundary refuses a new deny ACE. `Absent` with `Deny`
  removes a deny ACE that already exists.
- Compliance expands generic bits before comparing, because the provider stores
  a candidate ACE with the matching generic bit added. Rights are matched on
  the effective mask on both sides, so a resource naming `Read` never removes
  an account that holds `FullControl`.
- They take no credential. The LCM runs on the computer that owns the key.

## Make the module visible to the LCM

Install the module in a path visible to the SYSTEM Local Configuration Manager
process, such as `C:\Program Files\WindowsPowerShell\Modules`. A workspace or
build-output path visible to the calling shell is **not** automatically visible
to the LCM.

## Apply a configuration

```powershell
ContosoFilePermissions -OutputPath 'C:\DSC\ContosoFilePermissions'

Start-DscConfiguration `
    -Path 'C:\DSC\ContosoFilePermissions' `
    -Wait `
    -Verbose `
    -Force
```

List the resources the installed module exports:

```powershell
Get-DscResource -Module WindowsAccessControl
```

## See also

- [Backup, restore, and copy](backup-and-restore.md)
- [Active Directory objects](active-directory.md)
- [Task Scheduler](task-scheduler.md)
- [Certificate private keys](certificate-private-keys.md)
- [Enterprise portability and desired state](../../specs/0013-enterprise-portability-and-desired-state.md)
