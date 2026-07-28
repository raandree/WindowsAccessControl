[Flags()]
enum WindowsSecurityDescriptorSection {
    Owner = 1
    Group = 2
    Access = 4
    Audit = 8
    All = 15
}

enum WindowsRegistryView {
    Default = 0
    Registry32 = 32
    Registry64 = 64
}

[Flags()]
enum WindowsActiveDirectoryRights {
    CreateChild = 0x00000001
    DeleteChild = 0x00000002
    ListChildren = 0x00000004
    Self = 0x00000008
    ReadProperty = 0x00000010
    WriteProperty = 0x00000020
    DeleteTree = 0x00000040
    ListObject = 0x00000080
    ExtendedRight = 0x00000100
    Delete = 0x00010000
    ReadControl = 0x00020000
    WriteDacl = 0x00040000
    WriteOwner = 0x00080000
    Synchronize = 0x00100000
    AccessSystemSecurity = 0x01000000
    GenericExecute = 0x00020004
    GenericWrite = 0x00020028
    GenericRead = 0x00020094
    GenericAll = 0x000F01FF
}

enum WindowsActiveDirectoryInheritance {
    None = 0
    All = 1
    Descendents = 2
    SelfAndChildren = 3
    Children = 4
}

enum WindowsAccessControlDscEnsure {
    Absent = 0
    Present = 1
}

enum WindowsSecurityObjectType {
    File = 1
    Service = 2
    RegistryKey = 4
    SmbShare = 5
    Kernel = 6
    Registry32 = 12
    Registry64 = 13
}

[Flags()]
enum WindowsSmbShareRights {
    Delete = 0x00010000
    ReadControl = 0x00020000
    WriteDac = 0x00040000
    WriteOwner = 0x00080000
    Synchronize = 0x00100000
    AccessSystemSecurity = 0x01000000
    GenericAll = 0x10000000
    GenericExecute = 0x20000000
    GenericWrite = 0x40000000
    GenericRead = -2147483648
    Read = 0x001200A9
    Change = 0x001301BF
    Full = 0x001F01FF
}

[Flags()]
enum WindowsServiceRights {
    QueryConfig = 0x00000001
    ChangeConfig = 0x00000002
    QueryStatus = 0x00000004
    EnumerateDependents = 0x00000008
    Start = 0x00000010
    Stop = 0x00000020
    PauseContinue = 0x00000040
    Interrogate = 0x00000080
    UserDefinedControl = 0x00000100
    Delete = 0x00010000
    ReadControl = 0x00020000
    WriteDac = 0x00040000
    WriteOwner = 0x00080000
    Synchronize = 0x00100000
    AccessSystemSecurity = 0x01000000
    GenericAll = 0x10000000
    GenericExecute = 0x20000000
    GenericWrite = 0x40000000
    GenericRead = -2147483648
    AllAccess = 0x000F01FF
}

[Flags()]
enum WindowsServiceControlManagerRights {
    Connect = 0x00000001
    CreateService = 0x00000002
    EnumerateService = 0x00000004
    Lock = 0x00000008
    QueryLockStatus = 0x00000010
    ModifyBootConfig = 0x00000020
    Delete = 0x00010000
    ReadControl = 0x00020000
    WriteDac = 0x00040000
    WriteOwner = 0x00080000
    AccessSystemSecurity = 0x01000000
    GenericAll = 0x10000000
    GenericExecute = 0x20000000
    GenericWrite = 0x40000000
    GenericRead = -2147483648
    AllAccess = 0x000F003F
}

[Flags()]
enum WindowsProcessRights {
    Terminate = 0x00000001
    CreateThread = 0x00000002
    SetSessionId = 0x00000004
    VmOperation = 0x00000008
    VmRead = 0x00000010
    VmWrite = 0x00000020
    DuplicateHandle = 0x00000040
    CreateProcess = 0x00000080
    SetQuota = 0x00000100
    SetInformation = 0x00000200
    QueryInformation = 0x00000400
    SuspendResume = 0x00000800
    QueryLimitedInformation = 0x00001000
    SetLimitedInformation = 0x00002000
    Delete = 0x00010000
    ReadControl = 0x00020000
    WriteDac = 0x00040000
    WriteOwner = 0x00080000
    Synchronize = 0x00100000
    AccessSystemSecurity = 0x01000000
    GenericAll = 0x10000000
    GenericExecute = 0x20000000
    GenericWrite = 0x40000000
    GenericRead = -2147483648
    AllAccess = 0x001FFFFF
}

$windowsAccessControlEnums = @{
    WindowsSecurityDescriptorSection   = [WindowsSecurityDescriptorSection]
    WindowsRegistryView                = [WindowsRegistryView]
    WindowsActiveDirectoryRights       = [WindowsActiveDirectoryRights]
    WindowsActiveDirectoryInheritance  = [WindowsActiveDirectoryInheritance]
    WindowsAccessControlDscEnsure      = [WindowsAccessControlDscEnsure]
    WindowsSecurityObjectType          = [WindowsSecurityObjectType]
    WindowsSmbShareRights              = [WindowsSmbShareRights]
    WindowsServiceRights               = [WindowsServiceRights]
    WindowsServiceControlManagerRights = [WindowsServiceControlManagerRights]
    WindowsProcessRights               = [WindowsProcessRights]
}
$typeAccelerators = [psobject].Assembly.GetType(
    'System.Management.Automation.TypeAccelerators'
)
foreach ($enumName in $windowsAccessControlEnums.Keys) {
    $registeredType = $typeAccelerators::Get[$enumName]
    if ($registeredType -ne $windowsAccessControlEnums[$enumName]) {
        if ($registeredType) {
            $null = $typeAccelerators::Remove($enumName)
        }
        $typeAccelerators::Add($enumName, $windowsAccessControlEnums[$enumName])
    }
}

$registeredWindowsAccessControlEnums = $windowsAccessControlEnums.Clone()
$module = $ExecutionContext.SessionState.Module
$module.OnRemove = {
    $accelerators = [psobject].Assembly.GetType(
        'System.Management.Automation.TypeAccelerators'
    )
    foreach ($enumName in $registeredWindowsAccessControlEnums.Keys) {
        if ($accelerators::Get[$enumName] -eq $registeredWindowsAccessControlEnums[$enumName]) {
            $null = $accelerators::Remove($enumName)
        }
    }
}.GetNewClosure()
