function Initialize-WindowsAccessControlNativeType {
    [CmdletBinding()]
    param()

    if ([System.Management.Automation.PSTypeName]'WindowsAccessControl.NativeMethods'.Type) {
        return
    }

    $typeDefinition = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace WindowsAccessControl
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Luid
    {
        public UInt32 LowPart;
        public Int32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NativeFileTime
    {
        public UInt32 LowDateTime;
        public UInt32 HighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LuidAndAttributes
    {
        public Luid Luid;
        public UInt32 Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TokenPrivileges
    {
        public UInt32 PrivilegeCount;
        public LuidAndAttributes Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PrivilegeSet
    {
        public UInt32 PrivilegeCount;
        public UInt32 Control;
        public LuidAndAttributes Privilege;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct AuthzAccessRequest
    {
        public UInt32 DesiredAccess;
        public IntPtr PrincipalSelfSid;
        public IntPtr ObjectTypeList;
        public UInt32 ObjectTypeListLength;
        public IntPtr OptionalArguments;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct AuthzAccessReply
    {
        public UInt32 ResultListLength;
        public IntPtr GrantedAccessMask;
        public IntPtr SaclEvaluationResults;
        public IntPtr Error;
    }

    public sealed class TokenPrivilegeInfo
    {
        public string Name { get; private set; }
        public UInt32 Attributes { get; private set; }
        public bool Enabled { get; private set; }
        public bool EnabledByDefault { get; private set; }
        public bool UsedForAccess { get; private set; }

        internal TokenPrivilegeInfo(string name, UInt32 attributes)
        {
            Name = name;
            Attributes = attributes;
            EnabledByDefault = (attributes & 0x00000001) != 0;
            Enabled = (attributes & 0x00000002) != 0;
            UsedForAccess = (attributes & 0x80000000) != 0;
        }
    }

    public static class NativeMethods
    {
        private sealed class PrivilegeLeaseState
        {
            public Int32 Count;
            public bool WasEnabled;
        }

        private sealed class PrivilegeLease : IDisposable
        {
            private string privilegeName;
            private Int32 disposed;

            internal PrivilegeLease(string name)
            {
                privilegeName = name;
            }

            public void Dispose()
            {
                if (Interlocked.Exchange(ref disposed, 1) == 0)
                {
                    ReleasePrivilege(privilegeName);
                }
            }
        }

        private static readonly object PrivilegeLeaseLock = new object();
        private static readonly Dictionary<string, PrivilegeLeaseState> PrivilegeLeases =
            new Dictionary<string, PrivilegeLeaseState>(StringComparer.OrdinalIgnoreCase);

        private const UInt32 TokenQuery = 0x0008;
        private const UInt32 TokenAdjustPrivileges = 0x0020;
        private const UInt32 PrivilegeEnabled = 0x0002;
        private const UInt32 PrivilegeSetAllNecessary = 0x0001;
        private const Int32 ErrorNotAllAssigned = 1300;
        private const Int32 ErrorInsufficientBuffer = 122;
        private const Int32 TokenPrivilegesInformationClass = 3;
        private const UInt32 AuthzResourceManagerNoAudit = 0x0001;
        private const UInt32 MaximumAllowed = 0x02000000;
        private const UInt32 OwnerSecurityInformation = 0x00000001;
        private const UInt32 GroupSecurityInformation = 0x00000002;
        private const UInt32 DaclSecurityInformation = 0x00000004;
        private const UInt32 SaclSecurityInformation = 0x00000008;
        private const UInt32 AllSecurityInformation = 0x0000000F;
        private const UInt32 ProtectedDaclSecurityInformation = 0x80000000;
        private const UInt32 UnprotectedDaclSecurityInformation = 0x20000000;
        private const UInt32 ProtectedSaclSecurityInformation = 0x40000000;
        private const UInt32 UnprotectedSaclSecurityInformation = 0x10000000;
        private const UInt16 DaclProtectedControl = 0x1000;
        private const UInt16 SaclProtectedControl = 0x2000;
        private const UInt32 ReadControl = 0x00020000;
        private const UInt32 WriteDac = 0x00040000;
        private const UInt32 WriteOwner = 0x00080000;
        private const UInt32 AccessSystemSecurity = 0x01000000;
        private const UInt32 ProcessQueryLimitedInformation = 0x00001000;
        private const UInt32 FileObject = 1;
        private const UInt32 ServiceObject = 2;
        private const UInt32 KernelObject = 6;

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            UInt32 desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            UInt32 processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            IntPtr processHandle,
            out NativeFileTime creationTime,
            out NativeFileTime exitTime,
            out NativeFileTime kernelTime,
            out NativeFileTime userTime);

        [DllImport("kernel32.dll")]
        private static extern void SetLastError(UInt32 errorCode);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(
            IntPtr processHandle,
            UInt32 desiredAccess,
            out IntPtr tokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "OpenSCManagerW", SetLastError = true)]
        private static extern IntPtr OpenServiceControlManager(
            string machineName,
            string databaseName,
            UInt32 desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr serviceHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(
            IntPtr tokenHandle,
            Int32 tokenInformationClass,
            IntPtr tokenInformation,
            UInt32 tokenInformationLength,
            out UInt32 returnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValue(
            string systemName,
            string name,
            out Luid luid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeName(
            string systemName,
            ref Luid luid,
            StringBuilder name,
            ref UInt32 nameLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr tokenHandle,
            [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
            ref TokenPrivileges newState,
            UInt32 bufferLength,
            IntPtr previousState,
            IntPtr returnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PrivilegeCheck(
            IntPtr clientToken,
            ref PrivilegeSet requiredPrivileges,
            [MarshalAs(UnmanagedType.Bool)] out bool result);

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AuthzInitializeResourceManager(
            UInt32 flags,
            IntPtr dynamicAccessCheck,
            IntPtr computeDynamicGroups,
            IntPtr freeDynamicGroups,
            string resourceManagerName,
            out IntPtr resourceManager);

        [DllImport("authz.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AuthzInitializeContextFromSid(
            UInt32 flags,
            IntPtr userSid,
            IntPtr resourceManager,
            IntPtr expirationTime,
            Luid identifier,
            IntPtr dynamicGroupArguments,
            out IntPtr clientContext);

        [DllImport("authz.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AuthzAccessCheck(
            UInt32 flags,
            IntPtr clientContext,
            ref AuthzAccessRequest request,
            IntPtr auditEvent,
            IntPtr securityDescriptor,
            IntPtr optionalSecurityDescriptorArray,
            UInt32 optionalSecurityDescriptorCount,
            ref AuthzAccessReply reply,
            IntPtr accessCheckResults);

        [DllImport("authz.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AuthzFreeContext(IntPtr clientContext);

        [DllImport("authz.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AuthzFreeResourceManager(IntPtr resourceManager);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetNamedSecurityInfoW")]
        private static extern UInt32 GetNamedSecurityInfo(
            string objectName,
            UInt32 objectType,
            UInt32 securityInformation,
            IntPtr owner,
            IntPtr group,
            IntPtr dacl,
            IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "SetNamedSecurityInfoW")]
        private static extern UInt32 SetNamedSecurityInfo(
            string objectName,
            UInt32 objectType,
            UInt32 securityInformation,
            IntPtr owner,
            IntPtr group,
            IntPtr dacl,
            IntPtr sacl);

        [DllImport("advapi32.dll")]
        private static extern UInt32 GetSecurityInfo(
            IntPtr handle,
            UInt32 objectType,
            UInt32 securityInformation,
            IntPtr owner,
            IntPtr group,
            IntPtr dacl,
            IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport("advapi32.dll")]
        private static extern UInt32 SetSecurityInfo(
            IntPtr handle,
            UInt32 objectType,
            UInt32 securityInformation,
            IntPtr owner,
            IntPtr group,
            IntPtr dacl,
            IntPtr sacl);

        [DllImport("advapi32.dll")]
        private static extern UInt32 GetSecurityDescriptorLength(IntPtr securityDescriptor);

        [DllImport("advapi32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsValidSecurityDescriptor(IntPtr securityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSecurityDescriptorOwner(
            IntPtr securityDescriptor,
            out IntPtr owner,
            [MarshalAs(UnmanagedType.Bool)] out bool ownerDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSecurityDescriptorGroup(
            IntPtr securityDescriptor,
            out IntPtr group,
            [MarshalAs(UnmanagedType.Bool)] out bool groupDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSecurityDescriptorDacl(
            IntPtr securityDescriptor,
            [MarshalAs(UnmanagedType.Bool)] out bool daclPresent,
            out IntPtr dacl,
            [MarshalAs(UnmanagedType.Bool)] out bool daclDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSecurityDescriptorSacl(
            IntPtr securityDescriptor,
            [MarshalAs(UnmanagedType.Bool)] out bool saclPresent,
            out IntPtr sacl,
            [MarshalAs(UnmanagedType.Bool)] out bool saclDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSecurityDescriptorControl(
            IntPtr securityDescriptor,
            out UInt16 control,
            out UInt32 revision);

        private static void ValidateSecurityDescriptor(byte[] securityDescriptor)
        {
            if (securityDescriptor == null || securityDescriptor.Length == 0)
            {
                throw new ArgumentException(
                    "A security descriptor is required.",
                    "securityDescriptor");
            }
        }

        private static void ValidateSecurityDescriptorPointer(IntPtr securityDescriptor)
        {
            if (securityDescriptor == IntPtr.Zero ||
                !IsValidSecurityDescriptor(securityDescriptor))
            {
                throw new ArgumentException(
                    "The security descriptor is not structurally valid.",
                    "securityDescriptor");
            }
        }

        private static byte[] CopySecurityDescriptor(IntPtr securityDescriptor)
        {
            if (securityDescriptor == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    "Windows returned a null security descriptor.");
            }

            UInt32 length = GetSecurityDescriptorLength(securityDescriptor);
            if (length == 0 || length > Int32.MaxValue)
            {
                throw new InvalidOperationException(
                    "Windows returned an invalid security descriptor length.");
            }

            byte[] result = new byte[(Int32)length];
            Marshal.Copy(securityDescriptor, result, 0, result.Length);
            return result;
        }

        private static UInt32 GetSecurityInformationPointers(
            IntPtr securityDescriptor,
            UInt32 sections,
            out IntPtr owner,
            out IntPtr group,
            out IntPtr dacl,
            out IntPtr sacl)
        {
            owner = IntPtr.Zero;
            group = IntPtr.Zero;
            dacl = IntPtr.Zero;
            sacl = IntPtr.Zero;
            UInt32 securityInformation = sections & AllSecurityInformation;
            bool defaulted;
            bool daclPresent = false;
            bool saclPresent = false;

            if ((sections & OwnerSecurityInformation) != 0 &&
                !GetSecurityDescriptorOwner(securityDescriptor, out owner, out defaulted))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if ((sections & GroupSecurityInformation) != 0 &&
                !GetSecurityDescriptorGroup(securityDescriptor, out group, out defaulted))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if ((sections & DaclSecurityInformation) != 0 &&
                !GetSecurityDescriptorDacl(
                    securityDescriptor,
                    out daclPresent,
                    out dacl,
                    out defaulted))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if ((sections & DaclSecurityInformation) != 0 &&
                (!daclPresent || dacl == IntPtr.Zero))
            {
                throw new InvalidOperationException(
                    "The supplied security descriptor does not contain a non-null DACL.");
            }
            if ((sections & SaclSecurityInformation) != 0 &&
                !GetSecurityDescriptorSacl(
                    securityDescriptor,
                    out saclPresent,
                    out sacl,
                    out defaulted))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if ((sections & SaclSecurityInformation) != 0 &&
                (!saclPresent || sacl == IntPtr.Zero))
            {
                throw new InvalidOperationException(
                    "The supplied security descriptor does not contain a SACL.");
            }

            if ((sections & (DaclSecurityInformation | SaclSecurityInformation)) != 0)
            {
                UInt16 control;
                UInt32 revision;
                if (!GetSecurityDescriptorControl(
                    securityDescriptor,
                    out control,
                    out revision))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if ((sections & DaclSecurityInformation) != 0)
                {
                    securityInformation |= (control & DaclProtectedControl) != 0
                        ? ProtectedDaclSecurityInformation
                        : UnprotectedDaclSecurityInformation;
                }
                if ((sections & SaclSecurityInformation) != 0)
                {
                    securityInformation |= (control & SaclProtectedControl) != 0
                        ? ProtectedSaclSecurityInformation
                        : UnprotectedSaclSecurityInformation;
                }
            }

            return securityInformation;
        }

        private static void ValidateHandle(IntPtr handle)
        {
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                throw new ArgumentException("A valid native handle is required.", "handle");
            }
        }

        private static Int64 ToFileTime(NativeFileTime value)
        {
            UInt64 result = ((UInt64)value.HighDateTime << 32) | value.LowDateTime;
            return unchecked((Int64)result);
        }

        private static void VerifyProcessCreationTime(
            IntPtr processHandle,
            Int64 expectedCreationTime)
        {
            if (expectedCreationTime <= 0)
            {
                throw new ArgumentOutOfRangeException(
                    "expectedCreationTime",
                    "A positive process creation identity is required.");
            }

            NativeFileTime creationTime;
            NativeFileTime exitTime;
            NativeFileTime kernelTime;
            NativeFileTime userTime;
            if (!GetProcessTimes(
                processHandle,
                out creationTime,
                out exitTime,
                out kernelTime,
                out userTime))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if (ToFileTime(creationTime) != expectedCreationTime)
            {
                throw new InvalidOperationException(
                    "The process creation identity no longer matches the selected process.");
            }
        }

        private static IntPtr OpenProcessForSecurity(
            Int32 processId,
            UInt32 sections,
            bool write)
        {
            if (processId <= 0)
            {
                throw new ArgumentOutOfRangeException("processId");
            }

            UInt32 desiredAccess = ProcessQueryLimitedInformation;
            if ((sections & (OwnerSecurityInformation |
                GroupSecurityInformation |
                DaclSecurityInformation)) != 0)
            {
                if (write)
                {
                    if ((sections & (OwnerSecurityInformation | GroupSecurityInformation)) != 0)
                    {
                        desiredAccess |= WriteOwner;
                    }
                    if ((sections & DaclSecurityInformation) != 0)
                    {
                        desiredAccess |= WriteDac;
                    }
                }
                else
                {
                    desiredAccess |= ReadControl;
                }
            }
            if ((sections & SaclSecurityInformation) != 0)
            {
                desiredAccess |= AccessSystemSecurity;
            }

            IntPtr handle = OpenProcess(desiredAccess, false, unchecked((UInt32)processId));
            if (handle == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return handle;
        }

        private static IntPtr OpenServiceControlManagerForSecurity(
            UInt32 sections,
            bool write)
        {
            UInt32 desiredAccess = 0;
            if ((sections & (OwnerSecurityInformation |
                GroupSecurityInformation |
                DaclSecurityInformation)) != 0)
            {
                if (write)
                {
                    if ((sections & (OwnerSecurityInformation | GroupSecurityInformation)) != 0)
                    {
                        desiredAccess |= WriteOwner;
                    }
                    if ((sections & DaclSecurityInformation) != 0)
                    {
                        desiredAccess |= WriteDac;
                    }
                }
                else
                {
                    desiredAccess |= ReadControl;
                }
            }
            if ((sections & SaclSecurityInformation) != 0)
            {
                desiredAccess |= AccessSystemSecurity;
            }
            if (desiredAccess == 0)
            {
                throw new ArgumentOutOfRangeException("sections");
            }

            IntPtr handle = OpenServiceControlManager(null, null, desiredAccess);
            if (handle == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return handle;
        }

        public static byte[] GetNamedSecurityDescriptor(
            string objectName,
            UInt32 objectType,
            UInt32 sections)
        {
            if (String.IsNullOrWhiteSpace(objectName))
            {
                throw new ArgumentException("An object name is required.", "objectName");
            }
            if ((sections & AllSecurityInformation) == 0)
            {
                throw new ArgumentOutOfRangeException("sections");
            }

            IntPtr securityDescriptor = IntPtr.Zero;
            UInt32 result = GetNamedSecurityInfo(
                objectName,
                objectType,
                sections & AllSecurityInformation,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out securityDescriptor);
            if (result != 0)
            {
                throw new Win32Exception((Int32)result);
            }
            try
            {
                return CopySecurityDescriptor(securityDescriptor);
            }
            finally
            {
                if (securityDescriptor != IntPtr.Zero)
                {
                    LocalFree(securityDescriptor);
                }
            }
        }

        public static void SetNamedSecurityDescriptor(
            string objectName,
            UInt32 objectType,
            UInt32 sections,
            byte[] securityDescriptor)
        {
            if (String.IsNullOrWhiteSpace(objectName))
            {
                throw new ArgumentException("An object name is required.", "objectName");
            }
            ValidateSecurityDescriptor(securityDescriptor);
            IntPtr descriptorPointer = IntPtr.Zero;
            try
            {
                descriptorPointer = Marshal.AllocHGlobal(securityDescriptor.Length);
                Marshal.Copy(securityDescriptor, 0, descriptorPointer, securityDescriptor.Length);
                ValidateSecurityDescriptorPointer(descriptorPointer);
                IntPtr owner;
                IntPtr group;
                IntPtr dacl;
                IntPtr sacl;
                UInt32 securityInformation = GetSecurityInformationPointers(
                    descriptorPointer,
                    sections,
                    out owner,
                    out group,
                    out dacl,
                    out sacl);
                UInt32 result = SetNamedSecurityInfo(
                    objectName,
                    objectType,
                    securityInformation,
                    owner,
                    group,
                    dacl,
                    sacl);
                if (result != 0)
                {
                    throw new Win32Exception((Int32)result);
                }
            }
            finally
            {
                if (descriptorPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(descriptorPointer);
                }
            }
        }

        public static byte[] GetHandleSecurityDescriptor(
            IntPtr handle,
            UInt32 objectType,
            UInt32 sections)
        {
            ValidateHandle(handle);
            IntPtr securityDescriptor = IntPtr.Zero;
            UInt32 result = GetSecurityInfo(
                handle,
                objectType,
                sections & AllSecurityInformation,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out securityDescriptor);
            if (result != 0)
            {
                throw new Win32Exception((Int32)result);
            }
            try
            {
                return CopySecurityDescriptor(securityDescriptor);
            }
            finally
            {
                if (securityDescriptor != IntPtr.Zero)
                {
                    LocalFree(securityDescriptor);
                }
            }
        }

        public static void SetHandleSecurityDescriptor(
            IntPtr handle,
            UInt32 objectType,
            UInt32 sections,
            byte[] securityDescriptor)
        {
            ValidateHandle(handle);
            ValidateSecurityDescriptor(securityDescriptor);
            IntPtr descriptorPointer = IntPtr.Zero;
            try
            {
                descriptorPointer = Marshal.AllocHGlobal(securityDescriptor.Length);
                Marshal.Copy(securityDescriptor, 0, descriptorPointer, securityDescriptor.Length);
                ValidateSecurityDescriptorPointer(descriptorPointer);
                IntPtr owner;
                IntPtr group;
                IntPtr dacl;
                IntPtr sacl;
                UInt32 securityInformation = GetSecurityInformationPointers(
                    descriptorPointer,
                    sections,
                    out owner,
                    out group,
                    out dacl,
                    out sacl);
                UInt32 result = SetSecurityInfo(
                    handle,
                    objectType,
                    securityInformation,
                    owner,
                    group,
                    dacl,
                    sacl);
                if (result != 0)
                {
                    throw new Win32Exception((Int32)result);
                }
            }
            finally
            {
                if (descriptorPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(descriptorPointer);
                }
            }
        }

        public static byte[] GetServiceControlManagerSecurityDescriptor(UInt32 sections)
        {
            IntPtr serviceControlManager = OpenServiceControlManagerForSecurity(
                sections,
                false);
            try
            {
                return GetHandleSecurityDescriptor(
                    serviceControlManager,
                    ServiceObject,
                    sections);
            }
            finally
            {
                CloseServiceHandle(serviceControlManager);
            }
        }

        public static void SetServiceControlManagerSecurityDescriptor(
            UInt32 sections,
            byte[] securityDescriptor)
        {
            IntPtr serviceControlManager = OpenServiceControlManagerForSecurity(
                sections,
                true);
            try
            {
                SetHandleSecurityDescriptor(
                    serviceControlManager,
                    ServiceObject,
                    sections,
                    securityDescriptor);
            }
            finally
            {
                CloseServiceHandle(serviceControlManager);
            }
        }

        public static byte[] GetProcessSecurityDescriptor(
            Int32 processId,
            Int64 expectedCreationTime,
            UInt32 sections)
        {
            IntPtr processHandle = OpenProcessForSecurity(processId, sections, false);
            try
            {
                VerifyProcessCreationTime(processHandle, expectedCreationTime);
                return GetHandleSecurityDescriptor(processHandle, KernelObject, sections);
            }
            finally
            {
                CloseHandle(processHandle);
            }
        }

        public static void SetProcessSecurityDescriptor(
            Int32 processId,
            Int64 expectedCreationTime,
            UInt32 sections,
            byte[] securityDescriptor)
        {
            IntPtr processHandle = OpenProcessForSecurity(processId, sections, true);
            try
            {
                VerifyProcessCreationTime(processHandle, expectedCreationTime);
                SetHandleSecurityDescriptor(
                    processHandle,
                    KernelObject,
                    sections,
                    securityDescriptor);
            }
            finally
            {
                CloseHandle(processHandle);
            }
        }

        public static void SetFileSystemAclProtection(
            string path,
            byte[] securityDescriptor,
            bool setAccess,
            bool accessProtected,
            bool setAudit,
            bool auditProtected)
        {
            ValidateSecurityDescriptor(securityDescriptor);

            IntPtr descriptorPointer = IntPtr.Zero;
            try
            {
                descriptorPointer = Marshal.AllocHGlobal(securityDescriptor.Length);
                Marshal.Copy(
                    securityDescriptor,
                    0,
                    descriptorPointer,
                    securityDescriptor.Length);
                ValidateSecurityDescriptorPointer(descriptorPointer);

                UInt32 securityInformation = 0;
                IntPtr daclPointer = IntPtr.Zero;
                IntPtr saclPointer = IntPtr.Zero;
                bool aclPresent;
                bool aclDefaulted;

                if (setAccess)
                {
                    if (!GetSecurityDescriptorDacl(
                        descriptorPointer,
                        out aclPresent,
                        out daclPointer,
                        out aclDefaulted))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    if (!aclPresent || daclPointer == IntPtr.Zero)
                    {
                        throw new InvalidOperationException(
                            "The supplied security descriptor does not contain a non-null DACL.");
                    }
                    securityInformation |= DaclSecurityInformation;
                    securityInformation |= accessProtected
                        ? ProtectedDaclSecurityInformation
                        : UnprotectedDaclSecurityInformation;
                }
                if (setAudit)
                {
                    if (!GetSecurityDescriptorSacl(
                        descriptorPointer,
                        out aclPresent,
                        out saclPointer,
                        out aclDefaulted))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    if (!aclPresent || saclPointer == IntPtr.Zero)
                    {
                        throw new InvalidOperationException(
                            "The supplied security descriptor does not contain a SACL.");
                    }
                    securityInformation |= SaclSecurityInformation;
                    securityInformation |= auditProtected
                        ? ProtectedSaclSecurityInformation
                        : UnprotectedSaclSecurityInformation;
                }

                UInt32 result = SetNamedSecurityInfo(
                    path,
                    FileObject,
                    securityInformation,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    daclPointer,
                    saclPointer);
                if (result != 0)
                {
                    throw new Win32Exception((Int32)result);
                }
            }
            finally
            {
                if (descriptorPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(descriptorPointer);
                }
            }
        }

        public static IDisposable AcquirePrivilege(string privilegeName)
        {
            if (String.IsNullOrWhiteSpace(privilegeName))
            {
                throw new ArgumentException(
                    "A privilege name is required.",
                    "privilegeName");
            }

            lock (PrivilegeLeaseLock)
            {
                PrivilegeLeaseState state;
                if (PrivilegeLeases.TryGetValue(privilegeName, out state))
                {
                    state.Count++;
                    return new PrivilegeLease(privilegeName);
                }

                TokenPrivilegeInfo privilege = null;
                foreach (TokenPrivilegeInfo candidate in GetTokenPrivileges())
                {
                    if (String.Equals(
                        candidate.Name,
                        privilegeName,
                        StringComparison.OrdinalIgnoreCase))
                    {
                        privilege = candidate;
                        break;
                    }
                }
                if (privilege == null)
                {
                    throw new UnauthorizedAccessException(
                        "The process token does not contain privilege '" +
                        privilegeName + "'.");
                }

                state = new PrivilegeLeaseState();
                state.Count = 1;
                state.WasEnabled = privilege.Enabled;
                if (!state.WasEnabled)
                {
                    SetPrivilege(privilegeName, true);
                }
                PrivilegeLeases.Add(privilegeName, state);
                return new PrivilegeLease(privilegeName);
            }
        }

        private static void ReleasePrivilege(string privilegeName)
        {
            lock (PrivilegeLeaseLock)
            {
                PrivilegeLeaseState state;
                if (!PrivilegeLeases.TryGetValue(privilegeName, out state))
                {
                    return;
                }

                state.Count--;
                if (state.Count > 0)
                {
                    return;
                }

                try
                {
                    if (!state.WasEnabled)
                    {
                        SetPrivilege(privilegeName, false);
                    }
                    PrivilegeLeases.Remove(privilegeName);
                }
                catch
                {
                    state.Count = 0;
                    throw;
                }
            }
        }

        private static string GetPrivilegeName(Luid luid)
        {
            UInt32 nameLength = 0;
            LookupPrivilegeName(null, ref luid, null, ref nameLength);
            Int32 error = Marshal.GetLastWin32Error();
            if (nameLength == 0 && error != ErrorInsufficientBuffer)
            {
                throw new Win32Exception(error);
            }

            StringBuilder name = new StringBuilder((Int32)nameLength + 1);
            UInt32 bufferLength = (UInt32)name.Capacity;
            if (!LookupPrivilegeName(null, ref luid, name, ref bufferLength))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return name.ToString();
        }

        public static TokenPrivilegeInfo[] GetTokenPrivileges()
        {
            IntPtr tokenHandle;
            if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out tokenHandle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            IntPtr tokenInformation = IntPtr.Zero;
            try
            {
                UInt32 requiredLength;
                GetTokenInformation(
                    tokenHandle,
                    TokenPrivilegesInformationClass,
                    IntPtr.Zero,
                    0,
                    out requiredLength);
                Int32 error = Marshal.GetLastWin32Error();
                if (requiredLength == 0)
                {
                    throw new InvalidOperationException(
                        "Windows returned an empty token privilege buffer.");
                }
                if (error != ErrorInsufficientBuffer)
                {
                    throw new Win32Exception(error);
                }

                tokenInformation = Marshal.AllocHGlobal((Int32)requiredLength);
                if (!GetTokenInformation(
                    tokenHandle,
                    TokenPrivilegesInformationClass,
                    tokenInformation,
                    requiredLength,
                    out requiredLength))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                UInt32 privilegeCount = unchecked((UInt32)Marshal.ReadInt32(tokenInformation));
                Int32 privilegeOffset = (Int32)Marshal.OffsetOf(
                    typeof(TokenPrivileges),
                    "Privileges");
                Int32 privilegeSize = Marshal.SizeOf(typeof(LuidAndAttributes));
                List<TokenPrivilegeInfo> result = new List<TokenPrivilegeInfo>();

                for (UInt32 index = 0; index < privilegeCount; index++)
                {
                    IntPtr privilegePointer = IntPtr.Add(
                        tokenInformation,
                        privilegeOffset + ((Int32)index * privilegeSize));
                    LuidAndAttributes privilege = (LuidAndAttributes)Marshal.PtrToStructure(
                        privilegePointer,
                        typeof(LuidAndAttributes));
                    result.Add(new TokenPrivilegeInfo(
                        GetPrivilegeName(privilege.Luid),
                        privilege.Attributes));
                }

                return result.ToArray();
            }
            finally
            {
                if (tokenInformation != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(tokenInformation);
                }
                CloseHandle(tokenHandle);
            }
        }

        public static bool IsPrivilegeEnabled(string privilegeName)
        {
            IntPtr tokenHandle;
            if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out tokenHandle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                Luid luid;
                if (!LookupPrivilegeValue(null, privilegeName, out luid))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                PrivilegeSet privilegeSet = new PrivilegeSet();
                privilegeSet.PrivilegeCount = 1;
                privilegeSet.Control = PrivilegeSetAllNecessary;
                privilegeSet.Privilege = new LuidAndAttributes();
                privilegeSet.Privilege.Luid = luid;
                privilegeSet.Privilege.Attributes = PrivilegeEnabled;

                bool enabled;
                if (!PrivilegeCheck(tokenHandle, ref privilegeSet, out enabled))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return enabled;
            }
            finally
            {
                CloseHandle(tokenHandle);
            }
        }

        public static void SetPrivilege(string privilegeName, bool enabled)
        {
            IntPtr tokenHandle;
            UInt32 desiredAccess = TokenQuery | TokenAdjustPrivileges;
            if (!OpenProcessToken(GetCurrentProcess(), desiredAccess, out tokenHandle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                Luid luid;
                if (!LookupPrivilegeValue(null, privilegeName, out luid))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                TokenPrivileges privileges = new TokenPrivileges();
                privileges.PrivilegeCount = 1;
                privileges.Privileges = new LuidAndAttributes();
                privileges.Privileges.Luid = luid;
                privileges.Privileges.Attributes = enabled ? PrivilegeEnabled : 0;

                SetLastError(0);
                if (!AdjustTokenPrivileges(
                    tokenHandle,
                    false,
                    ref privileges,
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                Int32 error = Marshal.GetLastWin32Error();
                if (error == ErrorNotAllAssigned)
                {
                    if (!enabled)
                    {
                        return;
                    }
                    throw new UnauthorizedAccessException(
                        "The process token does not contain privilege '" + privilegeName + "'.");
                }
                if (error != 0)
                {
                    throw new Win32Exception(error);
                }
            }
            finally
            {
                CloseHandle(tokenHandle);
            }
        }

        public static UInt32 GetEffectiveAccess(byte[] securityDescriptor, byte[] userSid)
        {
            if (securityDescriptor == null || securityDescriptor.Length == 0)
            {
                throw new ArgumentException("A security descriptor is required.", "securityDescriptor");
            }
            if (userSid == null || userSid.Length == 0)
            {
                throw new ArgumentException("A user SID is required.", "userSid");
            }

            IntPtr resourceManager = IntPtr.Zero;
            IntPtr clientContext = IntPtr.Zero;
            IntPtr sidPointer = IntPtr.Zero;
            IntPtr descriptorPointer = IntPtr.Zero;
            IntPtr grantedAccessPointer = IntPtr.Zero;
            IntPtr saclResultPointer = IntPtr.Zero;
            IntPtr errorPointer = IntPtr.Zero;

            try
            {
                if (!AuthzInitializeResourceManager(
                    AuthzResourceManagerNoAudit,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    null,
                    out resourceManager))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                sidPointer = Marshal.AllocHGlobal(userSid.Length);
                Marshal.Copy(userSid, 0, sidPointer, userSid.Length);
                Luid identifier = new Luid();
                if (!AuthzInitializeContextFromSid(
                    0,
                    sidPointer,
                    resourceManager,
                    IntPtr.Zero,
                    identifier,
                    IntPtr.Zero,
                    out clientContext))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                descriptorPointer = Marshal.AllocHGlobal(securityDescriptor.Length);
                Marshal.Copy(securityDescriptor, 0, descriptorPointer, securityDescriptor.Length);
                grantedAccessPointer = Marshal.AllocHGlobal(sizeof(UInt32));
                saclResultPointer = Marshal.AllocHGlobal(sizeof(UInt32));
                errorPointer = Marshal.AllocHGlobal(sizeof(UInt32));
                Marshal.WriteInt32(grantedAccessPointer, 0);
                Marshal.WriteInt32(saclResultPointer, 0);
                Marshal.WriteInt32(errorPointer, 0);

                AuthzAccessRequest request = new AuthzAccessRequest();
                request.DesiredAccess = MaximumAllowed;
                AuthzAccessReply reply = new AuthzAccessReply();
                reply.ResultListLength = 1;
                reply.GrantedAccessMask = grantedAccessPointer;
                reply.SaclEvaluationResults = saclResultPointer;
                reply.Error = errorPointer;

                if (!AuthzAccessCheck(
                    0,
                    clientContext,
                    ref request,
                    IntPtr.Zero,
                    descriptorPointer,
                    IntPtr.Zero,
                    0,
                    ref reply,
                    IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                Int32 accessError = Marshal.ReadInt32(errorPointer);
                if (accessError != 0)
                {
                    throw new Win32Exception(accessError);
                }
                return unchecked((UInt32)Marshal.ReadInt32(grantedAccessPointer));
            }
            finally
            {
                if (clientContext != IntPtr.Zero)
                {
                    AuthzFreeContext(clientContext);
                }
                if (resourceManager != IntPtr.Zero)
                {
                    AuthzFreeResourceManager(resourceManager);
                }
                if (sidPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(sidPointer);
                }
                if (descriptorPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(descriptorPointer);
                }
                if (grantedAccessPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(grantedAccessPointer);
                }
                if (saclResultPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(saclResultPointer);
                }
                if (errorPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(errorPointer);
                }
            }
        }
    }
}
'@

    Add-Type -TypeDefinition $typeDefinition -Language CSharp -ErrorAction Stop
}
