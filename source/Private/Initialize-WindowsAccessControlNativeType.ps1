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
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
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

    [StructLayout(LayoutKind.Sequential)]
    internal struct AclSizeInformation
    {
        public UInt32 AceCount;
        public UInt32 AclBytesInUse;
        public UInt32 AclBytesFree;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct GenericMapping
    {
        public UInt32 GenericRead;
        public UInt32 GenericWrite;
        public UInt32 GenericExecute;
        public UInt32 GenericAll;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct InheritedFrom
    {
        public Int32 GenerationGap;
        public IntPtr AncestorName;
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

    public sealed class AccessRuleInheritanceSourceInfo
    {
        public Int32 GenerationGap { get; private set; }
        public string AncestorName { get; private set; }

        internal AccessRuleInheritanceSourceInfo(
            Int32 generationGap,
            string ancestorName)
        {
            GenerationGap = generationGap;
            AncestorName = ancestorName;
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
        private const UInt32 RegistryKeyObject = 4;
        private const UInt32 KernelObject = 6;
        private const UInt32 AclSizeInformationClass = 2;
        private const UInt32 FileGenericRead = 0x00120089;
        private const UInt32 FileGenericWrite = 0x00120116;
        private const UInt32 FileGenericExecute = 0x001200A0;
        private const UInt32 FileAllAccess = 0x001F01FF;
        private const UInt32 RegistryGenericRead = 0x00020019;
        private const UInt32 RegistryGenericWrite = 0x00020006;
        private const UInt32 RegistryGenericExecute = 0x00020019;
        private const UInt32 RegistryAllAccess = 0x000F003F;
        private const UInt32 Logon32LogonInteractive = 2;
        private const UInt32 Logon32ProviderDefault = 0;

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

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "LogonUserW", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeLogonUser(
            string userName,
            string domain,
            IntPtr password,
            UInt32 logonType,
            UInt32 logonProvider,
            out SafeAccessTokenHandle tokenHandle);

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

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetAclInformation(
            IntPtr acl,
            out AclSizeInformation aclInformation,
            UInt32 aclInformationLength,
            UInt32 aclInformationClass);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetInheritanceSourceW")]
        private static extern UInt32 NativeGetInheritanceSource(
            string objectName,
            UInt32 objectType,
            UInt32 securityInformation,
            [MarshalAs(UnmanagedType.Bool)] bool container,
            IntPtr objectClassGuids,
            UInt32 guidCount,
            IntPtr acl,
            IntPtr objectManagerFunctions,
            ref GenericMapping genericMapping,
            IntPtr inheritArray);

        [DllImport("advapi32.dll")]
        private static extern UInt32 FreeInheritedFromArray(
            IntPtr inheritArray,
            UInt16 aceCount,
            IntPtr objectManagerFunctions);

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
                !saclPresent)
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

        private static string NormalizeAncestorName(string ancestorName)
        {
            if (String.IsNullOrEmpty(ancestorName))
            {
                return ancestorName;
            }

            string root = Path.GetPathRoot(ancestorName);
            return String.Equals(ancestorName, root, StringComparison.OrdinalIgnoreCase)
                ? ancestorName
                : ancestorName.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar);
        }

        public static SafeAccessTokenHandle LogonUser(
            string userName,
            SecureString password)
        {
            if (String.IsNullOrWhiteSpace(userName))
            {
                throw new ArgumentException("A user name is required.", "userName");
            }
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            string accountName = userName;
            string domainName = ".";
            Int32 separatorIndex = userName.IndexOf('\\');
            if (separatorIndex >= 0)
            {
                if (separatorIndex == 0 || separatorIndex == userName.Length - 1)
                {
                    throw new ArgumentException(
                        "The user name must use the form domain\\user.",
                        "userName");
                }
                domainName = userName.Substring(0, separatorIndex);
                accountName = userName.Substring(separatorIndex + 1);
            }
            else if (userName.IndexOf('@') >= 0)
            {
                domainName = null;
            }

            IntPtr passwordPointer = IntPtr.Zero;
            SafeAccessTokenHandle tokenHandle = null;
            try
            {
                passwordPointer = Marshal.SecureStringToGlobalAllocUnicode(password);
                if (!NativeLogonUser(
                    accountName,
                    domainName,
                    passwordPointer,
                    Logon32LogonInteractive,
                    Logon32ProviderDefault,
                    out tokenHandle))
                {
                    Int32 errorCode = Marshal.GetLastWin32Error();
                    if (tokenHandle != null)
                    {
                        tokenHandle.Dispose();
                    }
                    throw new Win32Exception(errorCode);
                }
                return tokenHandle;
            }
            finally
            {
                if (passwordPointer != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(passwordPointer);
                }
            }
        }

        public static object RunImpersonated(
            SafeAccessTokenHandle tokenHandle,
            Func<object> operation)
        {
            if (tokenHandle == null || tokenHandle.IsInvalid || tokenHandle.IsClosed)
            {
                throw new ArgumentException("A valid access token is required.", "tokenHandle");
            }
            if (operation == null)
            {
                throw new ArgumentNullException("operation");
            }

            SecurityIdentifier expectedUser;
            using (WindowsIdentity tokenIdentity =
                new WindowsIdentity(tokenHandle.DangerousGetHandle()))
            {
                expectedUser = tokenIdentity.User;
            }
            return WindowsIdentity.RunImpersonated<object>(
                tokenHandle,
                delegate
                {
                    SecurityIdentifier currentUser;
                    using (WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent())
                    {
                        currentUser = currentIdentity.User;
                    }
                    if (expectedUser == null || currentUser == null ||
                        !expectedUser.Equals(currentUser))
                    {
                        throw new SecurityException(
                            "The requested Windows identity was not applied.");
                    }
                    return operation();
                });
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
                    desiredAccess |= ReadControl;
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

        public static IntPtr OpenProcessSecurityHandle(
            Int32 processId,
            Int64 expectedCreationTime,
            UInt32 sections,
            bool write)
        {
            IntPtr processHandle = OpenProcessForSecurity(processId, sections, write);
            try
            {
                VerifyProcessCreationTime(processHandle, expectedCreationTime);
                return processHandle;
            }
            catch
            {
                CloseHandle(processHandle);
                throw;
            }
        }

        public static void CloseProcessSecurityHandle(IntPtr processHandle)
        {
            ValidateHandle(processHandle);
            if (!CloseHandle(processHandle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
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

        public static AccessRuleInheritanceSourceInfo[] GetFileSystemAccessRuleInheritanceSources(
            string path,
            bool container,
            byte[] securityDescriptor)
        {
            if (String.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("A file-system path is required.", "path");
            }

            GenericMapping genericMapping = new GenericMapping
            {
                GenericRead = FileGenericRead,
                GenericWrite = FileGenericWrite,
                GenericExecute = FileGenericExecute,
                GenericAll = FileAllAccess
            };
            return GetAccessRuleInheritanceSources(
                path,
                FileObject,
                container,
                securityDescriptor,
                ref genericMapping,
                true,
                true);
        }

        public static AccessRuleInheritanceSourceInfo[] GetRegistryKeyAccessRuleInheritanceSources(
            string keyName,
            UInt32 objectType,
            byte[] securityDescriptor)
        {
            if (String.IsNullOrWhiteSpace(keyName))
            {
                throw new ArgumentException("A registry key path is required.", "keyName");
            }
            if (objectType != RegistryKeyObject)
            {
                throw new ArgumentOutOfRangeException(
                    "objectType",
                    "Windows resolves registry inheritance sources only for SE_REGISTRY_KEY.");
            }

            GenericMapping genericMapping = new GenericMapping
            {
                GenericRead = RegistryGenericRead,
                GenericWrite = RegistryGenericWrite,
                GenericExecute = RegistryGenericExecute,
                GenericAll = RegistryAllAccess
            };
            return GetAccessRuleInheritanceSources(
                keyName,
                RegistryKeyObject,
                true,
                securityDescriptor,
                ref genericMapping,
                false,
                false);
        }

        private static AccessRuleInheritanceSourceInfo[] GetAccessRuleInheritanceSources(
            string objectName,
            UInt32 objectType,
            bool container,
            byte[] securityDescriptor,
            ref GenericMapping genericMapping,
            bool accessAcesOnly,
            bool normalizeFileSystemName)
        {
            ValidateSecurityDescriptor(securityDescriptor);

            IntPtr descriptorPointer = IntPtr.Zero;
            IntPtr inheritanceArray = IntPtr.Zero;
            bool inheritedNamesAllocated = false;
            UInt16 aceCount = 0;
            UInt32 freeResult = 0;
            List<AccessRuleInheritanceSourceInfo> sources =
                new List<AccessRuleInheritanceSourceInfo>();
            try
            {
                descriptorPointer = Marshal.AllocHGlobal(securityDescriptor.Length);
                Marshal.Copy(
                    securityDescriptor,
                    0,
                    descriptorPointer,
                    securityDescriptor.Length);
                ValidateSecurityDescriptorPointer(descriptorPointer);

                bool daclPresent;
                bool daclDefaulted;
                IntPtr dacl;
                if (!GetSecurityDescriptorDacl(
                    descriptorPointer,
                    out daclPresent,
                    out dacl,
                    out daclDefaulted))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if (!daclPresent || dacl == IntPtr.Zero)
                {
                    return new AccessRuleInheritanceSourceInfo[0];
                }

                AclSizeInformation aclInformation;
                if (!GetAclInformation(
                    dacl,
                    out aclInformation,
                    (UInt32)Marshal.SizeOf(typeof(AclSizeInformation)),
                    AclSizeInformationClass))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if (aclInformation.AceCount == 0)
                {
                    return new AccessRuleInheritanceSourceInfo[0];
                }
                if (aclInformation.AceCount > UInt16.MaxValue)
                {
                    throw new InvalidOperationException(
                        "The DACL contains too many ACEs to resolve inheritance sources.");
                }
                aceCount = (UInt16)aclInformation.AceCount;
                RawSecurityDescriptor rawDescriptor =
                    new RawSecurityDescriptor(securityDescriptor, 0);
                RawAcl rawAcl = rawDescriptor.DiscretionaryAcl;
                if (rawAcl == null || rawAcl.Count != aceCount)
                {
                    throw new InvalidOperationException(
                        "The managed and native DACL ACE counts do not match.");
                }

                Int32 inheritedFromSize = Marshal.SizeOf(typeof(InheritedFrom));
                Int32 allocationSize = checked(
                    inheritedFromSize * aceCount);
                inheritanceArray = Marshal.AllocHGlobal(allocationSize);

                UInt32 result = NativeGetInheritanceSource(
                    objectName,
                    objectType,
                    DaclSecurityInformation,
                    container,
                    IntPtr.Zero,
                    0,
                    dacl,
                    IntPtr.Zero,
                    ref genericMapping,
                    inheritanceArray);
                if (result != 0)
                {
                    throw new Win32Exception((Int32)result);
                }
                inheritedNamesAllocated = true;

                for (Int32 index = 0; index < aceCount; index++)
                {
                    if (accessAcesOnly)
                    {
                        CommonAce managedAce = rawAcl[index] as CommonAce;
                        if (managedAce == null ||
                            (managedAce.AceQualifier != AceQualifier.AccessAllowed &&
                            managedAce.AceQualifier != AceQualifier.AccessDenied))
                        {
                            continue;
                        }
                    }
                    IntPtr entryPointer = IntPtr.Add(
                        inheritanceArray,
                        index * inheritedFromSize);
                    InheritedFrom entry = (InheritedFrom)Marshal.PtrToStructure(
                        entryPointer,
                        typeof(InheritedFrom));
                    string ancestorName = entry.AncestorName == IntPtr.Zero
                        ? null
                        : Marshal.PtrToStringUni(entry.AncestorName);
                    if (normalizeFileSystemName)
                    {
                        ancestorName = NormalizeAncestorName(ancestorName);
                    }
                    sources.Add(new AccessRuleInheritanceSourceInfo(
                        entry.GenerationGap,
                        ancestorName));
                }
            }
            finally
            {
                if (inheritedNamesAllocated)
                {
                    freeResult = FreeInheritedFromArray(
                        inheritanceArray,
                        aceCount,
                        IntPtr.Zero);
                }
                if (inheritanceArray != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(inheritanceArray);
                }
                if (descriptorPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(descriptorPointer);
                }
            }
            if (freeResult != 0)
            {
                throw new Win32Exception((Int32)freeResult);
            }
            return sources.ToArray();
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
            IntPtr processHandle = OpenProcessSecurityHandle(
                processId,
                expectedCreationTime,
                sections,
                false);
            try
            {
                return GetHandleSecurityDescriptor(processHandle, KernelObject, sections);
            }
            finally
            {
                CloseProcessSecurityHandle(processHandle);
            }
        }

        public static void SetProcessSecurityDescriptor(
            Int32 processId,
            Int64 expectedCreationTime,
            UInt32 sections,
            byte[] securityDescriptor)
        {
            IntPtr processHandle = OpenProcessSecurityHandle(
                processId,
                expectedCreationTime,
                sections,
                true);
            try
            {
                SetHandleSecurityDescriptor(
                    processHandle,
                    KernelObject,
                    sections,
                    securityDescriptor);
            }
            finally
            {
                CloseProcessSecurityHandle(processHandle);
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
