function Initialize-NTFSNativeType {
    [CmdletBinding()]
    param()

    if ([System.Management.Automation.PSTypeName]'NTFSPermission.NativeMethods'.Type) {
        return
    }

    $typeDefinition = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace NTFSPermission
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Luid
    {
        public UInt32 LowPart;
        public Int32 HighPart;
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

    public static class NativeMethods
    {
        private const UInt32 TokenQuery = 0x0008;
        private const UInt32 TokenAdjustPrivileges = 0x0020;
        private const UInt32 PrivilegeEnabled = 0x0002;
        private const UInt32 PrivilegeSetAllNecessary = 0x0001;
        private const Int32 ErrorNotAllAssigned = 1300;
        private const UInt32 AuthzResourceManagerNoAudit = 0x0001;
        private const UInt32 MaximumAllowed = 0x02000000;

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        private static extern void SetLastError(UInt32 errorCode);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(
            IntPtr processHandle,
            UInt32 desiredAccess,
            out IntPtr tokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValue(
            string systemName,
            string name,
            out Luid luid);

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