using System;
using System.Runtime.InteropServices;

namespace LocalKdc.Native;

public static unsafe partial class Secur32
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SEC_WINNT_AUTH_IDENTITY_W
    {
        public unsafe char* User;
        public int UserLength;
        public unsafe char* Domain;
        public int DomainLength;
        public unsafe char* Password;
        public int PasswordLength;
        public WinNTAuthIdentityFlags Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_INTEGER
    {
        public int LowPart;
        public int HighPart;
    }

    [Flags]
    public enum CredentialUse : int
    {
        SECPKG_CRED_INBOUND = 0x00000001,
        SECPKG_CRED_OUTBOUND = 0x00000002,
        SECPKG_CRED_BOTH = 0x00000003,
        SECPKG_CRED_DEFAULT = 0x00000004,
        SECPKG_CRED_AUTOLOGON_RESTRICTED = 0x00000010,
        SECPKG_CRED_PROCESS_POLICY_ONLY = 0x00000020,
    }

    public enum WinNTAuthIdentityFlags : int
    {
        SEC_WINNT_AUTH_IDENTITY_ANSI = 1,
        SEC_WINNT_AUTH_IDENTITY_UNICODE = 2,
    }

    [LibraryImport("Secur32.dll", StringMarshalling = StringMarshalling.Utf16)]
    public static partial int AcquireCredentialsHandleW(
        ReadOnlySpan<char> pszPrincipal,
        ReadOnlySpan<char> pPackage,
        CredentialUse fCredentialUse,
        nint pvLogonId,
        SEC_WINNT_AUTH_IDENTITY_W* pAuthData,
        nint pGetKeyFn,
        nint pvGetKeyArgument,
        SafeSspiCredentialHandle phCredential,
        out SECURITY_INTEGER ptsExpiry);
}
