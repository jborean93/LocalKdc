using System;
using System.Runtime.InteropServices;

namespace LocalKdc.Native;

public static unsafe partial class Secur32
{
    public static readonly Guid SEC_WINNT_AUTH_DATA_TYPE_KEYTAB = new Guid("D587AAE8-F78F-4455-A112-C934BEEE7CE1");

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
    public struct SEC_WINNT_AUTH_IDENTITY_EX2
    {
        public const int SEC_WINNT_AUTH_IDENTITY_VERSION_2 = 0x201;

        public int Version;
        public short cbHeaderLength;
        public int cbStructureLength;
        public int UserOffset;
        public short UserLength;
        public int DomainOffset;
        public short DomainLength;
        public int PackedCredentialsOffset;
        public short PackedCredentialsLength;
        public WinNTAuthIdentityFlags Flags;
        public int PackageListOffset;
        public short PackageListLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SEC_WINNT_AUTH_PACKED_CREDENTIALS
    {
        public short cbHeaderLength;
        public short cbStructureLength;
        public SEC_WINNT_AUTH_DATA AuthData;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SEC_WINNT_AUTH_DATA
    {
        public Guid CredType;
        public SEC_WINNT_AUTH_BYTE_VECTOR CredData;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SEC_WINNT_AUTH_BYTE_VECTOR
    {
        public int ByteArrayOffset;
        public short ByteArrayLength;
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
        void* pAuthData,
        nint pGetKeyFn,
        nint pvGetKeyArgument,
        SafeSspiCredentialHandle phCredential,
        out SECURITY_INTEGER ptsExpiry);
}
