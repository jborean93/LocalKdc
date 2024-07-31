using System;
using System.Runtime.InteropServices;

namespace LocalKdc.Native;

public static unsafe partial class Secur32
{
    [Flags]
    public enum InitiatorContextRequestFlags
    {
        ISC_REQ_DELEGATE = 0x00000001,
        ISC_REQ_MUTUAL_AUTH = 0x00000002,
        ISC_REQ_REPLAY_DETECT = 0x00000004,
        ISC_REQ_SEQUENCE_DETECT = 0x00000008,
        ISC_REQ_CONFIDENTIALITY = 0x00000010,
        ISC_REQ_USE_SESSION_KEY = 0x00000020,
        ISC_REQ_PROMPT_FOR_CREDS = 0x00000040,
        ISC_REQ_USE_SUPPLIED_CREDS = 0x00000080,
        ISC_REQ_ALLOCATE_MEMORY = 0x00000100,
        ISC_REQ_USE_DCE_STYLE = 0x00000200,
        ISC_REQ_DATAGRAM = 0x00000400,
        ISC_REQ_CONNECTION = 0x00000800,
        ISC_REQ_CALL_LEVEL = 0x00001000,
        ISC_REQ_FRAGMENT_SUPPLIED = 0x00002000,
        ISC_REQ_EXTENDED_ERROR = 0x00004000,
        ISC_REQ_STREAM = 0x00008000,
        ISC_REQ_INTEGRITY = 0x00010000,
        ISC_REQ_IDENTIFY = 0x00020000,
        ISC_REQ_NULL_SESSION = 0x00040000,
        ISC_REQ_MANUAL_CRED_VALIDATION = 0x00080000,
        ISC_REQ_RESERVED1 = 0x00100000,
        ISC_REQ_FRAGMENT_TO_FIT = 0x00200000,
        ISC_REQ_FORWARD_CREDENTIALS = 0x00400000,
        ISC_REQ_NO_INTEGRITY = 0x00800000,
        ISC_REQ_USE_HTTP_STYLE = 0x01000000,
        ISC_REQ_UNVERIFIED_TARGET_NAME = 0x20000000,
        ISC_REQ_CONFIDENTIALITY_ONLY = 0x40000000,
    }

    [Flags]
    public enum InitiatorContextReturnFlags
    {
        ISC_RET_DELEGATE = 0x00000001,
        ISC_RET_MUTUAL_AUTH = 0x00000002,
        ISC_RET_REPLAY_DETECT = 0x00000004,
        ISC_RET_SEQUENCE_DETECT = 0x00000008,
        ISC_RET_CONFIDENTIALITY = 0x00000010,
        ISC_RET_USE_SESSION_KEY = 0x00000020,
        ISC_RET_USED_COLLECTED_CREDS = 0x00000040,
        ISC_RET_USED_SUPPLIED_CREDS = 0x00000080,
        ISC_RET_ALLOCATED_MEMORY = 0x00000100,
        ISC_RET_USED_DCE_STYLE = 0x00000200,
        ISC_RET_DATAGRAM = 0x00000400,
        ISC_RET_CONNECTION = 0x00000800,
        ISC_RET_INTERMEDIATE_RETURN = 0x00001000,
        ISC_RET_CALL_LEVEL = 0x00002000,
        ISC_RET_EXTENDED_ERROR = 0x00004000,
        ISC_RET_STREAM = 0x00008000,
        ISC_RET_INTEGRITY = 0x00010000,
        ISC_RET_IDENTIFY = 0x00020000,
        ISC_RET_NULL_SESSION = 0x00040000,
        ISC_RET_MANUAL_CRED_VALIDATION = 0x00080000,
        ISC_RET_RESERVED1 = 0x00100000,
        ISC_RET_FRAGMENT_ONLY = 0x00200000,
        ISC_RET_FORWARD_CREDENTIALS = 0x00400000,
        ISC_RET_USED_HTTP_STYLE = 0x01000000,
        ISC_RET_NO_ADDITIONAL_TOKEN = 0x02000000,
        ISC_RET_REAUTHENTICATION = 0x08000000,
        ISC_RET_CONFIDENTIALITY_ONLY = 0x40000000,
    }

    public enum TargetDataRep : uint
    {
        SECURITY_NETWORK_DREP = 0x00000000,
        SECURITY_NATIVE_DREP = 0x00000010,
    }

    [LibraryImport("Secur32.dll", StringMarshalling = StringMarshalling.Utf16)]
    public static partial int InitializeSecurityContextW(
        SafeSspiCredentialHandle phCredential,
        SecHandle* phContext,
        string pszTargetName,
        InitiatorContextRequestFlags fContextReq,
        int Reserved1,
        TargetDataRep TargetDataRep,
        SecBufferDesc* pIntput,
        int Reserved2,
        SecHandle* phNewContext,
        SecBufferDesc* pOutput,
        out InitiatorContextReturnFlags pfContextAttr,
        out SECURITY_INTEGER ptsExpiry);
}
