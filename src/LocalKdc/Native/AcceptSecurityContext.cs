using System;
using System.Runtime.InteropServices;

namespace LocalKdc.Native;

public static unsafe partial class Secur32
{
    [Flags]
    public enum AcceptorContextRequestFlags
    {
        NONE = 0x00000000,
        ASC_REQ_DELEGATE = 0x00000001,
        ASC_REQ_MUTUAL_AUTH = 0x00000002,
        ASC_REQ_REPLAY_DETECT = 0x00000004,
        ASC_REQ_SEQUENCE_DETECT = 0x00000008,
        ASC_REQ_CONFIDENTIALITY = 0x00000010,
        ASC_REQ_USE_SESSION_KEY = 0x00000020,
        ASC_REQ_SESSION_TICKET = 0x00000040,
        ASC_REQ_ALLOCATE_MEMORY = 0x00000100,
        ASC_REQ_USE_DCE_STYLE = 0x00000200,
        ASC_REQ_DATAGRAM = 0x00000400,
        ASC_REQ_CONNECTION = 0x00000800,
        ASC_REQ_CALL_LEVEL = 0x00001000,
        ASC_REQ_FRAGMENT_SUPPLIED = 0x00002000,
        ASC_REQ_EXTENDED_ERROR = 0x00008000,
        ASC_REQ_STREAM = 0x00010000,
        ASC_REQ_INTEGRITY = 0x00020000,
        ASC_REQ_LICENSING = 0x00040000,
        ASC_REQ_IDENTIFY = 0x00080000,
        ASC_REQ_ALLOW_NULL_SESSION = 0x00100000,
        ASC_REQ_ALLOW_NON_USER_LOGONS = 0x00200000,
        ASC_REQ_ALLOW_CONTEXT_REPLAY = 0x00400000,
        ASC_REQ_FRAGMENT_TO_FIT = 0x00800000,
        ASC_REQ_NO_TOKEN = 0x01000000,
        ASC_REQ_PROXY_BINDINGS = 0x04000000,
        ASC_REQ_ALLOW_MISSING_BINDINGS = 0x10000000,
    }

    [Flags]
    public enum AcceptorContextReturnFlags
    {
        NONE = 0x00000000,
        ASC_RET_DELEGATE = 0x00000001,
        ASC_RET_MUTUAL_AUTH = 0x00000002,
        ASC_RET_REPLAY_DETECT = 0x00000004,
        ASC_RET_SEQUENCE_DETECT = 0x00000008,
        ASC_RET_CONFIDENTIALITY = 0x00000010,
        ASC_RET_USE_SESSION_KEY = 0x00000020,
        ASC_RET_SESSION_TICKET = 0x00000040,
        ASC_RET_ALLOCATED_MEMORY = 0x00000100,
        ASC_RET_USED_DCE_STYLE = 0x00000200,
        ASC_RET_DATAGRAM = 0x00000400,
        ASC_RET_CONNECTION = 0x00000800,
        ASC_RET_CALL_LEVEL = 0x00002000,
        ASC_RET_THIRD_LEG_FAILED = 0x00004000,
        ASC_RET_EXTENDED_ERROR = 0x00008000,
        ASC_RET_STREAM = 0x00010000,
        ASC_RET_INTEGRITY = 0x00020000,
        ASC_RET_LICENSING = 0x00040000,
        ASC_RET_IDENTIFY = 0x00080000,
        ASC_RET_NULL_SESSION = 0x00100000,
        ASC_RET_ALLOW_NON_USER_LOGONS = 0x00200000,
        ASC_RET_ALLOW_CONTEXT_REPLAY = 0x00400000,
        ASC_RET_FRAGMENT_ONLY = 0x00800000,
        ASC_RET_NO_TOKEN = 0x01000000,
        ASC_RET_NO_ADDITIONAL_TOKEN = 0x02000000,
    }

    [LibraryImport("Secur32.dll")]
    public static partial int AcceptSecurityContext(
        SafeSspiCredentialHandle? phCredential,
        SecHandle* phContext,
        SecBufferDesc* pInput,
        AcceptorContextRequestFlags fContextReq,
        TargetDataRep TargetDataRep,
        SecHandle* phNewContext,
        SecBufferDesc* pOutput,
        out AcceptorContextReturnFlags pfContextAttr,
        out SECURITY_INTEGER ptsExpiry);
}
