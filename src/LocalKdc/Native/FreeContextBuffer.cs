using System;
using System.Runtime.InteropServices;

namespace LocalKdc.Native;

public static unsafe partial class Secur32
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SecBufferDesc
    {
        public int ulVersion;
        public int cBuffers;
        public SecBuffer* pBuffers;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBuffer
    {
        public int cbBuffer;
        public int BufferType;
        public byte* pvBuffer;
    }

    public enum SecBufferFlags
    {
        SECBUFFER_READONLY_WITH_CHECKSUM = 0x10000000,
        SECBUFFER_RESERVED = 0x60000000,
        SECBUFFER_READONLY = unchecked((int)0x80000000),
    }

    public enum SecBufferType
    {
        SECBUFFER_EMPTY = 0,
        SECBUFFER_DATA = 1,
        SECBUFFER_TOKEN = 2,
        SECBUFFER_PKG_PARAMS = 3,
        SECBUFFER_MISSING = 4,
        SECBUFFER_EXTRA = 5,
        SECBUFFER_STREAM_TRAILER = 6,
        SECBUFFER_STREAM_HEADER = 7,
        SECBUFFER_NEGOTIATION_INFO = 8,
        SECBUFFER_PADDING = 9,
        SECBUFFER_STREAM = 10,
        SECBUFFER_MECHLIST = 11,
        SECBUFFER_MECHLIST_SIGNATURE = 12,
        SECBUFFER_TARGET = 13,
        SECBUFFER_CHANNEL_BINDINGS = 14,
        SECBUFFER_CHANGE_PASS_RESPONSE = 15,
        SECBUFFER_TARGET_HOST = 16,
        SECBUFFER_ALERT = 17,
        SECBUFFER_APPLICATION_PROTOCOLS = 18,
        SECBUFFER_SRTP_PROTECTION_PROFILES = 19,
        SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER = 20,
        SECBUFFER_TOKEN_BINDING = 21,
        SECBUFFER_PRESHARED_KEY = 22,
        SECBUFFER_PRESHARED_KEY_IDENTITY = 23,
    }

    [LibraryImport("Secur32.dll")]
    public static partial int FreeContextBuffer(
        byte* pvContextBuffer);
}
