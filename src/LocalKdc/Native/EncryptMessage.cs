using System.Runtime.InteropServices;

namespace LocalKdc.Native;

public static unsafe partial class Secur32
{
    [LibraryImport("Secur32.dll")]
    public static partial int EncryptMessage(
        SafeSspiSecurityContextHandle phContext,
        int fQOP,
        SecBufferDesc* pMessage,
        int MessageSeqNo);
}
