using System.Runtime.InteropServices;

namespace LocalKdc.Native;

public static unsafe partial class Secur32
{
    [LibraryImport("Secur32.dll")]
    public static partial int DecryptMessage(
        SafeSspiSecurityContextHandle phContext,
        SecBufferDesc* pMessage,
        int MessageSeqNo,
        out int pfQOP);
}
