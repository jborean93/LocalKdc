using System.Runtime.InteropServices;

namespace LocalKdc.Native;

public static unsafe partial class Secur32
{
    public const int SECPKG_ATTR_SIZES = 0;

    [StructLayout(LayoutKind.Sequential)]
    public struct SecPkgContext_Sizes
    {
        public int cbMaxToken;
        public int cbMaxSignature;
        public int cbBlockSize;
        public int cbSecurityTrailer;
    }

    [LibraryImport("Secur32.dll", StringMarshalling = StringMarshalling.Utf16)]
    public static partial int QueryContextAttributesW(
        SafeSspiSecurityContextHandle phContext,
        int ulAttribute,
        void* pBuffer);
}
