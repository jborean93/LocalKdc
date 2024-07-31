using System;
using System.Runtime.InteropServices;

namespace LocalKdc.Native;

public static unsafe partial class Secur32
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SecHandle
    {
        public UIntPtr dwLower;
        public UIntPtr dwUpper;
    }

    public class SafeSspiCredentialHandle : SafeHandle
    {
        internal bool SSPIFree = false;

        internal SafeSspiCredentialHandle() : base(Marshal.AllocHGlobal(Marshal.SizeOf<SecHandle>()), true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            if (SSPIFree)
            {
                FreeCredentialsHandle(handle);
            }
            Marshal.FreeHGlobal(handle);

            return true;
        }
    }

    [LibraryImport("Secur32.dll")]
    public static partial int FreeCredentialsHandle(
        nint phCredential);
}
