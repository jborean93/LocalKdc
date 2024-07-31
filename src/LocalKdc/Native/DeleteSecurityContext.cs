using System;
using System.Runtime.InteropServices;

namespace LocalKdc.Native;

public static unsafe partial class Secur32
{
    public class SafeSspiSecurityContextHandle : SafeHandle
    {
        internal bool SSPIFree = false;

        internal SafeSspiSecurityContextHandle() : base(Marshal.AllocHGlobal(Marshal.SizeOf<SecHandle>()), true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            if (SSPIFree)
            {
                DeleteSecurityContext(handle);
            }
            Marshal.FreeHGlobal(handle);

            return true;
        }
    }

    [LibraryImport("Secur32.dll")]
    public static partial int DeleteSecurityContext(
        nint phContext);
}
