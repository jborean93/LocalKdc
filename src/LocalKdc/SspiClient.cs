using LocalKdc.Native;
using Microsoft.Extensions.Logging;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace LocalKdc;

public class SspiClient
{
    public unsafe static void TryKerberosAuth(
        string userPrincipal,
        string password,
        string servicePrincipal,
        ILoggerFactory loggerFactory)
    {
        ILogger<SspiClient> logger = loggerFactory.CreateLogger<SspiClient>();
        logger.LogInformation("Starting client Kerberos test with {0} -> {1}",
            userPrincipal, servicePrincipal);

        using Secur32.SafeSspiCredentialHandle credential = new();

        fixed (char* userPrincipalPtr = userPrincipal)
        fixed (char* passwordPtr = password)
        {
            Secur32.SEC_WINNT_AUTH_IDENTITY_W authId = new()
            {
                User = userPrincipalPtr,
                UserLength = userPrincipal.Length,
                Domain = null,
                DomainLength = 0,
                Password = passwordPtr,
                PasswordLength = password.Length,
                Flags = Secur32.WinNTAuthIdentityFlags.SEC_WINNT_AUTH_IDENTITY_UNICODE,
            };

            logger.LogInformation("Calling AcquireCredentialsHandleW");
            int res = Secur32.AcquireCredentialsHandleW(
                null,
                "Kerberos",
                Secur32.CredentialUse.SECPKG_CRED_OUTBOUND,
                nint.Zero,
                &authId,
                nint.Zero,
                nint.Zero,
                credential,
                out var _);
            logger.LogInformation("AcquireCredentialsHandleW returned {0}", res);
            if (res != 0)
            {
                throw new Win32Exception(res);
            }
            credential.SSPIFree = true;
        }

        Secur32.SafeSspiSecurityContextHandle context = new();
        Secur32.InitiatorContextReturnFlags returnFlags;

        Span<Secur32.SecBuffer> outBuffers = stackalloc Secur32.SecBuffer[1];
        outBuffers[0].BufferType = (int)Secur32.SecBufferType.SECBUFFER_TOKEN;

        fixed (Secur32.SecBuffer* outBuffersPtr = outBuffers)
        {
            Secur32.SecBufferDesc outDesc = new()
            {
                cBuffers = 1,
                pBuffers = outBuffersPtr,
            };

            logger.LogInformation("Calling InitializeSecurityContextW");
            int res = Secur32.InitializeSecurityContextW(
                credential,
                null,
                servicePrincipal,
                Secur32.InitiatorContextRequestFlags.ISC_REQ_ALLOCATE_MEMORY,
                0,
                Secur32.TargetDataRep.SECURITY_NATIVE_DREP,
                null,
                0,
                (Secur32.SecHandle*)context.DangerousGetHandle(),
                &outDesc,
                out returnFlags,
                out var _);
            logger.LogInformation("InitializeSecurityContextW returned {0}", res);

            if (res != 0)
            {
                throw new Win32Exception(res);
            }
            context.SSPIFree = true;
        }

        try
        {
            byte[] outToken = new byte[outBuffers[0].cbBuffer];
            Marshal.Copy((nint)outBuffers[0].pvBuffer, outToken, 0, outToken.Length);
            logger.LogInformation("Return Flags {0}, Token {1}", returnFlags,
                Convert.ToHexString(outToken));
        }
        finally
        {
            Secur32.FreeContextBuffer(outBuffers[0].pvBuffer);
        }
    }
}
