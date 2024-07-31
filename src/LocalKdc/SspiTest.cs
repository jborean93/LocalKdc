using LocalKdc.Native;
using Microsoft.Extensions.Logging;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace LocalKdc;

public class SspiTest
{
    private const string KERBEROS_PACKAGE = "Kerberos";

    public unsafe static void TryKerberosAuth(
        string userPrincipal,
        string password,
        string servicePrincipal,
        ReadOnlySpan<byte> serviceKeyTab,
        ILoggerFactory loggerFactory)
    {
        ILogger<SspiTest> logger = loggerFactory.CreateLogger<SspiTest>();
        logger.LogInformation("Starting client Kerberos test with {0} -> {1}",
            userPrincipal, servicePrincipal);

        using var initiatorCredential = AcquireCredentialsHandleWithPassword(
            userPrincipal,
            password,
            Secur32.CredentialUse.SECPKG_CRED_OUTBOUND,
            logger);
        using var acceptorCredential = AcquireCredentialsHandleWithKeytab(
            servicePrincipal,
            serviceKeyTab,
            Secur32.CredentialUse.SECPKG_CRED_INBOUND,
            logger);

        using Secur32.SafeSspiSecurityContextHandle initiatorContext = new();
        Span<Secur32.SecBuffer> initiatorBuffers = stackalloc Secur32.SecBuffer[1];
        initiatorBuffers[0].BufferType = (int)Secur32.SecBufferType.SECBUFFER_TOKEN;
        Secur32.InitiatorContextRequestFlags initiatorRequestFlags =
            Secur32.InitiatorContextRequestFlags.ISC_REQ_ALLOCATE_MEMORY |
            Secur32.InitiatorContextRequestFlags.ISC_REQ_INTEGRITY |
            Secur32.InitiatorContextRequestFlags.ISC_REQ_CONFIDENTIALITY |
            Secur32.InitiatorContextRequestFlags.ISC_REQ_MUTUAL_AUTH;

        using Secur32.SafeSspiSecurityContextHandle acceptorContext = new();
        Span<Secur32.SecBuffer> acceptorBuffers = stackalloc Secur32.SecBuffer[1];
        acceptorBuffers[0].BufferType = (int)Secur32.SecBufferType.SECBUFFER_TOKEN;

        try
        {
            var initiatorReturn = InitializeSecurityContext(
                initiatorContext,
                initiatorCredential,
                servicePrincipal,
                initiatorRequestFlags,
                null,
                initiatorBuffers,
                logger);

            ReadOnlySpan<byte> outToken = new(initiatorBuffers[0].pvBuffer,
                initiatorBuffers[0].cbBuffer);
            logger.LogInformation("ISC Return Flags {0}, Token {1}",
                initiatorReturn, Convert.ToHexString(outToken));

            var acceptorReturn = AcceptSecurityContext(
                acceptorContext,
                acceptorCredential,
                Secur32.AcceptorContextRequestFlags.ASC_REQ_ALLOCATE_MEMORY |
                    Secur32.AcceptorContextRequestFlags.ASC_REQ_INTEGRITY |
                    Secur32.AcceptorContextRequestFlags.ASC_REQ_CONFIDENTIALITY |
                    Secur32.AcceptorContextRequestFlags.ASC_REQ_MUTUAL_AUTH,
                initiatorBuffers,
                acceptorBuffers,
                logger);

            Secur32.FreeContextBuffer(initiatorBuffers[0].pvBuffer);
            initiatorBuffers[0].cbBuffer = 0;
            initiatorBuffers[0].pvBuffer = null;

            outToken = new(acceptorBuffers[0].pvBuffer,
                acceptorBuffers[0].cbBuffer);
            logger.LogInformation("ASC Return Flags {0}, Token {1}",
                acceptorReturn, Convert.ToHexString(outToken));

            initiatorReturn = InitializeSecurityContext(
                initiatorContext,
                initiatorCredential,
                servicePrincipal,
                initiatorRequestFlags,
                acceptorBuffers,
                initiatorBuffers,
                logger);

            outToken = new(initiatorBuffers[0].pvBuffer,
                initiatorBuffers[0].cbBuffer);
            logger.LogInformation("ISC Return Flags {0}, Token {1}",
                initiatorReturn, Convert.ToHexString(outToken));
        }
        finally
        {
            if (initiatorBuffers[0].pvBuffer != null)
            {
                Secur32.FreeContextBuffer(initiatorBuffers[0].pvBuffer);
            }
            if (acceptorBuffers[0].pvBuffer != null)
            {
                Secur32.FreeContextBuffer(acceptorBuffers[0].pvBuffer);
            }
        }

        logger.LogInformation("Querying SecPkgContext_Sizes");
        Secur32.SecPkgContext_Sizes contextSizes = new();
        int res = Secur32.QueryContextAttributesW(
            initiatorContext,
            Secur32.SECPKG_ATTR_SIZES,
            &contextSizes);
        logger.LogInformation("QueryContextAttributesW res {0}", res);
        if (res != 0)
        {
            throw new Win32Exception(res);
        }

        logger.LogInformation(
            "SecPkgContext_Sizes - MaxToken: {0}, MaxSignature: {1}, BlockSize: {2}, SecurityTrailer: {3}",
            contextSizes.cbMaxToken, contextSizes.cbMaxSignature,
            contextSizes.cbBlockSize, contextSizes.cbSecurityTrailer);

        Random rnd = new();
        Span<byte> rndBytes = stackalloc byte[16];
        rnd.NextBytes(rndBytes);
        string plaintextHex = Convert.ToHexString(rndBytes);

        Span<Secur32.SecBuffer> encBuffers = stackalloc Secur32.SecBuffer[3];
        Span<byte> tokenBuffer = stackalloc byte[contextSizes.cbSecurityTrailer];
        Span<byte> data = stackalloc byte[16];
        Span<byte> paddingBuffer = stackalloc byte[contextSizes.cbBlockSize];
        fixed (byte* tokenPtr = tokenBuffer)
        fixed (byte* dataPtr = data)
        fixed (byte* paddingPtr = paddingBuffer)
        {
            foreach ((var scenario, var inContext, var outContext) in new (string, Secur32.SafeSspiSecurityContextHandle, Secur32.SafeSspiSecurityContextHandle)[]
            {
                ("initiator->acceptor", initiatorContext, acceptorContext),
                ("acceptor->initiator", acceptorContext, initiatorContext)
            })
            {
                logger.LogInformation("Running {0} encryption tests with data {1}",
                                        scenario, plaintextHex);
                rndBytes.CopyTo(data);

                encBuffers[0].BufferType = (int)Secur32.SecBufferType.SECBUFFER_TOKEN;
                encBuffers[0].cbBuffer = contextSizes.cbSecurityTrailer;
                encBuffers[0].pvBuffer = tokenPtr;

                encBuffers[1].BufferType = (int)Secur32.SecBufferType.SECBUFFER_DATA;
                encBuffers[1].cbBuffer = data.Length;
                encBuffers[1].pvBuffer = dataPtr;

                encBuffers[2].BufferType = (int)Secur32.SecBufferType.SECBUFFER_PADDING;
                encBuffers[2].cbBuffer = contextSizes.cbBlockSize;
                encBuffers[2].pvBuffer = paddingPtr;

                EncryptMessage(inContext, 0, encBuffers, 0, logger);

                string encryptedHex = Convert.ToHexString(data[..encBuffers[1].cbBuffer]);
                logger.LogInformation("Encrypted message {0} - {1}", scenario, encryptedHex);
                Debug.Assert(encryptedHex != plaintextHex);

                byte[] streamData = new byte[encBuffers[0].cbBuffer + encBuffers[1].cbBuffer];
                new Span<byte>(tokenPtr, encBuffers[0].cbBuffer).CopyTo(streamData);
                new Span<byte>(dataPtr, encBuffers[1].cbBuffer).CopyTo(
                    streamData.AsSpan(encBuffers[0].cbBuffer));

                fixed (byte* streamPtr = streamData)
                {
                    encBuffers[0].BufferType = (int)Secur32.SecBufferType.SECBUFFER_STREAM;
                    encBuffers[0].cbBuffer = streamData.Length;
                    encBuffers[0].pvBuffer = streamPtr;

                    encBuffers[1].BufferType = (int)Secur32.SecBufferType.SECBUFFER_DATA;
                    encBuffers[1].cbBuffer = 0;
                    encBuffers[1].pvBuffer = null;

                    DecryptMessage(outContext, encBuffers[..2], 0, logger);

                    string decryptedHex = Convert.ToHexString(
                        new Span<byte>(encBuffers[1].pvBuffer, encBuffers[1].cbBuffer));
                    logger.LogInformation("Decrypted message {0} - {1}", scenario, decryptedHex);
                    Debug.Assert(decryptedHex == plaintextHex);
                }
            }
        }
    }

    private unsafe static Secur32.SafeSspiCredentialHandle AcquireCredentialsHandleWithPassword(
        string principal,
        string password,
        Secur32.CredentialUse credentialUse,
        ILogger logger)
    {
        Secur32.SafeSspiCredentialHandle credential = new();

        fixed (char* principalPtr = principal)
        fixed (char* passwordPtr = password)
        {
            Secur32.SEC_WINNT_AUTH_IDENTITY_W authIdentity = new()
            {
                User = principalPtr,
                UserLength = principal.Length,
                Domain = null,
                DomainLength = 0,
                Password = passwordPtr,
                PasswordLength = password.Length,
                Flags = Secur32.WinNTAuthIdentityFlags.SEC_WINNT_AUTH_IDENTITY_UNICODE,
            };

            logger.LogInformation("Calling AcquireCredentialsHandleW with password for {0}", principal);
            int res = Secur32.AcquireCredentialsHandleW(
                null,
                KERBEROS_PACKAGE,
                credentialUse,
                nint.Zero,
                &authIdentity,
                nint.Zero,
                nint.Zero,
                credential,
                out var expiryRaw);

            long expiry = (long)(expiryRaw.HighPart << 32) | (long)expiryRaw.LowPart;
            logger.LogInformation("AcquireCredentialsHandleW returned 0x{0:X8}, Expiry {1}",
                res, expiry);

            if (res != 0)
            {
                throw new Win32Exception(res);
            }
            credential.SSPIFree = true;
        }

        return credential;
    }

    private unsafe static Secur32.SafeSspiCredentialHandle AcquireCredentialsHandleWithKeytab(
        string principal,
        ReadOnlySpan<byte> keyTab,
        Secur32.CredentialUse credentialUse,
        ILogger logger)
    {
        Secur32.SafeSspiCredentialHandle credential = new();

        short authIdentityLength = (short)Marshal.SizeOf<Secur32.SEC_WINNT_AUTH_IDENTITY_EX2>();
        short packedCredLength = (short)Marshal.SizeOf<Secur32.SEC_WINNT_AUTH_PACKED_CREDENTIALS>();
        short keyTabLength = (short)keyTab.Length;
        short principalLength = (short)(principal.Length * 2);
        short authDataLength = (short)(authIdentityLength + packedCredLength + keyTab.Length + principalLength);

        nint authDataPtr = Marshal.AllocHGlobal(authDataLength);
        try
        {
            // Zero out bytes for unused fields in the structure section of the data.
            new Span<byte>((byte*)authDataPtr, authIdentityLength + packedCredLength).Fill(0);

            Secur32.SEC_WINNT_AUTH_IDENTITY_EX2* authIdentity = (Secur32.SEC_WINNT_AUTH_IDENTITY_EX2*)authDataPtr;
            authIdentity->Version = Secur32.SEC_WINNT_AUTH_IDENTITY_EX2.SEC_WINNT_AUTH_IDENTITY_VERSION_2;
            authIdentity->cbHeaderLength = authIdentityLength;
            authIdentity->cbStructureLength = authDataLength;
            authIdentity->UserOffset = authIdentityLength + packedCredLength + keyTabLength;
            authIdentity->UserLength = principalLength;
            authIdentity->PackedCredentialsOffset = authIdentityLength;
            authIdentity->PackedCredentialsLength = (short)(packedCredLength + keyTabLength);
            authIdentity->Flags = Secur32.WinNTAuthIdentityFlags.SEC_WINNT_AUTH_IDENTITY_UNICODE;

            nint packedCredPtr = nint.Add(authDataPtr, authIdentity->PackedCredentialsOffset);
            Secur32.SEC_WINNT_AUTH_PACKED_CREDENTIALS* packedCred =
                (Secur32.SEC_WINNT_AUTH_PACKED_CREDENTIALS*)packedCredPtr;
            packedCred->cbHeaderLength = packedCredLength;
            packedCred->cbStructureLength = authIdentity->PackedCredentialsLength;
            packedCred->AuthData.CredType = Secur32.SEC_WINNT_AUTH_DATA_TYPE_KEYTAB;
            packedCred->AuthData.CredData.ByteArrayLength = keyTabLength;
            packedCred->AuthData.CredData.ByteArrayOffset = packedCredLength;

            keyTab.CopyTo(new Span<byte>(
                (void*)nint.Add(packedCredPtr, packedCred->AuthData.CredData.ByteArrayOffset),
                keyTab.Length));
            Encoding.Unicode.GetBytes(principal, new Span<byte>(
                (void*)nint.Add(authDataPtr, authIdentity->UserOffset),
                principalLength));

            logger.LogInformation("Calling AcquireCredentialsHandleW with KeyTab for {0}", principal);
            int res = Secur32.AcquireCredentialsHandleW(
                null,
                KERBEROS_PACKAGE,
                credentialUse,
                nint.Zero,
                authIdentity,
                nint.Zero,
                nint.Zero,
                credential,
                out var expiryRaw);

            long expiry = (long)(expiryRaw.HighPart << 32) | (long)expiryRaw.LowPart;
            logger.LogInformation("AcquireCredentialsHandleW returned 0x{0:X8}, Expiry {1}",
                res, expiry);

            if (res != 0)
            {
                throw new Win32Exception(res);
            }
            credential.SSPIFree = true;
        }
        finally
        {
            Marshal.FreeHGlobal(authDataPtr);
        }

        return credential;
    }

    private unsafe static Secur32.InitiatorContextReturnFlags InitializeSecurityContext(
        Secur32.SafeSspiSecurityContextHandle context,
        Secur32.SafeSspiCredentialHandle credential,
        string targetSpn,
        Secur32.InitiatorContextRequestFlags requestFlags,
        Span<Secur32.SecBuffer> inputBuffers,
        Span<Secur32.SecBuffer> outputBuffers,
        ILogger logger)
    {
        Secur32.InitiatorContextReturnFlags returnFlags;

        fixed (Secur32.SecBuffer* inputBuffersPtr = inputBuffers)
        fixed (Secur32.SecBuffer* outputBuffersPtr = outputBuffers)
        {
            Secur32.SecHandle* inputContext = null;
            if (context.SSPIFree)
            {
                inputContext = (Secur32.SecHandle*)context.DangerousGetHandle();
            }

            Secur32.SecBufferDesc inputBuffersDesc = new()
            {
                cBuffers = inputBuffers.Length,
                pBuffers = inputBuffersPtr,
            };
            Secur32.SecBufferDesc* inputBuffersDescPtr = inputBuffers.Length > 0
                ? &inputBuffersDesc : null;

            Secur32.SecBufferDesc outputBuffersDesc = new()
            {
                cBuffers = outputBuffers.Length,
                pBuffers = outputBuffersPtr,
            };
            Secur32.SecBufferDesc* outputBuffersDescPtr = outputBuffers.Length > 0
                ? &outputBuffersDesc : null;

            logger.LogInformation("Calling InitializeSecurityContextW with target SPN {0}",
                targetSpn);
            int res = Secur32.InitializeSecurityContextW(
                credential,
                inputContext,
                targetSpn,
                requestFlags,
                0,
                Secur32.TargetDataRep.SECURITY_NATIVE_DREP,
                inputBuffersDescPtr,
                0,
                (Secur32.SecHandle*)context.DangerousGetHandle(),
                outputBuffersDescPtr,
                out returnFlags,
                out var expiryRaw);

            long expiry = (long)(expiryRaw.HighPart << 32) | (long)expiryRaw.LowPart;
            logger.LogInformation("InitializeSecurityContextW returned 0x{0:X8}, Expiry {1}",
                res, expiry);

            if (res != 0 && res != Secur32.SEC_I_CONTINUE_NEEDED)
            {
                throw new Win32Exception(res);
            }
            context.SSPIFree = true;
        }

        return returnFlags;
    }

    private unsafe static Secur32.AcceptorContextReturnFlags AcceptSecurityContext(
        Secur32.SafeSspiSecurityContextHandle context,
        Secur32.SafeSspiCredentialHandle credential,
        Secur32.AcceptorContextRequestFlags requestFlags,
        Span<Secur32.SecBuffer> inputBuffers,
        Span<Secur32.SecBuffer> outputBuffers,
        ILogger logger)
    {
        Secur32.AcceptorContextReturnFlags returnFlags;

        fixed (Secur32.SecBuffer* inputBuffersPtr = inputBuffers)
        fixed (Secur32.SecBuffer* outputBuffersPtr = outputBuffers)
        {
            Secur32.SecHandle* inputContext = null;
            if (context.SSPIFree)
            {
                inputContext = (Secur32.SecHandle*)context.DangerousGetHandle();
            }

            Secur32.SecBufferDesc inputBuffersDesc = new()
            {
                cBuffers = inputBuffers.Length,
                pBuffers = inputBuffersPtr,
            };
            Secur32.SecBufferDesc* inputBuffersDescPtr = inputBuffers.Length > 0
                ? &inputBuffersDesc : null;

            Secur32.SecBufferDesc outputBuffersDesc = new()
            {
                cBuffers = outputBuffers.Length,
                pBuffers = outputBuffersPtr,
            };
            Secur32.SecBufferDesc* outputBuffersDescPtr = outputBuffers.Length > 0
                ? &outputBuffersDesc : null;

            logger.LogInformation("Calling AcceptSecurityContext");
            int res = Secur32.AcceptSecurityContext(
                credential,
                inputContext,
                inputBuffersDescPtr,
                requestFlags,
                Secur32.TargetDataRep.SECURITY_NATIVE_DREP,
                (Secur32.SecHandle*)context.DangerousGetHandle(),
                outputBuffersDescPtr,
                out returnFlags,
                out var expiryRaw);

            long expiry = (long)(expiryRaw.HighPart << 32) | (long)expiryRaw.LowPart;
            logger.LogInformation("AcceptSecurityContext returned 0x{0:X8}, Expiry {1}",
                res, expiry);

            if (res != 0 && res != Secur32.SEC_I_CONTINUE_NEEDED)
            {
                throw new Win32Exception(res);
            }
            context.SSPIFree = true;
        }

        return returnFlags;
    }

    private unsafe static void DecryptMessage(
        Secur32.SafeSspiSecurityContextHandle context,
        Span<Secur32.SecBuffer> message,
        int seqNo,
        ILogger logger)
    {
        fixed (Secur32.SecBuffer* messagePtr = message)
        {
            Secur32.SecBufferDesc messageDesc = new()
            {
                cBuffers = message.Length,
                pBuffers = messagePtr,
            };

            logger.LogInformation("Calling DecryptMessage");
            int res = Secur32.DecryptMessage(
                context,
                &messageDesc,
                seqNo,
                out var qop);
            logger.LogInformation("DecryptMessage returns 0x{0:X8}, QoP {1}", res, qop);

            if (res != 0)
            {
                throw new Win32Exception(res);
            }
        }
    }

    private unsafe static void EncryptMessage(
        Secur32.SafeSspiSecurityContextHandle context,
        int qop,
        Span<Secur32.SecBuffer> message,
        int seqNo,
        ILogger logger)
    {
        fixed (Secur32.SecBuffer* messagePtr = message)
        {
            Secur32.SecBufferDesc messageDesc = new()
            {
                cBuffers = message.Length,
                pBuffers = messagePtr,
            };

            logger.LogInformation("Calling EncryptMessage");
            int res = Secur32.EncryptMessage(
                context,
                qop,
                &messageDesc,
                seqNo);
            logger.LogInformation("EncryptMessage returns 0x{0:X8}", res);

            if (res != 0)
            {
                throw new Win32Exception(res);
            }
        }
    }
}
