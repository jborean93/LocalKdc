using Kerberos.NET.Configuration;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Microsoft.Extensions.Logging;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace LocalKdc;

public class KdcServer : IDisposable
{
    private readonly Kerberos.NET.Server.KdcServer _kdcServer;
    private readonly TcpListener _tcpListener;
    private CancellationTokenSource? _cancellationTokenSource;
    private bool _running;

    public KdcServer(
        IPAddress address,
        short port,
        string realm,
        IPrincipalService principalService,
        ILoggerFactory loggerFactory)
    {
        Krb5Config krb5Config = Krb5Config.Default();
        ListenerOptions options = new()
        {
            Log = loggerFactory,
            Configuration = krb5Config,
            DefaultRealm = realm,
            IsDebug = true,
            RealmLocator = realm => new FakeRealmService(realm, krb5Config, principalService),
        };

        _kdcServer = new Kerberos.NET.Server.KdcServer(options);
        _tcpListener = new TcpListener(address, port);
    }

    public void Start()
    {
        _cancellationTokenSource = new CancellationTokenSource();
        _running = true;
        _tcpListener.Start();

        var cancellationToken = _cancellationTokenSource.Token;
        Task.Run(async () =>
        {
            try
            {
                byte[] sizeBuffer = new byte[4];
                do
                {
                    using var socket = await _tcpListener.AcceptSocketAsync(cancellationToken);
                    using var socketStream = new NetworkStream(socket);

                    await socketStream.ReadExactlyAsync(sizeBuffer, cancellationToken);
                    var messageSize = BinaryPrimitives.ReadInt32BigEndian(sizeBuffer);
                    var requestRented = ArrayPool<byte>.Shared.Rent(messageSize);
                    var request = requestRented.AsMemory(0, messageSize);
                    await socketStream.ReadExactlyAsync(request);
                    var response = await _kdcServer.ProcessMessage(request);
                    ArrayPool<byte>.Shared.Return(requestRented);
                    var responseLength = response.Length + 4;
                    var responseRented = ArrayPool<byte>.Shared.Rent(responseLength);
                    BinaryPrimitives.WriteInt32BigEndian(responseRented.AsSpan(0, 4), responseLength);
                    response.CopyTo(responseRented.AsMemory(4, responseLength));
                    await socketStream.WriteAsync(responseRented.AsMemory(0, responseLength + 4), cancellationToken);
                    ArrayPool<byte>.Shared.Return(responseRented);
                }
                while (!cancellationToken.IsCancellationRequested);
            }
            finally
            {
                _running = false;
            }
        });
    }

    public void Dispose()
    {
        if (_running)
        {
            _cancellationTokenSource?.Cancel();
            _tcpListener.Stop();
        }
        _cancellationTokenSource?.Dispose();
    }
}

class FakeRealmService : IRealmService
{
    private readonly IPrincipalService _principalService;

    public FakeRealmService(string realm, Krb5Config config, IPrincipalService principalService)
    {
        Name = realm;
        Configuration = config;
        _principalService = principalService;
    }

    public IRealmSettings Settings => new FakeRealmSettings();

    public IPrincipalService Principals => _principalService;

    public string Name { get; private set; }

    public DateTimeOffset Now() => DateTimeOffset.UtcNow;

    public ITrustedRealmService? TrustedRealms => null;

    public Krb5Config Configuration { get; private set; }
}

internal class FakeRealmSettings : IRealmSettings
{
    public FakeRealmSettings()
    { }

    public TimeSpan MaximumSkew => TimeSpan.FromMinutes(5);

    public TimeSpan SessionLifetime => TimeSpan.FromHours(10);

    public TimeSpan MaximumRenewalWindow => TimeSpan.FromDays(7);

    public KerberosCompatibilityFlags Compatibility => KerberosCompatibilityFlags.None;
}

class FakePrincipalService : IPrincipalService
{
    private readonly Dictionary<string, IKerberosPrincipal> _principals;

    public FakePrincipalService()
    {
        _principals = new Dictionary<string, IKerberosPrincipal>(StringComparer.InvariantCultureIgnoreCase);
    }

    public void Add(string name, IKerberosPrincipal principal)
    {
        _principals.Add(name, principal);
    }

    public Task<IKerberosPrincipal?> FindAsync(KrbPrincipalName principalName, string? realm = null)
    {
        return Task.FromResult(Find(principalName, realm));
    }

    public IKerberosPrincipal? Find(KrbPrincipalName principalName, string? realm = null)
    {
        if (_principals.TryGetValue(principalName.FullyQualifiedName, out var principal))
        {
            return principal;
        }

        return null;
    }

    public X509Certificate2 RetrieveKdcCertificate()
    {
        throw new NotImplementedException();
    }

    private static readonly Dictionary<KeyAgreementAlgorithm, IExchangeKey> KeyCache = new();

    public IExchangeKey? RetrieveKeyCache(KeyAgreementAlgorithm algorithm)
    {
        if (KeyCache.TryGetValue(algorithm, out IExchangeKey? key))
        {
            if (key.CacheExpiry < DateTimeOffset.UtcNow)
            {
                KeyCache.Remove(algorithm);
            }
            else
            {
                return key;
            }
        }

        return null;
    }

    public IExchangeKey CacheKey(IExchangeKey key)
    {
        key.CacheExpiry = DateTimeOffset.UtcNow.AddMinutes(60);

        KeyCache[key.Algorithm] = key;

        return key;
    }
}

class FakeKerberosPrincipal : IKerberosPrincipal
{
    private readonly byte[] _password;

    public FakeKerberosPrincipal(PrincipalType type, string principalName, string realm, byte[] password)
    {
        Type = type;
        PrincipalName = principalName;
        Realm = realm;
        Expires = DateTimeOffset.UtcNow.AddMonths(1);
        _password = password;
    }

    public SupportedEncryptionTypes SupportedEncryptionTypes { get; set; }
            = SupportedEncryptionTypes.Aes128CtsHmacSha196 |
            SupportedEncryptionTypes.Aes256CtsHmacSha196 |
            SupportedEncryptionTypes.Aes128CtsHmacSha256 |
            SupportedEncryptionTypes.Aes256CtsHmacSha384 |
            SupportedEncryptionTypes.Rc4Hmac |
            SupportedEncryptionTypes.DesCbcCrc |
            SupportedEncryptionTypes.DesCbcMd5;

    public IEnumerable<PaDataType> SupportedPreAuthenticationTypes { get; set; } = new[]
    {
        PaDataType.PA_ENC_TIMESTAMP,
        PaDataType.PA_PK_AS_REQ
    };

    public PrincipalType Type { get; private set; }

    public string PrincipalName { get; private set; }

    public string Realm { get; private set; }

    public DateTimeOffset? Expires { get; set; }

    public PrivilegedAttributeCertificate? GeneratePac() => null;

    private static readonly ConcurrentDictionary<string, KerberosKey> KeyCache = new();

    public KerberosKey RetrieveLongTermCredential()
    {
        return RetrieveLongTermCredential(EncryptionType.AES256_CTS_HMAC_SHA1_96);
    }

    public KerberosKey RetrieveLongTermCredential(EncryptionType etype)
    {
        return KeyCache.GetOrAdd(etype + PrincipalName, pn =>
        {
            return new KerberosKey(
                password: _password,
                principal: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, Realm, [PrincipalName]),
                etype: etype,
                saltType: SaltType.ActiveDirectoryUser);
        });
    }

    public void Validate(X509Certificate2Collection certificates)
    { }
}
