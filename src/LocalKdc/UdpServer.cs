using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace LocalKdc;

public abstract class UdpServer : IDisposable
{
    private const int SIO_UDP_CONNRESET = -1744830452;

    private readonly IPEndPoint _endpoint;
    protected readonly ILogger _logger;

    private CancellationTokenSource? _cancellationTokenSource;
    private bool _running;

    public UdpServer(IPAddress address, short port, ILogger logger)
    {
        _endpoint = new IPEndPoint(address, port);
        _logger = logger;
    }

    public void Start()
    {
        _cancellationTokenSource = new CancellationTokenSource();
        _running = true;

        var cancellationToken = _cancellationTokenSource.Token;
        Task.Run(async () =>
        {
            _logger.LogInformation("Starting UDP listener on {0}", _endpoint);
            using UdpClient udp = new(_endpoint);

            // ICMP port unreachable responses to already sent messages will
            // bring down the connection, we don't want that.
            udp.Client.IOControl(
                (IOControlCode)SIO_UDP_CONNRESET,
                new byte[4],
                null);

            try
            {
                _running = true;
                do
                {
                    UdpReceiveResult request = await udp.ReceiveAsync(cancellationToken);
                    byte[] response = ProcessData(request.Buffer);
                    int sent = await udp.SendAsync(
                        response,
                        request.RemoteEndPoint,
                        cancellationToken);
                    Debug.Assert(sent == response.Length);
                }
                while (!cancellationToken.IsCancellationRequested);
            }
            catch (OperationCanceledException)
            { }
            catch (Exception ex)
            {
                _logger.LogError(ex, "DnsServer throw unhandled exception");
                throw;
            }
            finally
            {
                _running = false;
            }
        });
    }

    public abstract byte[] ProcessData(byte[] data);

    public void Dispose()
    {
        if (_running)
        {
            _cancellationTokenSource?.Cancel();
        }

        _cancellationTokenSource?.Dispose();
    }
}
