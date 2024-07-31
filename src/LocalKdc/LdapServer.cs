using Microsoft.Extensions.Logging;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace LocalKdc;

public class LdapServer : UdpServer
{
    private readonly Dictionary<string, NetlogonSamLogonResponseEx> _netlogonResponses = new(StringComparer.OrdinalIgnoreCase);

    public LdapServer(IPAddress address, short port, ILoggerFactory loggerFactory)
        : base(address, port, loggerFactory.CreateLogger<LdapServer>())
    { }

    public void AddNetlogonResponse(string dnsDomainName, NetlogonSamLogonResponseEx response)
    {
        _netlogonResponses.Add(dnsDomainName, response);
    }

    public override byte[] ProcessData(byte[] data)
    {
        LdapMessage message = LdapMessage.Unpack(data);
        _logger.LogInformation("Received LdapMessage {0}", message);
        if (!(message is SearchRequest searchRequest))
        {
            throw new NotImplementedException($"LdapServer cannot handle {message.GetType().Name}");
        }

        string? dnsDomainName = null;
        NetlogonNtVersion ntVer = default;
        if (searchRequest.Filter is LdapFilterAnd filterAnd)
        {
            foreach (LdapFilter filter in filterAnd.Filters)
            {
                if (!(filter is LdapFilterEquality filterEqual))
                {
                    continue;
                }

                if (filterEqual.Attribute.Equals("dnsdomain", StringComparison.OrdinalIgnoreCase))
                {
                    dnsDomainName = Encoding.UTF8.GetString(filterEqual.Value);
                }
                else if (filterEqual.Attribute.Equals("ntver", StringComparison.OrdinalIgnoreCase))
                {
                    ntVer = (NetlogonNtVersion)BinaryPrimitives.ReadInt32LittleEndian(filterEqual.Value);
                }
            }
        }

        _logger.LogInformation("Parsing LdapSearch for DnsDomain '{0}' and NtVer {1}",
            dnsDomainName, ntVer);

        if (dnsDomainName is null || !_netlogonResponses.TryGetValue(dnsDomainName, out var nlResponse))
        {
            return new SearchResultDone(searchRequest.MessageId,
                LdapResultCode.Other, "",
                $"LdapServer cannot find registered info for domain '{dnsDomainName}'").Pack();
        }
        if (!ntVer.HasFlag(NetlogonNtVersion.Version5Ex) || ntVer.HasFlag(NetlogonNtVersion.Version5ExWithIp))
        {
            return new SearchResultDone(searchRequest.MessageId,
                LdapResultCode.Other, "",
                "LdapServer can only respond to requests for NETLOGON_NT_VERSION_5EX").Pack();
        }

        _logger.LogInformation("Replying with NT_VERSION info: {0}", nlResponse);

        SearchResultEntry resultEntry = new(
            MessageId: searchRequest.MessageId,
            ObjectName: "", Attributes: [
                new PartialAttribute("Netlogon", [nlResponse.Pack()])
            ]);
        SearchResultDone resultDone = new(
            MessageId: searchRequest.MessageId,
            ResultCode: LdapResultCode.Success,
            MatchedDN: "",
            DiagnosticMessage: "");

        byte[] entryBytes = resultEntry.Pack();
        byte[] doneBytes = resultDone.Pack();
        int sendSize = entryBytes.Length + doneBytes.Length;

        using var resultBuffer = MemoryPool<byte>.Shared.Rent(sendSize);
        entryBytes.AsMemory().CopyTo(resultBuffer.Memory);
        doneBytes.AsMemory().CopyTo(resultBuffer.Memory.Slice(entryBytes.Length));
        return resultBuffer.Memory[..sendSize].ToArray();
    }
}
