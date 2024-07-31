using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;

namespace LocalKdc;

public enum DnsType : short
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    HINFO = 13,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    SIG = 24,
    KEY = 25,
    AAAA = 28,
    LOC = 29,
    SRV = 33,
    NAPTR = 35,
    KX = 26,
    CERT = 37,
    DNAME = 39,
    APL = 42,
    DS = 43,
    SSHFP = 44,
    IPSECKEY = 45,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    DHCID = 49,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    SMIMEA = 53,
    HIP = 55,
    CDS = 59,
    CDNSKEY = 60,
    OPENPGPKEY = 61,
    CSYNC = 62,
    ZONEMD = 63,
    SVCB = 64,
    HTTPS = 65,
    EUI48 = 108,
    EUI64 = 109,
    TKEY = 249,
    TSIG = 250,
    URI = 256,
    WALLET = 262,
    TA = unchecked((short)32768),
    DLV = unchecked((short)32769)
}

public enum DnsClassCode : short
{
    IN = 0x0001,
    CH = 0x0002,
    HS = 0x0004,
}

public class DnsServer : UdpServer
{
    private readonly SOAResourceRecord _soaRecord;
    private readonly Dictionary<string, AResourceRecord> _aRecords = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, SrvResourceRecord> _srvRecords = new(StringComparer.OrdinalIgnoreCase);

    public DnsServer(
        IPAddress address,
        short port,
        string rootNamespace,
        ILoggerFactory loggerFactory) : base(address, port, loggerFactory.CreateLogger<DnsServer>())
    {
        string[] realmSplit = rootNamespace.Split('.');
        _soaRecord = new SOAResourceRecord(
            Name: realmSplit,
            Class: DnsClassCode.IN,
            Ttl: 900,
            PrimaryNameSever: realmSplit,
            Mailbox: realmSplit,
            Serial: 16,
            RefreshInterval: 900,
            RetryInterval: 300,
            ExpireLimit: 604800,
            MinimumTTL: 900);
    }

    public void AddARecord(string name, IPAddress target)
    {
        Debug.Assert(target.AddressFamily == AddressFamily.InterNetwork);
        _aRecords.Add(name, new(name.Split('.'), DnsClassCode.IN, 3600, target));
    }

    public void AddSRVRecord(string name, string target, short port)
    {
        _srvRecords.Add(name,
            new SrvResourceRecord(name.Split('.'), DnsClassCode.IN, 600, 0,
                100, port, target.Split('.')));
    }

    public override byte[] ProcessData(byte[] data)
    {
        DnsQuery query = DnsQuery.Unpack(data);
        List<ResourceRecord> answers = new();
        foreach (DnsQuestion question in query.Questions)
        {
            _logger.LogInformation("Processing DNS request {0} {1} for {2}",
                query.TransactionId, question.Type, string.Join('.', question.Name));
            ResourceRecord? record = question.Type switch
            {
                DnsType.A => HandleARecord(question),
                DnsType.SRV => HandleSRVRecord(question),
                _ => null,
            };

            if (record is not null)
            {
                _logger.LogInformation("DNS record found for {0} {1}: {2}",
                    query.TransactionId, question.Type, record);
                answers.Add(record);
            }
            else
            {
                _logger.LogInformation("No DNS record found for {0} {1}",
                    query.TransactionId, question.Type);
            }
        }

        short flags = unchecked((short)0x8580);
        ResourceRecord[] authoritativeAnswers = [];
        if (answers.Count == 0)
        {
            flags |= 0x3;  // Name not found.
            authoritativeAnswers = [_soaRecord];
        }

        DnsQuery response = new(
            TransactionId: query.TransactionId,
            Flags: flags,
            Questions: query.Questions,
            Answers: answers.ToArray(),
            AuthoritativeAnswers: authoritativeAnswers,
            AdditionalRecords: []);

        _logger.LogInformation("Sending DNS response for {0}", query.TransactionId);
        return response.Pack();
    }

    private AResourceRecord? HandleARecord(DnsQuestion question)
    {
        string name = string.Join('.', question.Name);
        if (_aRecords.TryGetValue(name, out var record))
        {
            return record;
        }

        return null;
    }

    private SrvResourceRecord? HandleSRVRecord(DnsQuestion question)
    {
        string name = string.Join('.', question.Name);
        if (_srvRecords.TryGetValue(name, out var record))
        {
            return record;
        }

        return null;
    }
}

public record class DnsQuery(
    short TransactionId,
    short Flags,
    DnsQuestion[] Questions,
    ResourceRecord[] Answers,
    ResourceRecord[] AuthoritativeAnswers,
    ResourceRecord[] AdditionalRecords)
{
    internal byte[] Pack()
    {
        using MemoryStream ms = new();
        using BinaryWriter writer = new(ms);

        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteInt16BigEndian(header, TransactionId);
        BinaryPrimitives.WriteInt16BigEndian(header[2..], Flags);
        BinaryPrimitives.WriteInt16BigEndian(header[4..], (short)Questions.Length);
        BinaryPrimitives.WriteInt16BigEndian(header[6..], (short)Answers.Length);
        BinaryPrimitives.WriteInt16BigEndian(header[8..], (short)AuthoritativeAnswers.Length);
        BinaryPrimitives.WriteInt16BigEndian(header[10..], (short)AdditionalRecords.Length);
        writer.Write(header);

        Dictionary<string, short> stringMap = new();
        foreach (DnsQuestion question in Questions)
        {
            question.Pack(writer, stringMap);
        }
        foreach (ResourceRecord answer in Answers)
        {
            answer.Pack(writer, stringMap);
        }
        foreach (ResourceRecord answer in AuthoritativeAnswers)
        {
            answer.Pack(writer, stringMap);
        }
        foreach (ResourceRecord answer in AdditionalRecords)
        {
            answer.Pack(writer, stringMap);
        }

        return ms.ToArray();
    }

    internal static DnsQuery Unpack(ReadOnlySpan<byte> data)
    {
        short tId = BinaryPrimitives.ReadInt16BigEndian(data);
        short flags = BinaryPrimitives.ReadInt16BigEndian(data[2..]);
        short numQuestions = BinaryPrimitives.ReadInt16BigEndian(data[4..]);
        short numAnswers = BinaryPrimitives.ReadInt16BigEndian(data[6..]);
        short numAA = BinaryPrimitives.ReadInt16BigEndian(data[8..]);
        short numAR = BinaryPrimitives.ReadInt16BigEndian(data[10..]);

        int offset = 12;
        DnsQuestion[] questions = new DnsQuestion[numQuestions];
        for (int i = 0; i < numQuestions; i++)
        {
            (questions[i], offset) = DnsQuestion.Unpack(data, offset);
        }
        ResourceRecord[] answers = new ResourceRecord[numAnswers];
        for (int i = 0; i < numAnswers; i++)
        {
            (answers[i], offset) = ResourceRecord.Unpack(data, offset);
        }
        ResourceRecord[] aa = new ResourceRecord[numAA];
        for (int i = 0; i < numAA; i++)
        {
            (aa[i], offset) = ResourceRecord.Unpack(data, offset);
        }
        ResourceRecord[] ar = new ResourceRecord[numAR];
        for (int i = 0; i < numAR; i++)
        {
            (ar[i], offset) = ResourceRecord.Unpack(data, offset);
        }

        return new(
            TransactionId: tId,
            Flags: flags,
            Questions: questions,
            Answers: answers,
            AuthoritativeAnswers: aa,
            AdditionalRecords: ar);
    }

    internal static (string[], int) ReadCompressedString(ReadOnlySpan<byte> block, int offset)
    {
        List<string> components = new();

        ReadOnlySpan<byte> blockPtr = block[offset..];
        int bytesRead = 0;
        bool appendRead = true;
        while (true)
        {
            int valueLen = blockPtr[0];

            if ((valueLen & 0xC0) != 0)
            {
                // If the first two bits are set this is a pointer to the block
                // which contains the remaining values. The pointer can span
                // across two octets.
                short nextPtr = (short)(((short)(blockPtr[0] & ~0xC0) << 8) | blockPtr[1]);
                valueLen = block[nextPtr];
                blockPtr = block[(nextPtr + 1)..];

                if (appendRead)
                {
                    bytesRead += 2;
                    appendRead = false;
                }
            }
            else
            {
                blockPtr = blockPtr[1..];
                if (appendRead)
                {
                    bytesRead += 1 + valueLen;
                }
            }

            if (valueLen == 0)
            {
                break;
            }

            string entry = Encoding.UTF8.GetString(blockPtr[..valueLen]);
            blockPtr = blockPtr[valueLen..];
            components.Add(entry);
        }

        return (components.ToArray(), offset + bytesRead);
    }

    internal static void WriteCompressedString(
        BinaryWriter writer,
        string[] value,
        Dictionary<string, short> stringMap,
        bool doNotCompress = false)
    {
        for (int i = 0; i < value.Length; i++)
        {
            string mapKey = string.Join('\0', value.Skip(i));

            if (mapKey == "")
            {
                writer.Write((byte)0);
                continue;
            }

            bool containsPtr = stringMap.TryGetValue(mapKey, out short valuePtr);
            if (containsPtr && !doNotCompress)
            {
                writer.Write((byte)((valuePtr >> 8) | 0xC0));
                writer.Write((byte)(valuePtr & 0xFF));
                break;
            }

            if (!containsPtr)
            {
                stringMap.Add(mapKey, (short)writer.BaseStream.Length);
            }

            byte[] valueBytes = Encoding.UTF8.GetBytes(value[i]);
            writer.Write((byte)valueBytes.Length);
            writer.Write(valueBytes);
            if (i == value.Length - 1)
            {
                writer.Write((byte)0);
            }
        }
    }
}

public record class DnsQuestion(
    string[] Name,
    DnsType Type,
    DnsClassCode Class)
{
    internal void Pack(BinaryWriter writer, Dictionary<string, short> stringMap)
    {
        DnsQuery.WriteCompressedString(writer, Name, stringMap);
        Span<byte> payload = stackalloc byte[4];
        BinaryPrimitives.WriteInt16BigEndian(payload, (short)Type);
        BinaryPrimitives.WriteInt16BigEndian(payload[2..], (short)Class);
        writer.Write(payload);
    }

    internal static (DnsQuestion, int) Unpack(ReadOnlySpan<byte> block, int offset)
    {
        (string[] name, offset) = DnsQuery.ReadCompressedString(block, offset);
        DnsType type = (DnsType)BinaryPrimitives.ReadInt16BigEndian(block[offset..]);
        DnsClassCode classCode = (DnsClassCode)BinaryPrimitives.ReadInt16BigEndian(block[(offset + 2)..]);

        return (new(name, type, classCode), offset + 4);
    }
}

public abstract record class ResourceRecord(
    string[] Name,
    DnsType Type,
    DnsClassCode Class,
    int Ttl)
{
    internal void Pack(BinaryWriter writer, Dictionary<string, short> stringMap)
    {
        DnsQuery.WriteCompressedString(writer, Name, stringMap);
        Span<byte> payload = stackalloc byte[8];
        BinaryPrimitives.WriteInt16BigEndian(payload, (short)Type);
        BinaryPrimitives.WriteInt16BigEndian(payload[2..], (short)Class);
        BinaryPrimitives.WriteInt32BigEndian(payload[4..], Ttl);
        writer.Write(payload);

        PackData(writer, stringMap);
    }

    internal abstract void PackData(BinaryWriter write, Dictionary<string, short> stringMap);

    internal static (ResourceRecord, int) Unpack(ReadOnlySpan<byte> block, int offset)
    {
        (string[] name, offset) = DnsQuery.ReadCompressedString(block, offset);
        DnsType type = (DnsType)BinaryPrimitives.ReadInt16BigEndian(block[offset..]);
        DnsClassCode classCode = (DnsClassCode)BinaryPrimitives.ReadInt16BigEndian(block[(offset + 2)..]);
        int ttl = BinaryPrimitives.ReadInt32BigEndian(block[(offset + 4)..]);
        short rdLength = BinaryPrimitives.ReadInt16BigEndian(block[(offset + 8)..]);
        ReadOnlySpan<byte> dataBlock = block.Slice(0, offset + rdLength + 10);

        ResourceRecord value = type switch
        {
            DnsType.A => AResourceRecord.Unpack(name, classCode, ttl, dataBlock, offset + 10),
            DnsType.SOA => SOAResourceRecord.Unpack(name, classCode, ttl, dataBlock, offset + 10),
            DnsType.AAAA => AAAAResourceRecord.Unpack(name, classCode, ttl, dataBlock, offset + 10),
            DnsType.SRV => SrvResourceRecord.Unpack(name, classCode, ttl, dataBlock, offset + 10),
            _ => throw new NotImplementedException($"ResourceRecord {type} not implemented."),
        };
        return (value, offset + rdLength + 10);
    }
}

public record class AResourceRecord(
    string[] Name,
    DnsClassCode Class,
    int Ttl,
    IPAddress Address) : ResourceRecord(Name, DnsType.A, Class, Ttl)
{
    internal override void PackData(BinaryWriter writer, Dictionary<string, short> stringMap)
    {
        Debug.Assert(Address.AddressFamily == AddressFamily.InterNetwork);
        Span<byte> data = stackalloc byte[6];
        BinaryPrimitives.WriteInt16BigEndian(data, 4);
        Address.TryWriteBytes(data[2..], out var _);
        writer.Write(data);
    }

    internal static AResourceRecord Unpack(
        string[] name,
        DnsClassCode classCode,
        int ttl,
        ReadOnlySpan<byte> block,
        int offset)
            => new(name, classCode, ttl, new IPAddress(block[offset..]));
}

public record class SOAResourceRecord(
    string[] Name,
    DnsClassCode Class,
    int Ttl,
    string[] PrimaryNameSever,
    string[] Mailbox,
    int Serial,
    int RefreshInterval,
    int RetryInterval,
    int ExpireLimit,
    int MinimumTTL) : ResourceRecord(Name, DnsType.SOA, Class, Ttl)
{
    internal override void PackData(BinaryWriter writer, Dictionary<string, short> stringMap)
    {
        long preLength = writer.BaseStream.Length;

        // The length is set after as we don't know it yet.
        writer.Write((short)0);

        DnsQuery.WriteCompressedString(writer, PrimaryNameSever, stringMap);
        DnsQuery.WriteCompressedString(writer, Mailbox, stringMap);

        Span<byte> data = stackalloc byte[20];
        BinaryPrimitives.WriteInt32BigEndian(data, Serial);
        BinaryPrimitives.WriteInt32BigEndian(data[4..], RefreshInterval);
        BinaryPrimitives.WriteInt32BigEndian(data[8..], RetryInterval);
        BinaryPrimitives.WriteInt32BigEndian(data[12..], ExpireLimit);
        BinaryPrimitives.WriteInt32BigEndian(data[16..], MinimumTTL);
        writer.Write(data);

        // Capture the length, encode it as big endian, write to the
        // required offset, then reset back to the end.
        short dataLength = (short)(writer.BaseStream.Length - preLength - 2);
        BinaryPrimitives.WriteInt16BigEndian(data, dataLength);
        writer.Seek((int)preLength, SeekOrigin.Begin);
        writer.Write(data[..2]);
        writer.Seek(0, SeekOrigin.End);
    }

    internal static SOAResourceRecord Unpack(
        string[] name,
        DnsClassCode classCode,
        int ttl,
        ReadOnlySpan<byte> block,
        int offset)
    {
        (string[] primary, offset) = DnsQuery.ReadCompressedString(block, offset);
        (string[] mailbox, offset) = DnsQuery.ReadCompressedString(block, offset);
        int serial = BinaryPrimitives.ReadInt32BigEndian(block[offset..]);
        int refresh = BinaryPrimitives.ReadInt32BigEndian(block[(offset + 4)..]);
        int retry = BinaryPrimitives.ReadInt32BigEndian(block[(offset + 8)..]);
        int expire = BinaryPrimitives.ReadInt32BigEndian(block[(offset + 12)..]);
        int minimum = BinaryPrimitives.ReadInt32BigEndian(block[(offset + 16)..]);


        return new(name, classCode, ttl, primary, mailbox, serial, refresh, retry, expire, minimum);
    }
}

public record class AAAAResourceRecord(
    string[] Name,
    DnsClassCode Class,
    int Ttl,
    IPAddress Address) : ResourceRecord(Name, DnsType.AAAA, Class, Ttl)
{
    internal override void PackData(BinaryWriter writer, Dictionary<string, short> stringMap)
    {
        Debug.Assert(Address.AddressFamily == AddressFamily.InterNetworkV6);
        Span<byte> data = stackalloc byte[18];
        BinaryPrimitives.WriteInt16BigEndian(data, 16);
        Address.TryWriteBytes(data[2..], out var _);
        writer.Write(data);
    }

    internal static AAAAResourceRecord Unpack(
        string[] name,
        DnsClassCode classCode,
        int ttl,
        ReadOnlySpan<byte> block,
        int offset)
            => new(name, classCode, ttl, new IPAddress(block[offset..]));
}

public record class SrvResourceRecord(
    string[] Name,
    DnsClassCode Class,
    int Ttl,
    short Priority,
    short Weight,
    short Port,
    string[] Target) : ResourceRecord(Name, DnsType.SRV, Class, Ttl)
{
    internal override void PackData(BinaryWriter writer, Dictionary<string, short> stringMap)
    {
        long preLength = writer.BaseStream.Length;

        Span<byte> data = stackalloc byte[8];
        // The length is set after as we don't know it yet.
        BinaryPrimitives.WriteInt16BigEndian(data[2..], Priority);
        BinaryPrimitives.WriteInt16BigEndian(data[4..], Weight);
        BinaryPrimitives.WriteInt16BigEndian(data[6..], Port);
        writer.Write(data);
        DnsQuery.WriteCompressedString(writer, Target, stringMap, doNotCompress: true);

        // Capture the length, encode it as big endian, write to the
        // required offset, then reset back to the end.
        short dataLength = (short)(writer.BaseStream.Length - preLength - 2);
        BinaryPrimitives.WriteInt16BigEndian(data, dataLength);
        writer.Seek((int)preLength, SeekOrigin.Begin);
        writer.Write(data[..2]);
        writer.Seek(0, SeekOrigin.End);
    }

    internal static SrvResourceRecord Unpack(
        string[] name,
        DnsClassCode classCode,
        int ttl,
        ReadOnlySpan<byte> block,
        int offset)
    {
        short priority = BinaryPrimitives.ReadInt16BigEndian(block[offset..]);
        short weight = BinaryPrimitives.ReadInt16BigEndian(block[(offset + 2)..]);
        short port = BinaryPrimitives.ReadInt16BigEndian(block[(offset + 4)..]);
        (string[] target, int _) = DnsQuery.ReadCompressedString(block, offset + 6);

        return new(name, classCode, ttl, priority, weight, port, target);
    }
}
