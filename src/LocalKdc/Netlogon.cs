using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;

namespace LocalKdc;

[Flags]
public enum NetlogonNtVersion
{
    None = 0x00000000,
    Version1 = 0x00000001,
    Version5 = 0x00000002,
    Version5Ex = 0x00000004,
    Version5ExWithIp = 0x00000008,
    WithClosestSite = 0x00000010,
    AvoidNt4Emul = 0x01000000,
    Pdc = 0x10000000,
    Ip = 0x20000000,
    Local = 0x40000000,
    Gc = unchecked((int)0x80000000),
}

[Flags]
public enum NetlogonOpCodes : short
{
    PrimaryQuery = 7,
    PrimaryResponse = 12,
    SamLogonRequest = 18,
    SamLogonResponse = 19,
    SamPauseResponse = 20,
    SamUserUnknown = 21,
    SamLogonResponseEx = 23,
    SamPauseResponseEx = 24,
    SamUserUnknownEx = 25,
}

[Flags]
public enum DsFlag
{
    None = 0x00000000,
    Pdc = 0x00000001,
    Gc = 0x00000004,
    Ldap = 0x00000008,
    Ds = 0x00000010,
    Kdc = 0x00000020,
    Timeserv = 0x00000040,
    Closest = 0x00000080,
    Writable = 0x00000100,
    GoodTimeserv = 0x00000200,
    Ndnc = 0x00000400,
    SelectSecretDomain6 = 0x00000800,
    FullSecretDomain6 = 0x00001000,
    Ws = 0x00002000,
    Ds8 = 0x00004000,
    Ds9 = 0x00008000,
    Ds10 = 0x00010000,
    KeyList = 0x00020000,
    // DS_13 is not in any reference header I can find but is what nltest shows.
    Ds13 = 0x00040000,
    DnsController = 0x20000000,
    DnsDomain = 0x40000000,
    DnsForest = unchecked((int)0x80000000),
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8401a33f-34a8-40ca-bf03-c3484b66265f
public record class NetlogonSamLogonResponseEx(
    NetlogonOpCodes Opcode,
    DsFlag Flags,
    Guid DomainGuid,
    string DnsForestName,
    string DnsDomainName,
    string DnsHostName,
    string NetbiosDomainName,
    string NetbiosComputerName,
    string UserName,
    string DcSiteName,
    string ClientSiteName,
    string? NextClosestSiteName,
    int NtVersion,
    short LmNtToken,
    short Lm20Token)
{
    internal byte[] Pack()
    {
        Dictionary<string, short> stringMap = new Dictionary<string, short>();
        using var ms = new MemoryStream(128);
        using var writer = new BinaryWriter(ms);

        writer.Write((short)Opcode);
        writer.Write((short)0);  // Sbz
        writer.Write((int)Flags);
        writer.Write(DomainGuid.ToByteArray());
        DnsQuery.WriteCompressedString(writer, DnsForestName.Split('.'), stringMap);
        DnsQuery.WriteCompressedString(writer, DnsDomainName.Split('.'), stringMap);
        DnsQuery.WriteCompressedString(writer, DnsHostName.Split('.'), stringMap);
        DnsQuery.WriteCompressedString(writer, [NetbiosDomainName], stringMap);
        DnsQuery.WriteCompressedString(writer, [NetbiosComputerName], stringMap);
        DnsQuery.WriteCompressedString(writer, [UserName], stringMap);
        DnsQuery.WriteCompressedString(writer, [DcSiteName], stringMap);
        DnsQuery.WriteCompressedString(writer, [ClientSiteName], stringMap);
        if (NextClosestSiteName is not null)
        {
            DnsQuery.WriteCompressedString(writer, [NextClosestSiteName], stringMap);
        }
        writer.Write(NtVersion);
        writer.Write(LmNtToken);
        writer.Write(Lm20Token);
        writer.Flush();

        return ms.ToArray();
    }

    internal static NetlogonSamLogonResponseEx Unpack(
        ReadOnlySpan<byte> data,
        NetlogonNtVersion requestFlags)
    {
        NetlogonOpCodes opcode = (NetlogonOpCodes)BinaryPrimitives.ReadInt16LittleEndian(data);
        DsFlag flags = (DsFlag)BinaryPrimitives.ReadInt32LittleEndian(data[4..8]);
        Guid domainGuid = new Guid(data[8..24]);

        int offset = 24;
        (string[] dnsForestName, offset) = DnsQuery.ReadCompressedString(data, offset);
        (string[] dnsDomainName, offset) = DnsQuery.ReadCompressedString(data, offset);
        (string[] dnsHostName, offset) = DnsQuery.ReadCompressedString(data, offset);
        (string[] netbiosDomainName, offset) = DnsQuery.ReadCompressedString(data, offset);
        (string[] netbiosComputerName, offset) = DnsQuery.ReadCompressedString(data, offset);
        (string[] userName, offset) = DnsQuery.ReadCompressedString(data, offset);
        (string[] dcSiteName, offset) = DnsQuery.ReadCompressedString(data, offset);
        (string[] clientSiteName, offset) = DnsQuery.ReadCompressedString(data, offset);

        if (requestFlags.HasFlag(NetlogonNtVersion.Version5ExWithIp))
        {
            // Ignore DcSockAddrSize and DcSockAddr
            offset += 17;
        }

        string? nextClosestSiteName = null;
        if ((data.Length - offset) > 8 && requestFlags.HasFlag(NetlogonNtVersion.WithClosestSite))
        {
            (string[] rawNextClosestSiteName, offset) = DnsQuery.ReadCompressedString(data, offset);
            nextClosestSiteName = string.Join('.', rawNextClosestSiteName);
        }

        int ntVersion = BinaryPrimitives.ReadInt32LittleEndian(data[offset..]);
        short lmNtToken = BinaryPrimitives.ReadInt16LittleEndian(data[(offset + 4)..]);
        short lm20Token = BinaryPrimitives.ReadInt16LittleEndian(data[(offset + 6)..]);

        return new NetlogonSamLogonResponseEx(
            Opcode: opcode,
            Flags: flags,
            DomainGuid: domainGuid,
            DnsForestName: string.Join('.', dnsForestName),
            DnsDomainName: string.Join('.', dnsDomainName),
            DnsHostName: string.Join('.', dnsHostName),
            NetbiosDomainName: string.Join('.', netbiosDomainName),
            NetbiosComputerName: string.Join('.', netbiosComputerName),
            UserName: string.Join('.', userName),
            DcSiteName: string.Join('.', dcSiteName),
            ClientSiteName: string.Join('.', clientSiteName),
            NextClosestSiteName: nextClosestSiteName,
            NtVersion: ntVersion,
            LmNtToken: lmNtToken,
            Lm20Token: lm20Token);
    }
}
