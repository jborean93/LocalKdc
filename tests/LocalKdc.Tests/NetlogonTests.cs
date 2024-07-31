using System;
using Xunit;

namespace LocalKdc.Tests;

public class NetlogonTests
{
    [Fact]
    public void UnpackNetlogonSamLogonResponseEx()
    {
        byte[] data = Convert.FromHexString("17000000FDF307001AEB7668C6B2CA4BB69CFEDA682E82FD06646F6D61696E047465737400C0180444433031C01806444F4D41494E00044443303100001744656661756C742D46697273742D536974652D4E616D6500C03D05000000FFFFFFFF");

        var actual = NetlogonSamLogonResponseEx.Unpack(data, (NetlogonNtVersion)0x20000016);
        Assert.Equal(NetlogonOpCodes.SamLogonResponseEx, actual.Opcode);
        Assert.Equal((DsFlag)521213, actual.Flags);
        Assert.Equal(new Guid("6876eb1a-b2c6-4bca-b69c-feda682e82fd"), actual.DomainGuid);
        Assert.Equal("domain.test", actual.DnsForestName);
        Assert.Equal("domain.test", actual.DnsDomainName);
        Assert.Equal("DC01.domain.test", actual.DnsHostName);
        Assert.Equal("DOMAIN", actual.NetbiosDomainName);
        Assert.Equal("DC01", actual.NetbiosComputerName);
        Assert.Equal("", actual.UserName);
        Assert.Equal("Default-First-Site-Name", actual.DcSiteName);
        Assert.Equal("Default-First-Site-Name", actual.ClientSiteName);
        Assert.Null(actual.NextClosestSiteName);
        Assert.Equal(5, actual.NtVersion);
        Assert.Equal(-1, actual.LmNtToken);
        Assert.Equal(-1, actual.Lm20Token);
    }

    [Fact]
    public void PackNetlogonSamLogonResponseEx()
    {
        const string expected = "17000000FDF307001AEB7668C6B2CA4BB69CFEDA682E82FD06646F6D61696E047465737400C0180444433031C01806444F4D41494E00044443303100001744656661756C742D46697273742D536974652D4E616D6500C03D05000000FFFFFFFF";

        var value = new NetlogonSamLogonResponseEx(
            Opcode: NetlogonOpCodes.SamLogonResponseEx,
            Flags: (DsFlag)521213,
            DomainGuid: new Guid("6876eb1a-b2c6-4bca-b69c-feda682e82fd"),
            DnsForestName: "domain.test",
            DnsDomainName: "domain.test",
            DnsHostName: "DC01.domain.test",
            NetbiosDomainName: "DOMAIN",
            NetbiosComputerName: "DC01",
            UserName: "",
            DcSiteName: "Default-First-Site-Name",
            ClientSiteName: "Default-First-Site-Name",
            NextClosestSiteName: null,
            NtVersion: 5,
            LmNtToken: -1,
            Lm20Token: -1);
        byte[] actual = value.Pack();

        Assert.Equal(expected, Convert.ToHexString(actual));
    }
}
