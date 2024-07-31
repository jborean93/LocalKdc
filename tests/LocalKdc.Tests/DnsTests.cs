using System;
using System.Net;
using Xunit;

namespace LocalKdc.Tests;

public class DnsTests
{
    [Fact]
    public void UnpackSrvRequest()
    {
        byte[] data = Convert.FromHexString("A18A01000001000000000000095F6B65726265726F73045F746370026463065F6D7364637306444F4D41494E04544553540000210001");

        DnsQuery actual = DnsQuery.Unpack(data);
        Assert.Equal(-24182, actual.TransactionId);
        Assert.Equal(unchecked((short)0x0100), actual.Flags);

        Assert.Single(actual.Questions);
        Assert.Equal(6, actual.Questions[0].Name.Length);
        Assert.Equal("_kerberos", actual.Questions[0].Name[0]);
        Assert.Equal("_tcp", actual.Questions[0].Name[1]);
        Assert.Equal("dc", actual.Questions[0].Name[2]);
        Assert.Equal("_msdcs", actual.Questions[0].Name[3]);
        Assert.Equal("DOMAIN", actual.Questions[0].Name[4]);
        Assert.Equal("TEST", actual.Questions[0].Name[5]);
        Assert.Equal(DnsType.SRV, actual.Questions[0].Type);
        Assert.Equal(DnsClassCode.IN, actual.Questions[0].Class);

        Assert.Empty(actual.Answers);

        Assert.Empty(actual.AuthoritativeAnswers);

        Assert.Empty(actual.AdditionalRecords);
    }

    [Fact]
    public void PackSrvRequest()
    {
        const string expected = "A18A01000001000000000000095F6B65726265726F73045F746370026463065F6D7364637306444F4D41494E04544553540000210001";

        DnsQuery value = new(
            -24182, unchecked((short)0x0100),
            [
                new DnsQuestion(
                    ["_kerberos", "_tcp", "dc", "_msdcs", "DOMAIN", "TEST"],
                    DnsType.SRV,
                    DnsClassCode.IN)
            ], [], [], []);
        byte[] actual = value.Pack();

        Assert.Equal(expected, Convert.ToHexString(actual));
    }

    [Fact]
    public void UnpackSrvResponse()
    {
        byte[] data = Convert.FromHexString("A18A85800001000100000003095F6B65726265726F73045F746370026463065F6D7364637306444F4D41494E04544553540000210001C00C00210001000002580018000000640058046463303106646F6D61696E047465737400C0480001000100000E100004C0A8380AC0480001000100000E100004C0A84004C048001C000100000E100010FD7CDCB61E6174962DF9F75A0065E71D");

        DnsQuery actual = DnsQuery.Unpack(data);
        Assert.Equal(-24182, actual.TransactionId);
        Assert.Equal(unchecked((short)0x8580), actual.Flags);

        Assert.Single(actual.Questions);
        Assert.Equal(6, actual.Questions[0].Name.Length);
        Assert.Equal("_kerberos", actual.Questions[0].Name[0]);
        Assert.Equal("_tcp", actual.Questions[0].Name[1]);
        Assert.Equal("dc", actual.Questions[0].Name[2]);
        Assert.Equal("_msdcs", actual.Questions[0].Name[3]);
        Assert.Equal("DOMAIN", actual.Questions[0].Name[4]);
        Assert.Equal("TEST", actual.Questions[0].Name[5]);
        Assert.Equal(DnsType.SRV, actual.Questions[0].Type);
        Assert.Equal(DnsClassCode.IN, actual.Questions[0].Class);

        Assert.Single(actual.Answers);
        Assert.IsType<SrvResourceRecord>(actual.Answers[0]);
        SrvResourceRecord answer = (SrvResourceRecord)actual.Answers[0];
        Assert.Equal(6, answer.Name.Length);
        Assert.Equal("_kerberos", answer.Name[0]);
        Assert.Equal("_tcp", answer.Name[1]);
        Assert.Equal("dc", answer.Name[2]);
        Assert.Equal("_msdcs", answer.Name[3]);
        Assert.Equal("DOMAIN", answer.Name[4]);
        Assert.Equal("TEST", answer.Name[5]);
        Assert.Equal(DnsClassCode.IN, answer.Class);
        Assert.Equal(600, answer.Ttl);
        Assert.Equal(0, answer.Priority);
        Assert.Equal(100, answer.Weight);
        Assert.Equal(88, answer.Port);
        Assert.Equal(3, answer.Target.Length);
        Assert.Equal("dc01", answer.Target[0]);
        Assert.Equal("domain", answer.Target[1]);
        Assert.Equal("test", answer.Target[2]);

        Assert.Empty(actual.AuthoritativeAnswers);

        Assert.Equal(3, actual.AdditionalRecords.Length);
        Assert.IsType<AResourceRecord>(actual.AdditionalRecords[0]);
        AResourceRecord aRecord = (AResourceRecord)actual.AdditionalRecords[0];
        Assert.Equal(3, aRecord.Name.Length);
        Assert.Equal("dc01", aRecord.Name[0]);
        Assert.Equal("domain", aRecord.Name[1]);
        Assert.Equal("test", aRecord.Name[2]);
        Assert.Equal(DnsClassCode.IN, aRecord.Class);
        Assert.Equal(3600, aRecord.Ttl);
        Assert.Equal(IPAddress.Parse("192.168.56.10"), aRecord.Address);

        Assert.IsType<AResourceRecord>(actual.AdditionalRecords[1]);
        aRecord = (AResourceRecord)actual.AdditionalRecords[1];
        Assert.Equal(3, aRecord.Name.Length);
        Assert.Equal("dc01", aRecord.Name[0]);
        Assert.Equal("domain", aRecord.Name[1]);
        Assert.Equal("test", aRecord.Name[2]);
        Assert.Equal(DnsClassCode.IN, aRecord.Class);
        Assert.Equal(3600, aRecord.Ttl);
        Assert.Equal(IPAddress.Parse("192.168.64.4"), aRecord.Address);

        Assert.IsType<AAAAResourceRecord>(actual.AdditionalRecords[2]);
        AAAAResourceRecord aaaaRecord = (AAAAResourceRecord)actual.AdditionalRecords[2];
        Assert.Equal(3, aaaaRecord.Name.Length);
        Assert.Equal("dc01", aaaaRecord.Name[0]);
        Assert.Equal("domain", aaaaRecord.Name[1]);
        Assert.Equal("test", aaaaRecord.Name[2]);
        Assert.Equal(DnsClassCode.IN, aaaaRecord.Class);
        Assert.Equal(3600, aaaaRecord.Ttl);
        Assert.Equal(IPAddress.Parse("fd7c:dcb6:1e61:7496:2df9:f75a:65:e71d"), aaaaRecord.Address);
    }

    [Fact]
    public void PackSrvResponse()
    {
        const string expected = "A18A85800001000100000003095F6B65726265726F73045F746370026463065F6D7364637306444F4D41494E04544553540000210001C00C00210001000002580018000000640058046463303106646F6D61696E047465737400C0480001000100000E100004C0A8380AC0480001000100000E100004C0A84004C048001C000100000E100010FD7CDCB61E6174962DF9F75A0065E71D";

        DnsQuery value = new(
            -24182,
            unchecked((short)0x8580),
            [
                new DnsQuestion(
                    ["_kerberos", "_tcp", "dc", "_msdcs", "DOMAIN", "TEST"],
                    DnsType.SRV,
                    DnsClassCode.IN)
            ],
            [
                new SrvResourceRecord(
                    ["_kerberos", "_tcp", "dc", "_msdcs", "DOMAIN", "TEST"],
                    DnsClassCode.IN, 600, 0, 100, 88,
                    ["dc01", "domain", "test"])
            ],
            [],
            [
                new AResourceRecord(
                    ["dc01", "domain", "test"], DnsClassCode.IN, 3600,
                    IPAddress.Parse("192.168.56.10")),
                new AResourceRecord(
                    ["dc01", "domain", "test"], DnsClassCode.IN, 3600,
                    IPAddress.Parse("192.168.64.4")),
                new AAAAResourceRecord(
                    ["dc01", "domain", "test"], DnsClassCode.IN, 3600,
                    IPAddress.Parse("fd7c:dcb6:1e61:7496:2df9:f75a:65:e71d")),
            ]);
        byte[] actual = value.Pack();

        Assert.Equal(expected, Convert.ToHexString(actual));
    }

    [Fact]
    public void UnpackSoaResponse()
    {
        byte[] data = Convert.FromHexString("260085830001000000010000095F6B65726265726F73045F746370026463075F6D7364637361066A6F7264616E04746573740000210001C02600060001000003840022C02609686F737461646D696EC02600000010000003840000012C00093A8000000384");

        DnsQuery actual = DnsQuery.Unpack(data);
        Assert.Equal(9728, actual.TransactionId);
        Assert.Equal(unchecked((short)0x8583), actual.Flags);

        Assert.Single(actual.Questions);
        Assert.Equal(6, actual.Questions[0].Name.Length);
        Assert.Equal("_kerberos", actual.Questions[0].Name[0]);
        Assert.Equal("_tcp", actual.Questions[0].Name[1]);
        Assert.Equal("dc", actual.Questions[0].Name[2]);
        Assert.Equal("_msdcsa", actual.Questions[0].Name[3]);
        Assert.Equal("jordan", actual.Questions[0].Name[4]);
        Assert.Equal("test", actual.Questions[0].Name[5]);
        Assert.Equal(DnsType.SRV, actual.Questions[0].Type);
        Assert.Equal(DnsClassCode.IN, actual.Questions[0].Class);

        Assert.Empty(actual.Answers);

        Assert.Single(actual.AuthoritativeAnswers);
        Assert.IsType<SOAResourceRecord>(actual.AuthoritativeAnswers[0]);
        SOAResourceRecord record = (SOAResourceRecord)actual.AuthoritativeAnswers[0];
        Assert.Equal(2, record.Name.Length);
        Assert.Equal("jordan", record.Name[0]);
        Assert.Equal("test", record.Name[1]);
        Assert.Equal(DnsType.SOA, record.Type);
        Assert.Equal(DnsClassCode.IN, record.Class);
        Assert.Equal(900, record.Ttl);
        Assert.Equal(2, record.PrimaryNameSever.Length);
        Assert.Equal("jordan", record.PrimaryNameSever[0]);
        Assert.Equal("test", record.PrimaryNameSever[1]);
        Assert.Equal(3, record.Mailbox.Length);
        Assert.Equal("hostadmin", record.Mailbox[0]);
        Assert.Equal("jordan", record.Mailbox[1]);
        Assert.Equal("test", record.Mailbox[2]);
        Assert.Equal(16, record.Serial);
        Assert.Equal(900, record.RefreshInterval);
        Assert.Equal(300, record.RetryInterval);
        Assert.Equal(604800, record.ExpireLimit);
        Assert.Equal(900, record.MinimumTTL);

        Assert.Empty(actual.AdditionalRecords);
    }

    [Fact]
    public void PackSoaResponse()
    {
        const string expected = "260085830001000000010000095F6B65726265726F73045F746370026463075F6D7364637361066A6F7264616E04746573740000210001C02600060001000003840022C02609686F737461646D696EC02600000010000003840000012C00093A8000000384";

        DnsQuery value = new(
            9728,
            unchecked((short)0x8583),
            [
                new DnsQuestion(
                    ["_kerberos", "_tcp", "dc", "_msdcsa", "jordan", "test"],
                    DnsType.SRV,
                    DnsClassCode.IN)
            ],
            [],
            [
                new SOAResourceRecord(
                    ["jordan", "test"], DnsClassCode.IN, 900,
                    ["jordan", "test"], ["hostadmin", "jordan", "test"], 16,
                    900, 300, 604800, 900)
            ],
            []);
        byte[] actual = value.Pack();

        Assert.Equal(expected, Convert.ToHexString(actual));
    }
}
