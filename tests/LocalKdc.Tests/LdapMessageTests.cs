using System;
using System.Formats.Asn1;
using System.Text;
using Xunit;

namespace LocalKdc.Tests;

public class LdapMessageTests
{
    [Fact]
    public static void UnpackSearchRequestFromDcLocator()
    {
        byte[] data = Convert.FromHexString("3084000000a202010163840000009904000a01000a0100020100020100010100a08400000072a384000000180409446e73446f6d61696e040b444f4d41494e2e54455354a384000000170404486f7374040f57494e2d4c344256435030514c5246a3840000000d04054e74566572040416000020a3840000001e040b446e73486f73744e616d65040f57494e2d4c344256435030514c524630840000000a04084e65746c6f676f6e");

        LdapMessage actual = LdapMessage.Unpack(data);
        Assert.IsType<SearchRequest>(actual);

        SearchRequest request = (SearchRequest)actual;
        Assert.Equal(1, request.MessageId);
        Assert.Equal("", request.BaseObject);
        Assert.Equal(SearchScope.BaseObject, request.Scope);
        Assert.Equal(DerefAlias.NeverDerefAliases, request.DerefAliases);
        Assert.Equal(0, request.SizeLimit);
        Assert.Equal(0, request.TimeLimit);
        Assert.False(request.TypesOnly);
        Assert.IsType<LdapFilterAnd>(request.Filter);
        Assert.Single(request.Attributes);
        Assert.Equal("Netlogon", request.Attributes[0]);

        LdapFilterAnd filter = (LdapFilterAnd)request.Filter;
        Assert.Equal(4, filter.Filters.Length);
        Assert.IsType<LdapFilterEquality>(filter.Filters[0]);
        Assert.Equal("DnsDomain", ((LdapFilterEquality)filter.Filters[0]).Attribute);
        Assert.Equal("DOMAIN.TEST", Encoding.UTF8.GetString(((LdapFilterEquality)filter.Filters[0]).Value));

        Assert.IsType<LdapFilterEquality>(filter.Filters[1]);
        Assert.Equal("Host", ((LdapFilterEquality)filter.Filters[1]).Attribute);
        Assert.Equal("WIN-L4BVCP0QLRF", Encoding.UTF8.GetString(((LdapFilterEquality)filter.Filters[1]).Value));

        Assert.IsType<LdapFilterEquality>(filter.Filters[2]);
        Assert.Equal("NtVer", ((LdapFilterEquality)filter.Filters[2]).Attribute);
        Assert.Equal("16000020", Convert.ToHexString(((LdapFilterEquality)filter.Filters[2]).Value));

        Assert.IsType<LdapFilterEquality>(filter.Filters[3]);
        Assert.Equal("DnsHostName", ((LdapFilterEquality)filter.Filters[3]).Attribute);
        Assert.Equal("WIN-L4BVCP0QLRF", Encoding.UTF8.GetString(((LdapFilterEquality)filter.Filters[3]).Value));
    }

    [Fact]
    public static void PackSearchRequest()
    {
        const string expected = "30818702010163818104000A01000A0100020100020100010100A062A3180409446E73446F6D61696E040B444F4D41494E2E54455354A3170404486F7374040F57494E2D4C344256435030514C5246A30D04054E74566572040416000020A31E040B446E73486F73744E616D65040F57494E2D4C344256435030514C5246300A04084E65746C6F676F6E";

        LdapFilterAnd filter = new([
            new LdapFilterEquality("DnsDomain", Encoding.UTF8.GetBytes("DOMAIN.TEST")),
            new LdapFilterEquality("Host", Encoding.UTF8.GetBytes("WIN-L4BVCP0QLRF")),
            new LdapFilterEquality("NtVer", [0x16, 0x00, 0x00, 0x20]),
            new LdapFilterEquality("DnsHostName", Encoding.UTF8.GetBytes("WIN-L4BVCP0QLRF")),
        ]);
        SearchRequest value = new(1, "", SearchScope.BaseObject, DerefAlias.NeverDerefAliases, 0, 0, false, filter, ["Netlogon"]);
        byte[] actual = value.Pack();

        Assert.Equal(expected, Convert.ToHexString(actual));
    }

    [Fact]
    public static void UnpackSearchResultEntryFromDcLocator()
    {
        const string expectedValue = "17000000FDF307001AEB7668C6B2CA4BB69CFEDA682E82FD06646F6D61696E047465737400C0180444433031C01806444F4D41494E00044443303100001744656661756C742D46697273742D536974652D4E616D6500C03D05000000FFFFFFFF";
        byte[] data = Convert.FromHexString("308400000089020101648400000080040030840000007830840000007204084e65746c6f676f6e318400000062046017000000fdf307001aeb7668c6b2ca4bb69cfeda682e82fd06646f6d61696e047465737400c0180444433031c01806444f4d41494e00044443303100001744656661756c742d46697273742d536974652d4e616d6500c03d05000000ffffffff");

        LdapMessage actual = LdapMessage.Unpack(data);
        Assert.IsType<SearchResultEntry>(actual);

        SearchResultEntry entry = (SearchResultEntry)actual;
        Assert.Equal(1, entry.MessageId);
        Assert.Equal("", entry.ObjectName);
        Assert.Single(entry.Attributes);
        Assert.Equal("Netlogon", entry.Attributes[0].Type);
        Assert.Single(entry.Attributes[0].Values);
        Assert.Equal(expectedValue, Convert.ToHexString(entry.Attributes[0].Values[0]));
    }

    [Fact]
    public static void PackSearchResultEntry()
    {
        const string expected = "301D020101641804003014301204084E65746C6F676F6E3106040400010203";

        SearchResultEntry value = new(1, "", [new PartialAttribute("Netlogon", [[0, 1, 2, 3]])]);
        byte[] actual = value.Pack();

        Assert.Equal(expected, Convert.ToHexString(actual));
    }

    [Fact]
    public static void UnpackSearchResultDoneFromDcLocator()
    {
        byte[] data = Convert.FromHexString("3084000000100201016584000000070A010004000400");

        LdapMessage actual = LdapMessage.Unpack(data);
        Assert.IsType<SearchResultDone>(actual);

        SearchResultDone entry = (SearchResultDone)actual;
        Assert.Equal(1, entry.MessageId);
        Assert.Equal(LdapResultCode.Success, entry.ResultCode);
        Assert.Empty(entry.MatchedDN);
        Assert.Empty(entry.DiagnosticMessage);
    }

    [Fact]
    public static void PackSearchResultDone()
    {
        const string expected = "300C02010165070A010004000400";

        SearchResultDone value = new(1, LdapResultCode.Success, "", "");
        byte[] actual = value.Pack();

        Assert.Equal(expected, Convert.ToHexString(actual));
    }
}
