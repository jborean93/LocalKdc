using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Text;

namespace LocalKdc;

public abstract record LdapFilter
{
    internal abstract void Pack(AsnWriter writer);

    internal static LdapFilter Unpack(AsnReader reader)
    {
        var choiceTag = reader.PeekTag();
        var seqReader = reader.ReadSequence(choiceTag);

        return choiceTag switch
        {
            var t when t == new Asn1Tag(TagClass.ContextSpecific, LdapFilterAnd.TagChoice, true)
                => LdapFilterAnd.Unpack(seqReader),
            var t when t == new Asn1Tag(TagClass.ContextSpecific, LdapFilterEquality.TagChoice, true)
                => LdapFilterEquality.Unpack(seqReader),
            _ => throw new NotImplementedException(
                $"LdapFilter CHOICE {choiceTag.TagClass} [{choiceTag.TagValue}] not implemented."),
        };
    }
}

public record LdapFilterAnd(LdapFilter[] Filters) : LdapFilter
{
    internal static int TagChoice => 0;

    internal override void Pack(AsnWriter writer)
    {
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, TagChoice, true)))
        {
            foreach (LdapFilter filter in Filters)
            {
                filter.Pack(writer);
            }
        }
    }

    internal new static LdapFilterAnd Unpack(AsnReader reader)
    {
        List<LdapFilter> filters = new();
        while (reader.HasData)
        {
            filters.Add(LdapFilter.Unpack(reader));
        }

        return new LdapFilterAnd(filters.ToArray());
    }
}

public record LdapFilterEquality(string Attribute, byte[] Value) : LdapFilter
{
    internal static int TagChoice => 3;

    internal override void Pack(AsnWriter writer)
    {
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, TagChoice, true)))
        {
            writer.WriteOctetString(Encoding.UTF8.GetBytes(Attribute));
            writer.WriteOctetString(Value);
        }
    }

    internal new static LdapFilterEquality Unpack(AsnReader reader)
    {
        string attribute = Encoding.UTF8.GetString(reader.ReadOctetString());
        byte[] value = reader.ReadOctetString();

        return new LdapFilterEquality(attribute, value);
    }
}
