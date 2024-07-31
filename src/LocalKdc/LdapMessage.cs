using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Text;

namespace LocalKdc;

internal enum LdapResultCode
{
    Success,
    OperationsError,
    ProtocoLError,
    TimeLimitExceeded,
    SizeLimitExceeded,
    CompareFalse,
    CompareTrue,
    AuthMethodNotSupported,
    StrongerAuthRequired,
    Referral = 10,
    AdminLimitExceeded,
    UnavailableCriticalExtension,
    ConfidentialityRequired,
    SaslBindInProgress,
    NoSuchAttribute = 16,
    UndefinedAttributeType,
    InappropriateMatching,
    ConstraintViolation,
    AttributeOrValueExists,
    InvalidAttributeSyntax,
    NoSuchObject = 32,
    AliasProblem,
    InvalidDnSyntax,
    IsLeaf,
    AliasDereferencingProblem,
    InappropriateAuthentication = 48,
    InvalidCredentials,
    InsufficientAccessRights,
    Busy,
    Unavailable,
    UnwillingToPerform,
    LoopDetect,
    NamingViolation = 64,
    ObjectClassViolation,
    NotAllowedOnNonLeaf,
    NotAllowedOnRdn,
    EntryAlreadyExists,
    ObjectClassModsProhibited,
    AffectsMultipleDsas = 71,
    Other = 80,
}

internal enum SearchScope
{
    BaseObject,
    SignleLevel,
    WholeSubtree,
}

internal enum DerefAlias
{
    NeverDerefAliases,
    DerefInSearching,
    DerefFindingBaseObj,
    DerefAlways,
}

public abstract record LdapMessage(int MessageId)
{
    internal byte[] Pack()
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(MessageId);
            PackProtocolOP(writer);
        }

        return writer.Encode();
    }

    internal abstract void PackProtocolOP(AsnWriter writer);

    internal static LdapMessage Unpack(byte[] data)
    {
        AsnReader reader = new(data, AsnEncodingRules.BER);
        var seqReader = reader.ReadSequence();
        int messageId = (int)seqReader.ReadInteger();

        var protocolTag = seqReader.PeekTag();
        var valueReader = seqReader.ReadSequence(protocolTag);
        return protocolTag switch
        {
            var t when t == new Asn1Tag(TagClass.Application, SearchRequest.TagChoice, true)
                => SearchRequest.Unpack(messageId, valueReader),
            var t when t == new Asn1Tag(TagClass.Application, SearchResultEntry.TagChoice, true)
                => SearchResultEntry.Unpack(messageId, valueReader),
            var t when t == new Asn1Tag(TagClass.Application, SearchResultDone.TagChoice, true)
                => SearchResultDone.Unpack(messageId, valueReader),
            _ => throw new NotImplementedException(
                $"LdapMessage protocolOp CHOICE {protocolTag.TagClass} [{protocolTag.TagValue}] not implemented."),
        };
    }
}

internal record SearchRequest(
    int MessageId,
    string BaseObject,
    SearchScope Scope,
    DerefAlias DerefAliases,
    int SizeLimit,
    int TimeLimit,
    bool TypesOnly,
    LdapFilter Filter,
    string[] Attributes) : LdapMessage(MessageId)
{
    internal static int TagChoice => 3;

    internal override void PackProtocolOP(AsnWriter writer)
    {
        using (writer.PushSequence(new Asn1Tag(TagClass.Application, TagChoice, true)))
        {
            writer.WriteOctetString(Encoding.UTF8.GetBytes(BaseObject));
            writer.WriteEnumeratedValue(Scope);
            writer.WriteEnumeratedValue(DerefAliases);
            writer.WriteInteger(SizeLimit);
            writer.WriteInteger(TimeLimit);
            writer.WriteBoolean(TypesOnly);
            Filter.Pack(writer);
            using (writer.PushSequence())
            {
                foreach (string attr in Attributes)
                {
                    writer.WriteOctetString(Encoding.UTF8.GetBytes(attr));
                }
            }
        }
    }

    internal static SearchRequest Unpack(int messageId, AsnReader reader)
    {
        string baseObject = Encoding.UTF8.GetString(reader.ReadOctetString());
        var searchScope = reader.ReadEnumeratedValue<SearchScope>();
        var derefAliases = reader.ReadEnumeratedValue<DerefAlias>();
        int sizeLimit = (int)reader.ReadInteger();
        int timeLimit = (int)reader.ReadInteger();
        bool typesOnly = reader.ReadBoolean();
        LdapFilter filter = LdapFilter.Unpack(reader);

        List<string> attributes = new List<string>();
        var attributeReader = reader.ReadSequence();
        while (attributeReader.HasData)
        {
            string attr = Encoding.UTF8.GetString(attributeReader.ReadOctetString());
            attributes.Add(attr);
        }

        return new SearchRequest(
            MessageId: messageId,
            BaseObject: baseObject,
            Scope: searchScope,
            DerefAliases: derefAliases,
            SizeLimit: sizeLimit,
            TimeLimit: timeLimit,
            TypesOnly: typesOnly,
            Filter: filter,
            Attributes: attributes.ToArray());
    }
}

internal record SearchResultEntry(
    int MessageId,
    string ObjectName,
    PartialAttribute[] Attributes) : LdapMessage(MessageId)
{
    internal static int TagChoice => 4;

    internal override void PackProtocolOP(AsnWriter writer)
    {
        using (writer.PushSequence(new Asn1Tag(TagClass.Application, TagChoice, true)))
        {
            writer.WriteOctetString(Encoding.UTF8.GetBytes(ObjectName));
            using (writer.PushSequence())
            {
                foreach (PartialAttribute attr in Attributes)
                {
                    attr.Pack(writer);
                }
            }
        }
    }

    internal static SearchResultEntry Unpack(int messageId, AsnReader reader)
    {
        string objectName = Encoding.UTF8.GetString(reader.ReadOctetString());
        var attributeReader = reader.ReadSequence();
        List<PartialAttribute> attributes = new();
        while (attributeReader.HasData)
        {
            attributes.Add(PartialAttribute.Unpack(attributeReader));
        }

        return new SearchResultEntry(
            MessageId: messageId,
            ObjectName: objectName,
            Attributes: attributes.ToArray());
    }
}

internal record SearchResultDone(
    int MessageId,
    LdapResultCode ResultCode,
    string MatchedDN,
    string DiagnosticMessage) : LdapMessage(MessageId)
{
    internal static int TagChoice => 5;

    internal override void PackProtocolOP(AsnWriter writer)
    {
        using (writer.PushSequence(new Asn1Tag(TagClass.Application, TagChoice, true)))
        {
            writer.WriteEnumeratedValue(ResultCode);
            writer.WriteOctetString(Encoding.UTF8.GetBytes(MatchedDN));
            writer.WriteOctetString(Encoding.UTF8.GetBytes(DiagnosticMessage));
        }
    }

    internal static SearchResultDone Unpack(int messageId, AsnReader reader)
    {
        LdapResultCode code = reader.ReadEnumeratedValue<LdapResultCode>();
        string matchedDN = Encoding.UTF8.GetString(reader.ReadOctetString());
        string diagnosticMessage = Encoding.UTF8.GetString(reader.ReadOctetString());

        return new SearchResultDone(
            MessageId: messageId,
            ResultCode: code,
            MatchedDN: matchedDN,
            DiagnosticMessage: diagnosticMessage);
    }
}

internal record PartialAttribute(
    string Type,
    byte[][] Values)
{
    internal static PartialAttribute Unpack(AsnReader reader)
    {
        var paReader = reader.ReadSequence();

        string type = Encoding.UTF8.GetString(paReader.ReadOctetString());
        List<byte[]> values = new();
        var valueReader = paReader.ReadSetOf();
        while (valueReader.HasData)
        {
            values.Add(valueReader.ReadOctetString());
        }

        return new PartialAttribute(
            Type: type,
            Values: values.ToArray());
    }

    internal void Pack(AsnWriter writer)
    {
        using (writer.PushSequence())
        {
            writer.WriteOctetString(Encoding.UTF8.GetBytes(Type));
            using (writer.PushSetOf())
            {
                foreach (byte[] v in Values)
                {
                    writer.WriteOctetString(v);
                }
            }
        }
    }
}
