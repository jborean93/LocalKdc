
using System.IO;
using Kerberos.NET.Crypto;

namespace LocalKdc;

public class KerberosKeyTab
{
    public static void WriteKeytab(
        FakeKerberosPrincipal principal,
        string path,
        EncryptionType[] etypes)
    {
        KeyTable keyTable = new();
        foreach (EncryptionType etype in etypes)
        {
            KerberosKey key = principal.RetrieveLongTermCredential(etype);
            keyTable.Entries.Add(new KeyEntry(key));
        }

        using (FileStream fs = File.OpenWrite(path))
        using (BinaryWriter writer = new(fs))
        {
            keyTable.Write(writer);
            writer.Flush();
        }
    }
}
