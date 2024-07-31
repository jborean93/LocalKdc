using Kerberos.NET.Server;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace LocalKdc;

public class Program
{
    private const short DNS_PORT = 53;
    private const short KDC_PORT = 88;
    private const short LDAP_PORT = 389;
    private const string REALM = "contoso.com";
    private const string USERNAME = "user";
    private const string SERVICE = "test-service";
    private const string PASSWORD = "Password123";

    public static async Task Main(string[] args)
    {
        using ILoggerFactory loggerFactory =
            LoggerFactory.Create(builder =>
                builder.AddSimpleConsole(options =>
                {
                    options.IncludeScopes = true;
                    options.SingleLine = true;
                    options.TimestampFormat = "HH:mm:ss ";
                }));

        string listenerAddress;
        if (args.Length == 0)
        {
            listenerAddress = "127.0.0.1";
        }
        else
        {
            listenerAddress = args[0];
        }

        if (listenerAddress == "test")
        {
            SspiClient.TryKerberosAuth(
                $"{USERNAME}@{REALM.ToUpperInvariant()}",
                PASSWORD,
                $"host/{SERVICE}.{REALM}",
                loggerFactory);
        }
        else
        {
            IPAddress listener = IPAddress.Parse(listenerAddress);
            await Server(listener, loggerFactory);
        }
    }

    private static async Task Server(IPAddress listener, ILoggerFactory loggerFactory)
    {
        // This is pretty yuck but we want to try and cleanup the rule if ctrl+c
        // was pressed on the console.
        DnsClientNrptRule? nrptRule = null;
        Console.CancelKeyPress += (s, e) =>
        {
            if (nrptRule != null)
            {
                nrptRule.Remove().GetAwaiter().GetResult();
            }
        };

        // Cleanup any existing rules in case they conflict. This could be
        // tidier to just change the nameserver.
        foreach (DnsClientNrptRule rule in await DnsClientNrptRule.Get())
        {
            if (
                rule.Namespaces.Contains(REALM, StringComparer.OrdinalIgnoreCase) ||
                rule.Namespaces.Contains($".{REALM}", StringComparer.OrdinalIgnoreCase))
            {
                await rule.Remove();
            }
        }
        nrptRule = await DnsClientNrptRule.Create([REALM, $".{REALM}"], [listener.ToString()]);

        string kdcRealm = REALM.ToUpperInvariant();
        var principalService = new FakePrincipalService();
        var krbtgt = new FakeKerberosPrincipal(
            PrincipalType.Service, "krbtgt", kdcRealm, new byte[16]);
        principalService.Add("krbtgt", krbtgt);
        principalService.Add($"krbtgt/{kdcRealm}", krbtgt);

        var servicePrinc = new FakeKerberosPrincipal(
            PrincipalType.Service, SERVICE, kdcRealm,
            Encoding.Unicode.GetBytes(PASSWORD));
        principalService.Add($"host/{SERVICE}.{kdcRealm}", servicePrinc);

        var userPrinc = new FakeKerberosPrincipal(
            PrincipalType.User, USERNAME, kdcRealm,
            Encoding.Unicode.GetBytes(PASSWORD));
        principalService.Add(USERNAME, userPrinc);
        principalService.Add($"{USERNAME}@{kdcRealm}", userPrinc);

        using KdcServer kdcServer = new(
            listener,
            KDC_PORT,
            kdcRealm,
            principalService,
            loggerFactory);

        using DnsServer dnsServer = new(
            listener,
            DNS_PORT,
            REALM,
            loggerFactory);
        dnsServer.AddARecord($"dc01.{REALM}", listener);
        dnsServer.AddSRVRecord($"_ldap._tcp.dc._msdcs.{REALM}", $"dc01.{REALM}", KDC_PORT);
        dnsServer.AddSRVRecord($"_kerberos._tcp.dc._msdcs.{REALM}", $"dc01.{REALM}", KDC_PORT);

        using LdapServer ldapServer = new(listener, LDAP_PORT, loggerFactory);
        ldapServer.AddNetlogonResponse(REALM,
            new NetlogonSamLogonResponseEx(
                Opcode: NetlogonOpCodes.SamLogonResponseEx,
                Flags: DsFlag.Pdc | DsFlag.Gc | DsFlag.Ldap | DsFlag.Ds |
                    DsFlag.Kdc | DsFlag.Timeserv | DsFlag.Closest |
                    DsFlag.Writable | DsFlag.GoodTimeserv |
                    DsFlag.FullSecretDomain6 | DsFlag.Ws | DsFlag.Ds8 |
                    DsFlag.Ds9 | DsFlag.Ds10 | DsFlag.KeyList | DsFlag.Ds13,
                DomainGuid: Guid.NewGuid(),
                DnsForestName: REALM,
                DnsDomainName: REALM,
                DnsHostName: $"dc01.{REALM}",
                NetbiosDomainName: "",
                NetbiosComputerName: "",
                UserName: "",
                DcSiteName: "Default-First-Site-Name",
                ClientSiteName: "Default-First-Site-Name",
                NextClosestSiteName: null,
                NtVersion: 5,
                LmNtToken: -1,
                Lm20Token: -1));

        kdcServer.Start();
        dnsServer.Start();
        ldapServer.Start();
        await Task.Delay(-1);
    }
}
