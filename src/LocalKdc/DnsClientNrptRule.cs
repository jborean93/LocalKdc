using System;
using System.Collections.Generic;
using System.Management;
using System.Threading.Tasks;

namespace LocalKdc;

public record class DnsClientNrptRule(string Name, string[] Namespaces, string[] NameServers)
{
    private const string WMI_PATH = @"\\.\root\Microsoft\Windows\DNS:PS_DnsClientNrptRule";

    public static async Task<DnsClientNrptRule[]> Get()
    {
        List<DnsClientNrptRule> rules = new();
        await InvokeMethod("Get", null, (o) =>
        {
            foreach (ManagementBaseObject obj in (ManagementBaseObject[])o["cmdletOutput"])
            {
                string name = (string)obj["Name"];
                string[] namespaces = (string[])obj["Namespace"];
                string[] nameservers = (string[])obj["NameServers"];
                rules.Add(new(name, namespaces, nameservers));
            }
        });

        return rules.ToArray();
    }

    public static async Task<DnsClientNrptRule> Create(string[] namespaces, string[] nameservers)
    {
        Dictionary<string, object?> newParams = new()
        {
            { "Namespace", namespaces },
            { "NameServers", nameservers },
            { "PassThru", true },
        };
        string name = "";
        await InvokeMethod("Add", newParams, (o) =>
        {
            name = (string)((ManagementBaseObject)o["cmdletOutput"])["Name"];
        });

        return new(name, namespaces, nameservers);
    }

    public async Task Remove()
        => await InvokeMethod("Remove", new() { { "Name", Name } }, null);

    private static async Task InvokeMethod(
        string method,
        Dictionary<string, object?>? parameters,
        Action<ManagementBaseObject>? onReady)
    {
        TaskCompletionSource<ManagementStatus> tcs = new();

        ManagementClass dnsClientNrptRule = new(WMI_PATH);
        ManagementBaseObject inParams = dnsClientNrptRule.GetMethodParameters(method);
        if (parameters is not null)
        {
            foreach (KeyValuePair<string, object?> kvp in parameters)
            {
                inParams[kvp.Key] = kvp.Value;
            }
        }

        ManagementOperationObserver observer = new();
        if (onReady is not null)
        {
            observer.ObjectReady += (sender, o) => onReady(o.NewObject);
        }
        observer.Completed += (sender, e) => tcs.SetResult(e.Status);
        dnsClientNrptRule.InvokeMethod(observer, method, inParams, null);

        ManagementStatus status = await tcs.Task;
        if (status != ManagementStatus.NoError)
        {
            throw new Exception($"{WMI_PATH}.{method}() failed: {status}");
        }
    }
}
