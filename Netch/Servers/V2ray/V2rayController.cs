using System.Net;
using System.Text.Json;
using Netch.Controllers;
using Netch.Interfaces;
using Netch.Models;

namespace Netch.Servers;

public class V2rayController : Guard, IServerController
{
    public V2rayController() : base("xray.exe") // Changed from v2ray-sn.exe to xray.exe
    {
        //if (!Global.Settings.V2RayConfig.XrayCone)
        //    Instance.StartInfo.Environment["XRAY_CONE_DISABLED"] = "true";
    }

    protected override IEnumerable<string> StartedKeywords => new[] { "Xray", "started" }; // Adjusted for typical Xray startup message

    protected override IEnumerable<string> FailedKeywords => new[] { "config file not readable", "failed to" }; // These should be general enough

    public override string Name => "Xray"; // Updated name

    public ushort? Socks5LocalPort { get; set; }

    public string? LocalAddress { get; set; }

    public virtual async Task<Socks5Server> StartAsync(Server s)
    {
        await using (var fileStream = new FileStream(Constants.TempConfig, FileMode.Create, FileAccess.Write, FileShare.Read))
        {
            await JsonSerializer.SerializeAsync(fileStream, await V2rayConfigUtils.GenerateClientConfigAsync(s), Global.NewCustomJsonSerializerOptions());
        }

        await StartGuardAsync("run -c ..\\data\\last.json");
        return new Socks5Server(IPAddress.Loopback.ToString(), this.Socks5LocalPort(), s.Hostname);
    }
}