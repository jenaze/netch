using Netch.Models;
using Netch.Utils;

#pragma warning disable VSTHRD200

namespace Netch.Servers;

public static class V2rayConfigUtils
{
    public static async Task<V2rayConfig> GenerateClientConfigAsync(Server server)
    {
        var v2rayConfig = new V2rayConfig
        {
            inbounds = new object[]
            {
                new
                {
                    port = Global.Settings.Socks5LocalPort,
                    protocol = "socks",
                    listen = Global.Settings.LocalAddress,
                    settings = new
                    {
                        auth = "noauth",
                        udp = true
                    }
                }
            }
        };

        v2rayConfig.outbounds = new[] { await outbound(server) };

        return v2rayConfig;
    }

    private static async Task<Outbound> outbound(Server server)
    {
        var outbound = new Outbound
        {
            settings = new OutboundConfiguration(),
            mux = new Mux()
        };

        switch (server)
        {
            case Socks5Server socks:
            {
                outbound.protocol = "socks";
                outbound.settings.servers = new object[]
                {
                    new
                    {
                        address = await server.AutoResolveHostnameAsync(),
                        port = server.Port,
                        users = socks.Auth()
                            ? new[]
                            {
                                new
                                {
                                    user = socks.Username,
                                    pass = socks.Password,
                                    level = 1
                                }
                            }
                            : null
                    }
                };
                outbound.settings.version = socks.Version;

                outbound.mux.enabled = false;
                outbound.mux.concurrency = -1;
                break;
            }
            case VLESSServer vless:
            {
                outbound.protocol = "vless";
                outbound.settings.vnext = new[]
                {
                    new VnextItem
                    {
                        address = await server.AutoResolveHostnameAsync(),
                        port = server.Port,
                        users = new[]
                        {
                            new User
                            {
                                id = getUUID(vless.UserID),
                                flow = vless.TLSSecureType == "xtls" ? "xtls-rprx-direct" : "",
                                encryption = vless.EncryptMethod
                            }
                        }
                    }
                };

                outbound.settings.packetEncoding = Global.Settings.V2RayConfig.XrayCone ? vless.PacketEncoding : "none";
                outbound.mux.packetEncoding = Global.Settings.V2RayConfig.XrayCone ? vless.PacketEncoding : "none";

                outbound.streamSettings = boundStreamSettings(vless);

                if (vless.TLSSecureType == "xtls")
                {
                    outbound.mux.enabled = false;
                    outbound.mux.concurrency = -1;
                }
                else
                {
                    outbound.mux.enabled = vless.UseMux ?? Global.Settings.V2RayConfig.UseMux;
                    outbound.mux.concurrency = vless.UseMux ?? Global.Settings.V2RayConfig.UseMux ? 8 : -1;
                }

                break;
            }
            case VMessServer vmess:
            {
                outbound.protocol = "vmess";
                if (vmess.EncryptMethod == "auto" && vmess.TLSSecureType != "none" && !Global.Settings.V2RayConfig.AllowInsecure)
                {
                    vmess.EncryptMethod = "zero";
                }
                outbound.settings.vnext = new[]
                {
                    new VnextItem
                    {
                        address = await server.AutoResolveHostnameAsync(),
                        port = server.Port,
                        users = new[]
                        {
                            new User
                            {
                                id = getUUID(vmess.UserID),
                                alterId = vmess.AlterID,
                                security = vmess.EncryptMethod
                            }
                        }
                    }
                };

                outbound.settings.packetEncoding = Global.Settings.V2RayConfig.XrayCone ? vmess.PacketEncoding : "none";
                outbound.mux.packetEncoding = Global.Settings.V2RayConfig.XrayCone ? vmess.PacketEncoding : "none";

                outbound.streamSettings = boundStreamSettings(vmess);

                outbound.mux.enabled = vmess.UseMux ?? Global.Settings.V2RayConfig.UseMux;
                outbound.mux.concurrency = vmess.UseMux ?? Global.Settings.V2RayConfig.UseMux ? 8 : -1;
                break;
            }
            case ShadowsocksServer ss:
                outbound.protocol = "shadowsocks";
                outbound.settings.servers = new[]
                {
                    new ShadowsocksServerItem
                    {
                        address = await server.AutoResolveHostnameAsync(),
                        port = server.Port,
                        method = ss.EncryptMethod,
                        password = ss.Password
                    }
                };
                outbound.settings.plugin = ss.Plugin ?? "";
                outbound.settings.pluginOpts = ss.PluginOption ?? "";
                
                if (Global.Settings.V2RayConfig.TCPFastOpen)
                {
                    outbound.streamSettings = new StreamSettings
                    {
                        sockopt = new Sockopt
                        {
                            tcpFastOpen = true
                        }
                    };
                }
                break;
             case ShadowsocksRServer ssr:
                outbound.protocol = "shadowsocks";
                outbound.settings.servers = new[]
                {
                    new ShadowsocksServerItem
                    {
                        address = await server.AutoResolveHostnameAsync(),
                        port = server.Port,
                        method = ssr.EncryptMethod,
                        password = ssr.Password,
                    }
                };
                outbound.settings.plugin = "shadowsocksr";
                outbound.settings.pluginArgs = new string[]
                {
                    "--obfs=" + ssr.OBFS,
                    "--obfs-param=" + ssr.OBFSParam ?? "",
                    "--protocol=" + ssr.Protocol,
                    "--protocol-param=" + ssr.ProtocolParam ?? ""
                };

                if (Global.Settings.V2RayConfig.TCPFastOpen)
                {
                    outbound.streamSettings = new StreamSettings
                    {
                        sockopt = new Sockopt
                        {
                            tcpFastOpen = true
                        }
                    };
                }
                break;
             case TrojanServer trojan:
                outbound.protocol = "trojan";
                outbound.settings.servers = new[]
                {
                    new ShadowsocksServerItem // I'm not serious
                    {
                        address = await server.AutoResolveHostnameAsync(),
                        port = server.Port,
                        method = "", // Trojan doesn't have 'method' in the same way as SS
                        password = trojan.Password,
                        flow = trojan.TLSSecureType == "xtls" && trojan.TransferProtocol != "http" ? "xtls-rprx-direct" : "" // flow only for non-http xtls
                    }
                };

                // Default stream settings for Trojan (direct TCP)
                var streamSettings = new StreamSettings
                {
                    network = "tcp", // Default, can be overridden by XHTTP settings
                    security = trojan.TLSSecureType
                };

                if (trojan.TransferProtocol == "http" && !string.IsNullOrEmpty(trojan.XHTTPMode) && trojan.XHTTPSpecificSettings != null)
                {
                    streamSettings.network = "http"; // Override network to http for XHTTP
                    // Basic httpSettings (Xray might still need this for path/host if not in xhttpSettings fully)
                    streamSettings.httpSettings = new HttpSettings
                    {
                        path = trojan.Path,
                        host = trojan.Host.SplitOrDefault()
                    };

                    var xhttpSettings = new XHttpSettings
                    {
                        method = trojan.XHTTPMode.ToLowerInvariant() == "auto" ? null : trojan.XHTTPMode,
                        path = trojan.Path,
                        host = trojan.Host.SplitOrDefault(),
                    };

                    var specificSettings = trojan.XHTTPSpecificSettings;
                    xhttpSettings.xPaddingBytes = specificSettings.PaddingBytes;
                    if (specificSettings.NoGRPCHeader) xhttpSettings.noGRPCHeader = true;
                    if (specificSettings.NoSSEHeader) xhttpSettings.noSSEHeader = true;
                    xhttpSettings.scMaxEachPostBytes = specificSettings.SCMaxEachPostBytes;
                    xhttpSettings.scMinPostsIntervalMs = specificSettings.SCMinPostsIntervalMs;
                    xhttpSettings.scMaxBufferedPosts = specificSettings.SCMaxBufferedPosts;
                    xhttpSettings.scStreamUpServerSecs = specificSettings.SCStreamUpServerSecs;

                    if (specificSettings.Xmux != null)
                    {
                        xhttpSettings.xmux = new XMuxSettings
                        {
                            maxConcurrency = specificSettings.Xmux.MaxConcurrency,
                            maxConnections = specificSettings.Xmux.MaxConnections,
                            cMaxReuseTimes = specificSettings.Xmux.CMaxReuseTimes,
                            hMaxRequestTimes = specificSettings.Xmux.HMaxRequestTimes,
                            hMaxReusableSecs = specificSettings.Xmux.HMaxReusableSecs,
                            hKeepAlivePeriod = specificSettings.Xmux.HKeepAlivePeriod
                        };
                    }
                    streamSettings.xhttpSettings = xhttpSettings;
                }

                // Apply TLS/XTLS settings regardless of XHTTP, as XHTTP is a transport layer
                if (trojan.TLSSecureType != "none")
                {
                    var tlsSettings = new TlsSettings
                    {
                        allowInsecure = Global.Settings.V2RayConfig.AllowInsecure,
                        serverName = trojan.Host ?? "" // SNI is usually the Host for Trojan
                    };

                    switch (trojan.TLSSecureType)
                    {
                        case "tls":
                            streamSettings.tlsSettings = tlsSettings;
                            break;
                        case "xtls":
                            streamSettings.xtlsSettings = tlsSettings;
                            // XTLS flow is handled in `vnext` user settings for VLESS,
                            // for Trojan, it's typically direct or via other means if not TCP.
                            // If XHTTP is used, XTLS direct flow might not be applicable.
                            break;
                    }
                }
                outbound.streamSettings = streamSettings;

                if (Global.Settings.V2RayConfig.TCPFastOpen)
                {
                    outbound.streamSettings.sockopt = new Sockopt
                    {
                        tcpFastOpen = true
                    };
                }
                break;
            case WireGuardServer wg:
                outbound.protocol = "wireguard";
                outbound.settings.address = await server.AutoResolveHostnameAsync();
                outbound.settings.port = server.Port;
                outbound.settings.localAddresses = wg.LocalAddresses.SplitOrDefault();
                outbound.settings.peerPublicKey = wg.PeerPublicKey;
                outbound.settings.privateKey = wg.PrivateKey;
                outbound.settings.preSharedKey = wg.PreSharedKey;
                outbound.settings.mtu = wg.MTU;

                if (Global.Settings.V2RayConfig.TCPFastOpen)
                {
                    outbound.streamSettings = new StreamSettings
                    {
                        sockopt = new Sockopt
                        {
                            tcpFastOpen = true
                        }
                    };
                }
                break;

            case SSHServer ssh:
                outbound.protocol = "ssh";
                outbound.settings.address = await server.AutoResolveHostnameAsync();
                outbound.settings.port = server.Port;
                outbound.settings.user = ssh.User;
                outbound.settings.password = ssh.Password;
                outbound.settings.privateKey = ssh.PrivateKey;
                outbound.settings.publicKey = ssh.PublicKey;
                
                if (Global.Settings.V2RayConfig.TCPFastOpen)
                {
                    outbound.streamSettings = new StreamSettings
                    {
                        sockopt = new Sockopt
                        {
                            tcpFastOpen = true
                        }
                    };
                }
                break;
        }

        return outbound;
    }

    private static StreamSettings boundStreamSettings(VMessServer server)
    {
        // https://xtls.github.io/config/transports

        var streamSettings = new StreamSettings
        {
            network = server.TransferProtocol,
            security = server.TLSSecureType
        };

        if (server.TLSSecureType != "none")
        {
            var tlsSettings = new TlsSettings
            {
                allowInsecure = Global.Settings.V2RayConfig.AllowInsecure,
                serverName = server.ServerName.ValueOrDefault() ?? server.Host.SplitOrDefault()?[0]
            };

            switch (server.TLSSecureType)
            {
                case "tls":
                    streamSettings.tlsSettings = tlsSettings;
                    break;
                case "xtls":
                    streamSettings.xtlsSettings = tlsSettings;
                    break;
            }
        }

        switch (server.TransferProtocol)
        {
            case "tcp":

                streamSettings.tcpSettings = new TcpSettings
                {
                    header = new
                    {
                        type = server.FakeType,
                        request = server.FakeType switch
                        {
                            "none" => null,
                            "http" => new
                            {
                                path = server.Path.SplitOrDefault(),
                                headers = new
                                {
                                    Host = server.Host.SplitOrDefault()
                                }
                            },
                            _ => throw new MessageException($"Invalid tcp type {server.FakeType}")
                        }
                    }
                };

                break;
            case "ws":

                streamSettings.wsSettings = new WsSettings
                {
                    path = server.Path.ValueOrDefault(),
                    headers = new
                    {
                        Host = server.Host.ValueOrDefault()
                    }
                };

                break;
            case "kcp":

                streamSettings.kcpSettings = new KcpSettings
                {
                    mtu = Global.Settings.V2RayConfig.KcpConfig.mtu,
                    tti = Global.Settings.V2RayConfig.KcpConfig.tti,
                    uplinkCapacity = Global.Settings.V2RayConfig.KcpConfig.uplinkCapacity,
                    downlinkCapacity = Global.Settings.V2RayConfig.KcpConfig.downlinkCapacity,
                    congestion = Global.Settings.V2RayConfig.KcpConfig.congestion,
                    readBufferSize = Global.Settings.V2RayConfig.KcpConfig.readBufferSize,
                    writeBufferSize = Global.Settings.V2RayConfig.KcpConfig.writeBufferSize,
                    header = new
                    {
                        type = server.FakeType
                    },
                    seed = server.Path.ValueOrDefault()
                };

                break;
            case "h2":

                streamSettings.httpSettings = new HttpSettings
                {
                    host = server.Host.SplitOrDefault(),
                    path = server.Path.ValueOrDefault()
                };

                break;
            case "quic":

                streamSettings.quicSettings = new QuicSettings
                {
                    security = server.QUICSecure,
                    key = server.QUICSecret,
                    header = new
                    {
                        type = server.FakeType
                    }
                };

                break;
            case "grpc":

                streamSettings.grpcSettings = new GrpcSettings
                {
                    serviceName = server.Path,
                    multiMode = server.FakeType == "multi"
                };

                break;

            case "http": // Handling for XHTTP, note network is "http"
                // Standard httpSettings for basic path/host if not using XHTTP enhancements
                streamSettings.httpSettings = new HttpSettings
                {
                    host = server.Host.SplitOrDefault(),
                    path = server.Path.ValueOrDefault()
                };

                // Populate xhttpSettings if XHTTPMode is specified
                if (!string.IsNullOrEmpty(server.XHTTPMode) && server.XHTTPSpecificSettings != null)
                {
                    var xhttpSettings = new XHttpSettings
                    {
                        method = server.XHTTPMode.ToLowerInvariant() == "auto" ? null : server.XHTTPMode,
                        path = server.Path.ValueOrDefault(), // Reuse server Path for XHTTP path
                        host = server.Host.SplitOrDefault(), // Reuse server Host for XHTTP host
                    };

                    var specificSettings = server.XHTTPSpecificSettings;
                    xhttpSettings.xPaddingBytes = specificSettings.PaddingBytes;

                    if (specificSettings.NoGRPCHeader)
                        xhttpSettings.noGRPCHeader = true;

                    if (specificSettings.NoSSEHeader)
                        xhttpSettings.noSSEHeader = true;

                    xhttpSettings.scMaxEachPostBytes = specificSettings.SCMaxEachPostBytes;
                    xhttpSettings.scMinPostsIntervalMs = specificSettings.SCMinPostsIntervalMs;
                    xhttpSettings.scMaxBufferedPosts = specificSettings.SCMaxBufferedPosts;
                    xhttpSettings.scStreamUpServerSecs = specificSettings.SCStreamUpServerSecs;


                    if (specificSettings.Xmux != null)
                    {
                        xhttpSettings.xmux = new XMuxSettings
                        {
                            maxConcurrency = specificSettings.Xmux.MaxConcurrency,
                            maxConnections = specificSettings.Xmux.MaxConnections,
                            cMaxReuseTimes = specificSettings.Xmux.CMaxReuseTimes,
                            hMaxRequestTimes = specificSettings.Xmux.HMaxRequestTimes,
                            hMaxReusableSecs = specificSettings.Xmux.HMaxReusableSecs,
                            hKeepAlivePeriod = specificSettings.Xmux.HKeepAlivePeriod
                        };
                    }
                    streamSettings.xhttpSettings = xhttpSettings;
                }
                break;

            default:
                throw new MessageException($"transfer protocol \"{server.TransferProtocol}\" not implemented yet");
        }

        if (Global.Settings.V2RayConfig.TCPFastOpen)
        {
            streamSettings.sockopt = new Sockopt
            {
                tcpFastOpen = true
            };
        }

        return streamSettings;
    }

    public static string getUUID(string uuid)
    {
        if (uuid.Length == 36 || uuid.Length == 32)
        {
            return uuid;
        }
        return uuid.GenerateUUIDv5();
    }
}