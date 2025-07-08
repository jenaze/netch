using Netch.Models;

namespace Netch.Servers;

public class TrojanServer : Server
{
    private string _tlsSecureType = VLESSGlobal.TLSSecure[1];

    public override string Type { get; } = "Trojan";

    public override string MaskedData()
    {
        return "";
    }

    /// <summary>
    ///     密码
    /// </summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>
    ///     伪装域名
    /// </summary>
    public string? Host { get; set; }

    /// <summary>
    ///     TLS 底层传输安全
    /// </summary>
    public string TLSSecureType
    {
        get => _tlsSecureType;
        set
        {
            if (value == "")
                value = VLESSGlobal.TLSSecure[1];

            _tlsSecureType = value;
        }
    }

    #region XHTTP Settings
    // Note: For Trojan, XHTTP implies using an HTTP-based transport layer before Trojan.
    // The Netch UI and Trojan controller would need to handle this specific setup.
    // These fields are added for model consistency and potential future use.

    /// <summary>
    /// Specifies the HTTP transport protocol if Trojan is to be wrapped in XHTTP.
    /// Should be "http" if XHTTPMode is set.
    /// </summary>
    public string? TransferProtocol { get; set; } // Should be "http" for XHTTP

    /// <summary>
    /// XHTTP Mode when TransferProtocol is "http".
    /// </summary>
    public string? XHTTPMode { get; set; }

    /// <summary>
    /// Path for XHTTP (if applicable)
    /// </summary>
    public string? Path { get; set; }


    public XHTTPSettingsModel? XHTTPSpecificSettings { get; set; } = new();
    #endregion
}