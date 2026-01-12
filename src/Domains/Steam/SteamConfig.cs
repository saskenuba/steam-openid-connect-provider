namespace SteamOpenIdConnectProvider.Domains.Steam;

public sealed class SteamConfig
{
    public const string ConfigKey = "Steam";

    public required string ApplicationKey { get; set; }

    /// <summary>
    /// Skip Steam API connectivity check at startup.
    /// Useful for CI/CD environments without internet access.
    /// Default: false (perform check)
    /// </summary>
    public bool SkipConnectivityCheck { get; set; } = false;

    /// <summary>
    /// Timeout in seconds for the connectivity check.
    /// Default: 5 seconds
    /// </summary>
    public int ConnectivityCheckTimeoutSeconds { get; set; } = 5;
}
