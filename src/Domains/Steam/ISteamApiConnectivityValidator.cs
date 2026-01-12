using System.Threading.Tasks;

namespace SteamOpenIdConnectProvider.Domains.Steam;

/// <summary>
/// Validates Steam API connectivity at application startup
/// </summary>
public interface ISteamApiConnectivityValidator
{
    /// <summary>
    /// Validates that the Steam API is accessible with the configured API key
    /// </summary>
    /// <returns>Task completing when validation is done</returns>
    /// <exception cref="InvalidOperationException">Thrown when validation fails</exception>
    Task ValidateAsync();
}
