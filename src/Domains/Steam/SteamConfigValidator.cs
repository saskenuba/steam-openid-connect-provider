using System.Linq;
using Microsoft.Extensions.Options;

namespace SteamOpenIdConnectProvider.Domains.Steam;

public class SteamConfigValidator : IValidateOptions<SteamConfig>
{
    public ValidateOptionsResult Validate(string? name, SteamConfig options)
    {
        if (string.IsNullOrWhiteSpace(options.ApplicationKey))
        {
            return ValidateOptionsResult.Fail("Steam:ApplicationKey is required");
        }

        if (options.ApplicationKey == "changeme")
        {
            return ValidateOptionsResult.Fail("Steam:ApplicationKey must be changed from default value 'changeme'");
        }

        if (options.ApplicationKey.Length != 32)
        {
            return ValidateOptionsResult.Fail(
                $"Steam:ApplicationKey must be exactly 32 characters (provided: {options.ApplicationKey.Length})");
        }

        if (!IsValidHexString(options.ApplicationKey))
        {
            return ValidateOptionsResult.Fail(
                "Steam:ApplicationKey must contain only hexadecimal characters (0-9, A-F)");
        }

        return ValidateOptionsResult.Success;
    }

    private static bool IsValidHexString(string value) =>
        value.All(c => (c >= '0' && c <= '9') ||
                       (c >= 'A' && c <= 'F') ||
                       (c >= 'a' && c <= 'f'));
}
