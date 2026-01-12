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

        return ValidateOptionsResult.Success;
    }
}
