using System;
using System.Linq;
using Microsoft.Extensions.Options;

namespace SteamOpenIdConnectProvider.Domains.IdentityServer;

public class OpenIdConfigValidator : IValidateOptions<OpenIdConfig>
{
    public ValidateOptionsResult Validate(string? name, OpenIdConfig options)
    {
        if (string.IsNullOrWhiteSpace(options.ClientId))
        {
            return ValidateOptionsResult.Fail("OpenId:ClientId is required");
        }

        if (string.IsNullOrWhiteSpace(options.ClientSecret))
        {
            return ValidateOptionsResult.Fail("OpenId:ClientSecret is required");
        }

        if (string.IsNullOrWhiteSpace(options.RedirectUri))
        {
            return ValidateOptionsResult.Fail("OpenId:RedirectUri is required");
        }

        // Validate redirect URIs are valid URLs
        foreach (var uri in options.RedirectUris)
        {
            if (!Uri.TryCreate(uri, UriKind.Absolute, out _))
            {
                return ValidateOptionsResult.Fail($"Invalid redirect URI: {uri}");
            }
        }

        // Validate post-logout redirect URIs if provided
        if (!string.IsNullOrWhiteSpace(options.PostLogoutRedirectUri))
        {
            foreach (var uri in options.PostLogoutRedirectUris)
            {
                if (!Uri.TryCreate(uri, UriKind.Absolute, out _))
                {
                    return ValidateOptionsResult.Fail($"Invalid post-logout redirect URI: {uri}");
                }
            }
        }

        return ValidateOptionsResult.Success;
    }
}
