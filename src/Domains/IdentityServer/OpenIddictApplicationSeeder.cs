using System;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace SteamOpenIdConnectProvider.Domains.IdentityServer;

public sealed class OpenIddictApplicationSeeder
{
    public static async Task SeedAsync(
        IServiceProvider serviceProvider,
        OpenIdConfig config)
    {
        using var scope = serviceProvider.CreateScope();

        var context = scope.ServiceProvider
            .GetRequiredService<AppInMemoryDbContext>();
        await context.Database.EnsureCreatedAsync();

        var manager = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();

        // Check if client already exists
        var client = await manager.FindByClientIdAsync(config.ClientId);
        if (client == null)
        {
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = config.ClientId,
                ClientSecret = config.ClientSecret,
                DisplayName = config.ClientName,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                ClientType = OpenIddictConstants.ClientTypes.Confidential,

                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,

                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,

                    OpenIddictConstants.Permissions.Prefixes.Scope + "openid",
                    OpenIddictConstants.Permissions.Prefixes.Scope + "profile",

                    OpenIddictConstants.Permissions.ResponseTypes.Code
                },

                // Disable PKCE requirement to match IdentityServer4 behavior (RequirePkce = false)
                Requirements =
                {
                }
            };

            // Add redirect URIs
            foreach (var uri in config.RedirectUris)
            {
                descriptor.RedirectUris.Add(new Uri(uri));
            }

            // Add post-logout redirect URIs
            foreach (var uri in config.PostLogoutRedirectUris)
            {
                descriptor.PostLogoutRedirectUris.Add(new Uri(uri));
            }

            await manager.CreateAsync(descriptor);
        }
    }
}
