using System;
using System.Linq;
using System.Net.Http.Headers;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Serilog;
using SteamOpenIdConnectProvider.Domains.Common;
using SteamOpenIdConnectProvider.Domains.IdentityServer;
using SteamOpenIdConnectProvider.Domains.Steam;
using SteamOpenIdConnectProvider.Middleware;

namespace SteamOpenIdConnectProvider;

public sealed class Startup(IConfiguration configuration)
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllers();

        services.AddDbContext<AppInMemoryDbContext>(options =>
            options.UseInMemoryDatabase("default"));

        services.AddIdentity<IdentityUser, IdentityRole>(options =>
            {
                options.User.AllowedUserNameCharacters = string.Empty;
                options.User.RequireUniqueEmail = false;
                options.Lockout.AllowedForNewUsers = false;
            })
            .AddEntityFrameworkStores<AppInMemoryDbContext>()
            .AddDefaultTokenProviders();

        var openIdConfig = configuration.GetSection(OpenIdConfig.ConfigKey);
        services
            .Configure<OpenIdConfig>(openIdConfig);

        services.AddSingleton<IValidateOptions<OpenIdConfig>, OpenIdConfigValidator>();
        services.AddOptions<OpenIdConfig>().ValidateOnStart();

        services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseSuccessEvents = true;
                options.UserInteraction.LoginUrl = "/external-login";
                options.UserInteraction.LogoutUrl = "/external-logout";
            })
            .AddAspNetIdentity<IdentityUser>()
            .AddProfileService<SteamProfileService>()
            .AddInMemoryClients(IdentityServerConfigFactory.GetClients(openIdConfig.Get<OpenIdConfig>()!))
            .AddInMemoryPersistedGrants()
            .AddDeveloperSigningCredential()
            .AddInMemoryIdentityResources(IdentityServerConfigFactory.GetIdentityResources());

        var steamConfig = configuration.GetSection(SteamConfig.ConfigKey);
        services
            .Configure<SteamConfig>(steamConfig);

        services.AddSingleton<IValidateOptions<SteamConfig>, SteamConfigValidator>();
        services.AddOptions<SteamConfig>().ValidateOnStart();

        // Register connectivity validator with HttpClient for fail-fast validation
        services.AddHttpClient<ISteamApiConnectivityValidator, SteamApiConnectivityValidator>(client =>
        {
            client.Timeout = TimeSpan.FromSeconds(10);
            client.DefaultRequestHeaders.UserAgent.Add(
                new ProductInfoHeaderValue("SteamOpenIdConnectProvider", "1.1.0"));
        });
        services.AddHostedService<SteamApiStartupValidator>();

        services.AddHttpClient<IProfileService, SteamProfileService>();

        services.AddAuthentication()
            .AddCookie(options =>
            {
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.Cookie.IsEssential = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            })
            .AddSteam(options =>
            {
                options.ApplicationKey = steamConfig.Get<SteamConfig>()!.ApplicationKey;
            });
            
        services.Configure<CookiePolicyOptions>(options =>
        {
            options.Secure = CookieSecurePolicy.Always;
            options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
            options.OnAppendCookie = cookieContext =>
                SetSameSiteCookieOption(cookieContext.Context, cookieContext.CookieOptions);
            options.OnDeleteCookie = cookieContext =>
                SetSameSiteCookieOption(cookieContext.Context, cookieContext.CookieOptions);
        });

        services.AddHealthChecks()
            .AddUrlGroup(
                uri: new Uri(SteamConstants.OpenIdUrl), 
                name: "Steam",
                configureClient: (_, client) =>
                {
                    var userAgentHeaders
                        = client.DefaultRequestHeaders.UserAgent;

                    userAgentHeaders.Clear();
                    userAgentHeaders.Add(new ProductInfoHeaderValue("SteamOpenIdConnectProvider", "1.1.0"));
                });
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILogger<Startup> logger)
    {
        // Log configuration at startup (with secrets masked)
        var openIdConfig = configuration.GetSection(OpenIdConfig.ConfigKey).Get<OpenIdConfig>()!;
        var steamConfig = configuration.GetSection(SteamConfig.ConfigKey).Get<SteamConfig>()!;

        logger.LogInformation(
            "Configuration loaded - ClientId: {ClientId}, RedirectURIs: {RedirectCount}, SteamKey: {HasValidSteamKey}",
            openIdConfig.ClientId,
            openIdConfig.RedirectUris.Count(),
            !string.IsNullOrEmpty(steamConfig.ApplicationKey) && steamConfig.ApplicationKey != "changeme");

        // Log redirect URIs for troubleshooting
        foreach (var uri in openIdConfig.RedirectUris)
        {
            logger.LogInformation("  Redirect URI: {RedirectUri}", uri);
        }

        // Log post-logout redirect URIs if configured
        if (openIdConfig.PostLogoutRedirectUris.Any())
        {
            foreach (var uri in openIdConfig.PostLogoutRedirectUris)
            {
                logger.LogInformation("  Post-logout redirect URI: {PostLogoutRedirectUri}", uri);
            }
        }

        var hostingConfig = configuration.GetSection(HostingConfig.Config).Get<HostingConfig>()!;
        var forwardOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
            RequireHeaderSymmetry = false
        };

        forwardOptions.KnownNetworks.Clear();
        forwardOptions.KnownProxies.Clear();

        app.UseForwardedHeaders(forwardOptions);

        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseMiddleware<GlobalExceptionHandlerMiddleware>();
        }

        app.UseCookiePolicy(new CookiePolicyOptions
        {
            Secure = CookieSecurePolicy.Always,
            MinimumSameSitePolicy = SameSiteMode.Unspecified,
            OnAppendCookie = cookieContext =>
                SetSameSiteCookieOption(cookieContext.Context, cookieContext.CookieOptions),
            OnDeleteCookie = cookieContext =>
                SetSameSiteCookieOption(cookieContext.Context, cookieContext.CookieOptions)
        });

        app.UseAuthentication();

        app.Use(async (ctx, next) =>
        {
            if (!string.IsNullOrWhiteSpace(hostingConfig.PublicOrigin))
            {
                ctx.SetIdentityServerOrigin(hostingConfig.PublicOrigin);
            }

            if (!string.IsNullOrWhiteSpace(hostingConfig.BasePath))
            {
                ctx.SetIdentityServerBasePath(hostingConfig.BasePath);
            }

            await next();
        });

        app.UseMiddleware<CorrelationIdMiddleware>();

        app.UseSerilogRequestLogging(options =>
        {
            options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
            {
                diagnosticContext.Set("CorrelationId", httpContext.Items["CorrelationId"] ?? "unknown");
                diagnosticContext.Set("ClientIP", httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            };
        });
        app.UseRouting();
        app.UseIdentityServer();
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
            endpoints.MapHealthChecks("/health");
        });
    }

    private static void SetSameSiteCookieOption(HttpContext httpContext, CookieOptions options)
    {
        if (options.SameSite != SameSiteMode.None)
        {
            return;
        }

        var userAgent = httpContext.Request.Headers.UserAgent.ToString();
        if (userAgent.Contains("CPU iPhone OS 12")
            || userAgent.Contains("iPad; CPU OS 12")
            || (userAgent.Contains("Macintosh; Intel Mac OS X 10_14")
                && userAgent.Contains("Version/")
                && userAgent.Contains("Safari"))
            || userAgent.Contains("Chrome/5")
            || userAgent.Contains("Chrome/6"))
        {
            options.SameSite = SameSiteMode.Unspecified;
        }
    }
}
