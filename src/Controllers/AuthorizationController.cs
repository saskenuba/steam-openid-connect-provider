using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using SteamOpenIdConnectProvider.Domains.IdentityServer;
using SteamOpenIdConnectProvider.Domains.Steam;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace SteamOpenIdConnectProvider.Controllers;

[ApiController]
public sealed class AuthorizationController : ControllerBase
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<AuthorizationController> _logger;
    private readonly SteamConfig _steamConfig;
    private readonly HttpClient _httpClient;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        ILogger<AuthorizationController> logger,
        IOptions<SteamConfig> steamConfig,
        IHttpClientFactory httpClientFactory)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
        _steamConfig = steamConfig.Value;
        _httpClient = httpClientFactory.CreateClient();
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Retrieve the user principal stored in the authentication cookie
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

        if (!result.Succeeded)
        {
            // User not authenticated - redirect to external login
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                        Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                });
        }

        var user = await _userManager.GetUserAsync(result.Principal)
            ?? throw new InvalidOperationException("The user details cannot be retrieved.");

        // Retrieve the application details
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        // Retrieve the permanent authorizations associated with the user and client
        var authorizations = new List<object>();
        await foreach (var auth in _authorizationManager.FindAsync(
            subject: await _userManager.GetUserIdAsync(user),
            client: (await _applicationManager.GetIdAsync(application))!,
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: request.GetScopes()))
        {
            authorizations.Add(auth);
        }

        // Create authorization if none exists
        var authorization = authorizations.LastOrDefault();
        if (authorization == null)
        {
            authorization = await _authorizationManager.CreateAsync(
                principal: result.Principal,
                subject: await _userManager.GetUserIdAsync(user),
                client: (await _applicationManager.GetIdAsync(application))!,
                type: AuthorizationTypes.Permanent,
                scopes: request.GetScopes());
        }

        // Create claims principal with Steam profile data
        var principal = await CreatePrincipalAsync(user, request.GetScopes());

        // Set authorization ID
        principal.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));

        // Set destinations for claims (ID token vs access token)
        SetClaimDestinations(principal, request.GetScopes());

        // Return sign-in response
        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpGet("~/connect/logout")]
    [HttpPost("~/connect/logout")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();

        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            });
    }

    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo")]
    [HttpPost("~/connect/userinfo")]
    public async Task<IActionResult> Userinfo()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = "/"
                });
        }

        // Fetch Steam profile and return as claims
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Subject] = user.Id
        };

        // Fetch Steam data
        var steamId = user.Id[SteamConstants.OpenIdUrl.Length..];
        try
        {
            var playerSummary = await GetPlayerSummariesAsync([steamId]);
            var player = playerSummary?.Players.FirstOrDefault();

            if (player != null)
            {
                if (User.HasScope(Scopes.Profile))
                {
                    claims[Claims.Name] = player.PersonaName ?? string.Empty;
                    claims[Claims.PreferredUsername] = player.PersonaName ?? string.Empty;
                    claims[OpenIdStandardClaims.Nickname] = player.PersonaName ?? string.Empty;
                    claims[Claims.Picture] = player.AvatarFull ?? string.Empty;
                    claims[Claims.Website] = player.ProfileUrl ?? string.Empty;
                    claims[OpenIdStandardClaims.GivenName] = player.RealName ?? string.Empty;
                    claims[SteamClaims.SteamId] = steamId;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve Steam profile for user {UserId}", user.Id);
        }

        return Ok(claims);
    }

    [HttpPost("~/connect/token")]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsAuthorizationCodeGrantType())
        {
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var user = await _userManager.FindByIdAsync(result.Principal!.GetClaim(Claims.Subject)!);
            if (user == null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                    }));
            }

            // Ensure user is still allowed to sign in
            if (!await _signInManager.CanSignInAsync(user))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
                    }));
            }

            // Recreate principal with fresh claims
            var principal = await CreatePrincipalAsync(user, request.GetScopes());

            // Copy authorization ID from original principal
            principal.SetAuthorizationId(result.Principal!.GetAuthorizationId());

            SetClaimDestinations(principal, request.GetScopes());

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    private async Task<ClaimsPrincipal> CreatePrincipalAsync(
        IdentityUser user,
        IEnumerable<string> scopes)
    {
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        // Add subject claim (required)
        identity.AddClaim(Claims.Subject, user.Id, Destinations.AccessToken, Destinations.IdentityToken);
        identity.AddClaim(Claims.Name, user.UserName ?? string.Empty, Destinations.AccessToken, Destinations.IdentityToken);

        // Fetch Steam profile data
        var steamId = user.Id[SteamConstants.OpenIdUrl.Length..];
        identity.AddClaim(SteamClaims.SteamId, steamId, Destinations.AccessToken, Destinations.IdentityToken);

        if (scopes.Contains(Scopes.Profile))
        {
            try
            {
                var playerSummary = await GetPlayerSummariesAsync([steamId]);
                var player = playerSummary?.Players.FirstOrDefault();

                if (player != null)
                {
                    _logger.LogDebug("Successfully retrieved Steam player summary for SteamID: {SteamId}", steamId);

                    AddClaimIfNotEmpty(identity, OpenIdStandardClaims.Nickname, player.PersonaName);
                    AddClaimIfNotEmpty(identity, Claims.PreferredUsername, player.PersonaName);
                    AddClaimIfNotEmpty(identity, OpenIdStandardClaims.GivenName, player.RealName);
                    AddClaimIfNotEmpty(identity, Claims.Picture, player.AvatarFull);
                    AddClaimIfNotEmpty(identity, Claims.Website, player.ProfileUrl);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve Steam profile for user {UserId}", user.Id);
            }
        }

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(scopes);

        return principal;
    }

    private void SetClaimDestinations(ClaimsPrincipal principal, IEnumerable<string> scopes)
    {
        var scopesList = scopes.ToList();

        foreach (var claim in principal.Claims)
        {
            var destinations = new List<string>();

            // Always include sub in both tokens
            if (claim.Type == Claims.Subject)
            {
                destinations.Add(Destinations.AccessToken);
                destinations.Add(Destinations.IdentityToken);
            }
            // Name claims in identity token
            else if (claim.Type == Claims.Name || claim.Type == Claims.PreferredUsername)
            {
                destinations.Add(Destinations.IdentityToken);
            }
            // Profile scope claims
            else if (scopesList.Contains(Scopes.Profile))
            {
                destinations.Add(Destinations.IdentityToken);

                // Also add to access token for userinfo endpoint
                if (claim.Type == OpenIdStandardClaims.Nickname ||
                    claim.Type == Claims.Picture ||
                    claim.Type == Claims.Website ||
                    claim.Type == OpenIdStandardClaims.GivenName ||
                    claim.Type == SteamClaims.SteamId)
                {
                    destinations.Add(Destinations.AccessToken);
                }
            }

            claim.SetDestinations(destinations);
        }
    }

    private async Task<GetPlayerSummariesResponse?> GetPlayerSummariesAsync(IEnumerable<string> steamIds)
    {
        const string EndPoint = $"{SteamConstants.ApiBaseUrl}ISteamUser/GetPlayerSummaries/v0002";

        var appKey = _steamConfig.ApplicationKey;
        var steamIdList = string.Join(',', steamIds);

        var url = $"{EndPoint}/?key={appKey}&steamids={steamIdList}";
        var res = await _httpClient.GetStringAsync(url);
        var response = JsonSerializer.Deserialize<SteamResponse<GetPlayerSummariesResponse>>(res);

        return response?.Response;
    }

    private static void AddClaimIfNotEmpty(ClaimsIdentity identity, string type, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            identity.AddClaim(new Claim(type, value));
        }
    }
}

// Extension helpers
internal static class ClaimsIdentityExtensions
{
    public static void AddClaim(
        this ClaimsIdentity identity,
        string type,
        string value,
        params string[] destinations)
    {
        var claim = new Claim(type, value);
        claim.SetDestinations(destinations);
        identity.AddClaim(claim);
    }
}
