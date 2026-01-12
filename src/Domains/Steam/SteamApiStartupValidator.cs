using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace SteamOpenIdConnectProvider.Domains.Steam;

/// <summary>
/// Hosted service that validates Steam API connectivity during application startup
/// </summary>
public sealed class SteamApiStartupValidator : IHostedService
{
    private readonly ISteamApiConnectivityValidator _validator;
    private readonly ILogger<SteamApiStartupValidator> _logger;

    public SteamApiStartupValidator(
        ISteamApiConnectivityValidator validator,
        ILogger<SteamApiStartupValidator> logger)
    {
        _validator = validator;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Running Steam API startup validation");

        try
        {
            await _validator.ValidateAsync();
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogCritical(ex,
                "Steam API connectivity validation failed. Application cannot start.");
            throw; // Fail-fast
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        // No cleanup needed
        return Task.CompletedTask;
    }
}
