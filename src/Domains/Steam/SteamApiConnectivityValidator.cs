using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SteamOpenIdConnectProvider.Domains.Steam;

public sealed class SteamApiConnectivityValidator : ISteamApiConnectivityValidator
{
    private readonly HttpClient _httpClient;
    private readonly SteamConfig _config;
    private readonly ILogger<SteamApiConnectivityValidator> _logger;

    public SteamApiConnectivityValidator(
        HttpClient httpClient,
        IOptions<SteamConfig> config,
        ILogger<SteamApiConnectivityValidator> logger)
    {
        _httpClient = httpClient;
        _config = config.Value;
        _logger = logger;
    }

    public async Task ValidateAsync()
    {
        if (_config.SkipConnectivityCheck)
        {
            _logger.LogWarning(
                "Steam API connectivity check skipped due to configuration (SkipConnectivityCheck=true)");
            return;
        }

        _logger.LogInformation(
            "Validating Steam API connectivity (timeout: {Timeout}s)",
            _config.ConnectivityCheckTimeoutSeconds);

        try
        {
            using var cts = new CancellationTokenSource(
                TimeSpan.FromSeconds(_config.ConnectivityCheckTimeoutSeconds));

            // Use a known valid SteamID (GabeN's SteamID) for testing
            const string testSteamId = "76561197960287930";
            const string endpoint = $"{SteamConstants.ApiBaseUrl}ISteamUser/GetPlayerSummaries/v0002";
            var url = $"{endpoint}/?key={_config.ApplicationKey}&steamids={testSteamId}";

            var response = await _httpClient.GetAsync(url, cts.Token);

            if (!response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync(cts.Token);

                if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
                    response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    throw new InvalidOperationException(
                        $"Steam API key validation failed: Invalid or unauthorized API key. " +
                        $"Status: {response.StatusCode}. " +
                        $"Ensure your API key is valid and registered at https://steamcommunity.com/dev/apikey");
                }

                throw new InvalidOperationException(
                    $"Steam API connectivity check failed: HTTP {response.StatusCode}. " +
                    $"Response: {content}");
            }

            var responseText = await response.Content.ReadAsStringAsync(cts.Token);

            // Validate response structure
            try
            {
                var steamResponse = JsonSerializer.Deserialize<SteamResponse<GetPlayerSummariesResponse>>(responseText);
                if (steamResponse?.Response?.Players == null)
                {
                    throw new InvalidOperationException(
                        "Steam API returned invalid response structure. Response may have changed.");
                }
            }
            catch (JsonException ex)
            {
                throw new InvalidOperationException(
                    $"Steam API returned invalid JSON. Response: {responseText}", ex);
            }

            _logger.LogInformation(
                "Steam API connectivity validated successfully at {Endpoint}", endpoint);
        }
        catch (OperationCanceledException)
        {
            throw new InvalidOperationException(
                $"Steam API connectivity check timed out after {_config.ConnectivityCheckTimeoutSeconds} seconds. " +
                $"Check network connectivity or increase Steam:ConnectivityCheckTimeoutSeconds");
        }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException(
                $"Steam API connectivity check failed: {ex.Message}. " +
                $"Ensure network connectivity to {SteamConstants.ApiBaseUrl}", ex);
        }
    }
}
