using System;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;
using SteamOpenIdConnectProvider;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting web host");

    var host = CreateHostBuilder(args).Build();

    // Seed OpenIddict applications
    using (var scope = host.Services.CreateScope())
    {
        var services = scope.ServiceProvider;
        var config = services.GetRequiredService<Microsoft.Extensions.Options.IOptions<SteamOpenIdConnectProvider.Domains.IdentityServer.OpenIdConfig>>().Value;
        await SteamOpenIdConnectProvider.Domains.IdentityServer.OpenIddictApplicationSeeder.SeedAsync(services, config);
    }

    await host.RunAsync();

    return 0;
}
catch (Exception ex)
{
    Log.Fatal(ex, "Host terminated unexpectedly");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .UseSerilog((context, services, configuration) => configuration
                .ReadFrom.Configuration(context.Configuration)
                .ReadFrom.Services(services)
                .MinimumLevel.Is(context.HostingEnvironment.IsDevelopment()
                    ? LogEventLevel.Debug
                    : LogEventLevel.Information)
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Debug)
                .MinimumLevel.Override("OpenIddict", LogEventLevel.Debug)
                .Enrich.FromLogContext()
                .WriteTo.Console(theme: AnsiConsoleTheme.Code))
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();
            });
