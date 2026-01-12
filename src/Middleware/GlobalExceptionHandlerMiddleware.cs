using System;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace SteamOpenIdConnectProvider.Middleware;

public class GlobalExceptionHandlerMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<GlobalExceptionHandlerMiddleware> _logger;

    public GlobalExceptionHandlerMiddleware(RequestDelegate next, ILogger<GlobalExceptionHandlerMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            var correlationId = context.Items["CorrelationId"]?.ToString() ?? "unknown";

            _logger.LogError(ex,
                "Unhandled exception. Path: {Path}, Method: {Method}, CorrelationId: {CorrelationId}, User: {User}",
                context.Request.Path,
                context.Request.Method,
                correlationId,
                context.User?.Identity?.Name ?? "anonymous");

            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            context.Response.ContentType = "application/json";

            var response = JsonSerializer.Serialize(new
            {
                error = "An error occurred processing your request",
                correlationId = correlationId
            });

            await context.Response.WriteAsync(response);
        }
    }
}
