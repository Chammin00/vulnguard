using System.Text;
using vulnerability_management.Services;

namespace vulnerability_management.Middleware;

public class IdsIpsMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<IdsIpsMiddleware> _logger;

    public IdsIpsMiddleware(RequestDelegate next, ILogger<IdsIpsMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, IIdsIpsService idsIpsService)
    {
        var path = context.Request.Path.Value ?? "";

        // Skip static assets and dedicated sandbox simulation endpoints
        if (path.StartsWith("/css") || path.StartsWith("/js") || path.StartsWith("/lib") || path.StartsWith("/favicon.ico") ||
            path.StartsWith("/api/ids-ips/simulate") || path.StartsWith("/IdsIps/SimulateAttack"))
        {
            await _next(context);
            return;
        }

        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        var method = context.Request.Method;
        var queryString = context.Request.QueryString.Value ?? "";
        var userAgent = context.Request.Headers["User-Agent"].ToString();

        // Read request body if present (using memory stream buffering for inspection)
        string body = "";
        if (context.Request.ContentLength > 0 && context.Request.ContentLength < 1024 * 512 &&
            (context.Request.ContentType?.Contains("application/json") == true || context.Request.ContentType?.Contains("application/x-www-form-urlencoded") == true))
        {
            context.Request.EnableBuffering();
            using (var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true))
            {
                body = await reader.ReadToEndAsync();
                context.Request.Body.Position = 0;
            }
        }

        var (isAllowed, triggeredEvent) = idsIpsService.InspectRequest(ip, method, path, queryString, body, userAgent);

        if (!isAllowed && triggeredEvent != null)
        {
            _logger.LogWarning("IPS BLOCKED request from {IP} on {Path}. Rule: {Rule} (SID: {SID})", ip, path, triggeredEvent.RuleName, triggeredEvent.MatchedSid);

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            context.Response.Headers["X-Protected-By"] = "VulnGuard-IPS-Engine";
            context.Response.Headers["X-Blocked-By-SID"] = triggeredEvent.MatchedSid.ToString();

            var responseJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                error = "Access Blocked by VulnGuard IPS (Intrusion Prevention System)",
                status = 403,
                eventId = triggeredEvent.Id,
                blockedAt = triggeredEvent.Timestamp.ToString("o"),
                sourceIp = ip,
                matchedRule = triggeredEvent.RuleName,
                ruleSid = triggeredEvent.MatchedSid,
                mitreAttack = triggeredEvent.MitreAttackId,
                action = triggeredEvent.ActionTaken.ToString(),
                reason = "Your request triggered an active intrusion prevention signature. This security event has been logged and correlated with defense telemetry."
            });

            await context.Response.WriteAsync(responseJson);
            return;
        }

        await _next(context);
    }
}
