namespace vulnerability_management.Middleware;

/// <summary>
/// Enforces HTTP security response headers and same-origin validation on mutating requests.
/// </summary>
public class SecurityHardeningMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SecurityHardeningMiddleware> _logger;

    private static readonly HashSet<string> MutatingMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        HttpMethods.Post,
        HttpMethods.Put,
        HttpMethods.Patch,
        HttpMethods.Delete
    };

    private const string ContentSecurityPolicy =
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com data:; " +
        "img-src 'self' data: https:; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self'";

    public SecurityHardeningMiddleware(RequestDelegate next, ILogger<SecurityHardeningMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        ApplySecurityHeaders(context.Response);

        if (MutatingMethods.Contains(context.Request.Method) && !IsSameOriginRequest(context.Request))
        {
            _logger.LogWarning(
                "Blocked cross-origin {Method} request to {Path} from Origin={Origin}",
                context.Request.Method,
                context.Request.Path,
                context.Request.Headers.Origin.ToString());

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsJsonAsync(new
            {
                error = "Cross-origin state-changing request blocked."
            });
            return;
        }

        await _next(context);
    }

    private static void ApplySecurityHeaders(HttpResponse response)
    {
        var headers = response.Headers;
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        headers["X-Permitted-Cross-Domain-Policies"] = "none";
        headers["Content-Security-Policy"] = ContentSecurityPolicy;
    }

    private static bool IsSameOriginRequest(HttpRequest request)
    {
        var requestHost = request.Host;
        var origin = request.Headers.Origin.ToString();

        if (!string.IsNullOrEmpty(origin))
        {
            return IsMatchingHost(origin, requestHost);
        }

        var referer = request.Headers.Referer.ToString();
        if (!string.IsNullOrEmpty(referer))
        {
            return IsMatchingHost(referer, requestHost);
        }

        return true;
    }

    private static bool IsMatchingHost(string uriString, HostString expectedHost)
    {
        if (!Uri.TryCreate(uriString, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (!string.Equals(uri.Host, expectedHost.Host, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (expectedHost.Port.HasValue && uri.Port != expectedHost.Port.Value)
        {
            return false;
        }

        return true;
    }
}
