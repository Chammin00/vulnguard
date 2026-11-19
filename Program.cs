using Microsoft.EntityFrameworkCore;
using vulnerability_management.Data;
using vulnerability_management.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Database context with SQLite
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? "Data Source=vulnguard.db";
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(connectionString));

// Register domain services
builder.Services.AddScoped<IRiskScoringService, RiskScoringService>();
builder.Services.AddSingleton<IScannerService, ScannerService>();
builder.Services.AddScoped<IThreatIntelService, ThreatIntelService>();
builder.Services.AddScoped<IReportService, ReportService>();
builder.Services.AddScoped<ILocalSmartScanService, LocalSmartScanService>();
builder.Services.AddScoped<IFileScannerService, FileScannerService>();
builder.Services.AddScoped<IFirewallService, FirewallService>();
builder.Services.AddScoped<IPcHealthCheckService, PcHealthCheckService>();
builder.Services.AddScoped<IHardeningService, HardeningService>();
builder.Services.AddScoped<IHashToolService, HashToolService>();
builder.Services.AddSingleton<IIdsIpsService, IdsIpsService>();
builder.Services.AddScoped<ICryptiiService, CryptiiService>();
builder.Services.AddSingleton<IVpnService, VpnService>();

var app = builder.Build();

// Auto-migrate and seed database
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<AppDbContext>();
        DbInitializer.Initialize(context);
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred creating/seeding the DB.");
    }
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Dashboard/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseMiddleware<vulnerability_management.Middleware.SecurityHardeningMiddleware>();
app.UseStaticFiles();

app.UseRouting();

// IDS/IPS Real-time packet and payload inspection
app.UseMiddleware<vulnerability_management.Middleware.IdsIpsMiddleware>();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Dashboard}/{action=Index}/{id?}");

app.Run();
