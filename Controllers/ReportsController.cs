using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using vulnerability_management.Data;
using vulnerability_management.Services;

namespace vulnerability_management.Controllers;

public class ReportsController : Controller
{
    private readonly IReportService _reportService;
    private readonly IRiskScoringService _riskScoringService;
    private readonly AppDbContext _context;

    public ReportsController(IReportService reportService, IRiskScoringService riskScoringService, AppDbContext context)
    {
        _reportService = reportService;
        _riskScoringService = riskScoringService;
        _context = context;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var complianceModel = await _reportService.GenerateComplianceReportAsync();
        var dashboardModel = await _riskScoringService.GetDashboardMetricsAsync();
        ViewBag.Dashboard = dashboardModel;
        return View(complianceModel);
    }

    [HttpGet]
    public async Task<IActionResult> ExecutiveSummary()
    {
        var dashboardModel = await _riskScoringService.GetDashboardMetricsAsync();
        var complianceModel = await _reportService.GenerateComplianceReportAsync();
        ViewBag.Compliance = complianceModel;
        return View(dashboardModel);
    }

    [HttpGet]
    public async Task<IActionResult> ExportFindingsCsv()
    {
        var findings = await _context.VulnerabilityFindings
            .Include(f => f.Vulnerability)
            .Include(f => f.Asset)
            .ToListAsync();

        var sb = new StringBuilder();
        sb.AppendLine("FindingId,CVE,Title,Severity,CVSS,EPSS,CISA_KEV,AssetHostname,AssetIP,Port,Status,DiscoveredAt,DueDate,AssignedTo,IsSlaBreached");

        foreach (var f in findings)
        {
            sb.AppendLine($"\"{f.Id}\",\"{f.Vulnerability?.CveId}\",\"{f.Vulnerability?.Title.Replace("\"", "\"\"")}\",\"{f.Vulnerability?.Severity}\",\"{f.Vulnerability?.CvssScore}\",\"{f.Vulnerability?.EpssScore}\",\"{f.Vulnerability?.IsInCisaKev}\",\"{f.Asset?.Hostname}\",\"{f.Asset?.IpAddress}\",\"{f.AffectedPort}\",\"{f.Status}\",\"{f.DiscoveredAt:yyyy-MM-dd}\",\"{f.DueDate:yyyy-MM-dd}\",\"{f.AssignedTo}\",\"{f.IsSlaBreached}\"");
        }

        var bytes = Encoding.UTF8.GetBytes(sb.ToString());
        return File(bytes, "text/csv", $"vulnguard_findings_{DateTime.UtcNow:yyyyMMdd_HHmm}.csv");
    }

    [HttpGet]
    public async Task<IActionResult> ExportAssetsJson()
    {
        var assets = await _context.Assets
            .Include(a => a.Findings)
            .ThenInclude(f => f.Vulnerability)
            .Select(a => new
            {
                a.Id,
                a.Hostname,
                a.IpAddress,
                a.OperatingSystem,
                Environment = a.Environment.ToString(),
                Criticality = a.Criticality.ToString(),
                a.Owner,
                a.Tags,
                a.OpenPorts,
                a.LastScannedAt,
                ActiveFindingsCount = a.Findings.Count(f => f.Status != Models.FindingStatus.Remediated)
            })
            .ToListAsync();

        var json = JsonSerializer.Serialize(assets, new JsonSerializerOptions { WriteIndented = true });
        var bytes = Encoding.UTF8.GetBytes(json);
        return File(bytes, "application/json", $"vulnguard_assets_{DateTime.UtcNow:yyyyMMdd_HHmm}.json");
    }
}
