using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using vulnerability_management.Data;
using vulnerability_management.Models;
using vulnerability_management.Services;

namespace vulnerability_management.Controllers;

public class VulnerabilitiesController : Controller
{
    private readonly AppDbContext _context;
    private readonly IRiskScoringService _riskService;

    public VulnerabilitiesController(AppDbContext context, IRiskScoringService riskService)
    {
        _context = context;
        _riskService = riskService;
    }

    [HttpGet]
    public async Task<IActionResult> Index(string? search, SeverityLevel? severity, FindingStatus? status, bool? cisaKevOnly)
    {
        var query = _context.VulnerabilityFindings
            .Include(f => f.Vulnerability)
            .Include(f => f.Asset)
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var s = search.ToLower().Trim();
            query = query.Where(f => 
                f.Vulnerability!.CveId.ToLower().Contains(s) || 
                f.Vulnerability.Title.ToLower().Contains(s) || 
                f.Asset!.Hostname.ToLower().Contains(s) || 
                f.Asset.IpAddress.ToLower().Contains(s) ||
                (f.AssignedTo != null && f.AssignedTo.ToLower().Contains(s)));
        }

        if (severity.HasValue)
        {
            query = query.Where(f => f.Vulnerability!.Severity == severity.Value);
        }

        if (status.HasValue)
        {
            query = query.Where(f => f.Status == status.Value);
        }

        if (cisaKevOnly.HasValue && cisaKevOnly.Value)
        {
            query = query.Where(f => f.Vulnerability!.IsInCisaKev);
        }

        var findings = await query
            .OrderByDescending(f => f.Vulnerability!.CvssScore)
            .ThenBy(f => f.DueDate)
            .ToListAsync();

        ViewBag.Search = search;
        ViewBag.Severity = severity;
        ViewBag.Status = status;
        ViewBag.CisaKevOnly = cisaKevOnly;

        return View(findings);
    }

    [HttpGet]
    public async Task<IActionResult> Details(int id)
    {
        var finding = await _context.VulnerabilityFindings
            .Include(f => f.Vulnerability)
            .Include(f => f.Asset)
            .Include(f => f.ActivityLogs)
            .FirstOrDefaultAsync(f => f.Id == id);

        if (finding == null) return NotFound();

        return View(finding);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateStatus(int id, FindingStatus newStatus, string? notes, string? assignee, string? riskReason)
    {
        var finding = await _context.VulnerabilityFindings
            .Include(f => f.Vulnerability)
            .FirstOrDefaultAsync(f => f.Id == id);

        if (finding == null) return NotFound();

        var oldStatus = finding.Status;
        finding.Status = newStatus;

        if (!string.IsNullOrWhiteSpace(notes))
        {
            finding.RemediationNotes = notes;
        }

        if (!string.IsNullOrWhiteSpace(assignee))
        {
            finding.AssignedTo = assignee;
        }

        if (newStatus == FindingStatus.AcceptedRisk && !string.IsNullOrWhiteSpace(riskReason))
        {
            finding.RiskAcceptanceReason = riskReason;
        }

        if (newStatus == FindingStatus.Remediated)
        {
            finding.ResolvedAt = DateTime.UtcNow;
        }

        // Add Activity Log
        var log = new ActivityLog
        {
            VulnerabilityFindingId = finding.Id,
            Action = $"Status changed to {newStatus}",
            Details = $"Status modified from {oldStatus} to {newStatus}. Notes: {notes ?? "N/A"}",
            User = "SecOps Engineer",
            Timestamp = DateTime.UtcNow
        };
        _context.ActivityLogs.Add(log);

        await _context.SaveChangesAsync();
        TempData["SuccessMessage"] = $"Finding #{id} status updated to {newStatus}.";

        return RedirectToAction(nameof(Details), new { id });
    }

    [HttpGet]
    public async Task<IActionResult> Catalog(string? search, SeverityLevel? severity, bool? cisaKevOnly)
    {
        var query = _context.Vulnerabilities
            .Include(v => v.Findings)
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var s = search.ToLower().Trim();
            query = query.Where(v => v.CveId.ToLower().Contains(s) || v.Title.ToLower().Contains(s) || v.Description.ToLower().Contains(s) || v.AffectedComponent.ToLower().Contains(s));
        }

        if (severity.HasValue)
        {
            query = query.Where(v => v.Severity == severity.Value);
        }

        if (cisaKevOnly.HasValue && cisaKevOnly.Value)
        {
            query = query.Where(v => v.IsInCisaKev);
        }

        var list = await query.OrderByDescending(v => v.CvssScore).ToListAsync();
        ViewBag.Search = search;
        ViewBag.Severity = severity;
        ViewBag.CisaKevOnly = cisaKevOnly;

        return View(list);
    }
}
