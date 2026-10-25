using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using vulnerability_management.Data;
using vulnerability_management.Models;

namespace vulnerability_management.Controllers;

public class RemediationController : Controller
{
    private readonly AppDbContext _context;

    public RemediationController(AppDbContext context)
    {
        _context = context;
    }

    [HttpGet]
    public async Task<IActionResult> Index(string? filter)
    {
        var query = _context.VulnerabilityFindings
            .Include(f => f.Vulnerability)
            .Include(f => f.Asset)
            .AsQueryable();

        if (filter == "overdue")
        {
            var now = DateTime.UtcNow;
            query = query.Where(f => (f.Status == FindingStatus.Open || f.Status == FindingStatus.InProgress) && f.DueDate < now);
        }
        else if (filter == "accepted")
        {
            query = query.Where(f => f.Status == FindingStatus.AcceptedRisk);
        }
        else if (filter == "inprogress")
        {
            query = query.Where(f => f.Status == FindingStatus.InProgress);
        }

        var findings = await query
            .OrderBy(f => f.DueDate)
            .ToListAsync();

        ViewBag.Filter = filter;
        ViewBag.Policies = await _context.SlaPolicies.ToListAsync();

        return View(findings);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateSlaPolicy(List<SlaPolicy> policies)
    {
        foreach (var p in policies)
        {
            var existing = await _context.SlaPolicies.FindAsync(p.Id);
            if (existing != null)
            {
                existing.MaxDaysToRemediate = p.MaxDaysToRemediate;
                existing.Description = p.Description;
            }
        }
        await _context.SaveChangesAsync();
        TempData["SuccessMessage"] = "SLA remediation policies updated.";
        return RedirectToAction(nameof(Index));
    }
}
