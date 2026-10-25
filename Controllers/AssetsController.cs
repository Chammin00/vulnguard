using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using vulnerability_management.Data;
using vulnerability_management.Models;
using vulnerability_management.Services;

namespace vulnerability_management.Controllers;

public class AssetsController : Controller
{
    private readonly AppDbContext _context;
    private readonly IRiskScoringService _riskScoringService;

    public AssetsController(AppDbContext context, IRiskScoringService riskScoringService)
    {
        _context = context;
        _riskScoringService = riskScoringService;
    }

    [HttpGet]
    public async Task<IActionResult> Index(string? search, EnvironmentType? env, CriticalityTier? tier)
    {
        var query = _context.Assets
            .Include(a => a.Findings)
            .ThenInclude(f => f.Vulnerability)
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var s = search.ToLower().Trim();
            query = query.Where(a => a.Hostname.ToLower().Contains(s) || a.IpAddress.ToLower().Contains(s) || a.OperatingSystem.ToLower().Contains(s) || a.Tags.ToLower().Contains(s) || a.Owner.ToLower().Contains(s));
        }

        if (env.HasValue)
        {
            query = query.Where(a => a.Environment == env.Value);
        }

        if (tier.HasValue)
        {
            query = query.Where(a => a.Criticality == tier.Value);
        }

        var assets = await query.OrderBy(a => a.Criticality).ThenBy(a => a.Hostname).ToListAsync();
        ViewBag.Search = search;
        ViewBag.Env = env;
        ViewBag.Tier = tier;
        ViewBag.RiskScoringService = _riskScoringService;

        return View(assets);
    }

    [HttpGet]
    public async Task<IActionResult> Details(int id)
    {
        var asset = await _context.Assets
            .Include(a => a.Findings)
            .ThenInclude(f => f.Vulnerability)
            .Include(a => a.Findings)
            .ThenInclude(f => f.ActivityLogs)
            .FirstOrDefaultAsync(a => a.Id == id);

        if (asset == null) return NotFound();

        ViewBag.RiskScore = _riskScoringService.CalculateAssetRiskScore(asset);
        return View(asset);
    }

    [HttpGet]
    public IActionResult Create()
    {
        return View(new Asset());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(Asset asset)
    {
        if (ModelState.IsValid)
        {
            asset.CreatedAt = DateTime.UtcNow;
            _context.Assets.Add(asset);
            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = $"Asset '{asset.Hostname}' was added successfully.";
            return RedirectToAction(nameof(Index));
        }
        return View(asset);
    }

    [HttpGet]
    public async Task<IActionResult> Edit(int id)
    {
        var asset = await _context.Assets.FindAsync(id);
        if (asset == null) return NotFound();
        return View(asset);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(int id, Asset asset)
    {
        if (id != asset.Id) return NotFound();

        if (ModelState.IsValid)
        {
            _context.Update(asset);
            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = $"Asset '{asset.Hostname}' updated successfully.";
            return RedirectToAction(nameof(Details), new { id = asset.Id });
        }
        return View(asset);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(int id)
    {
        var asset = await _context.Assets.FindAsync(id);
        if (asset != null)
        {
            _context.Assets.Remove(asset);
            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = $"Asset '{asset.Hostname}' deleted.";
        }
        return RedirectToAction(nameof(Index));
    }
}
