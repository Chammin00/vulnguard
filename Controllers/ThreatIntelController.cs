using Microsoft.AspNetCore.Mvc;
using vulnerability_management.Models;
using vulnerability_management.Services;

namespace vulnerability_management.Controllers;

public class ThreatIntelController : Controller
{
    private readonly IThreatIntelService _threatIntelService;

    public ThreatIntelController(IThreatIntelService threatIntelService)
    {
        _threatIntelService = threatIntelService;
    }

    [HttpGet]
    public async Task<IActionResult> Index(string? search)
    {
        var kevs = await _threatIntelService.GetCisaKevCatalogAsync();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var s = search.ToLower().Trim();
            kevs = kevs.Where(k => k.CveId.ToLower().Contains(s) || k.Title.ToLower().Contains(s) || k.AffectedComponent.ToLower().Contains(s)).ToList();
        }
        ViewBag.Search = search;
        return View(kevs);
    }

    [HttpGet]
    public async Task<IActionResult> Lookup(string cveId)
    {
        if (string.IsNullOrWhiteSpace(cveId))
        {
            return RedirectToAction(nameof(Index));
        }

        var vuln = await _threatIntelService.LookupCveAsync(cveId);
        if (vuln == null)
        {
            ViewBag.Error = $"CVE identifier '{cveId}' was not found in active catalog.";
            return View("LookupResult", null);
        }

        return View("LookupResult", vuln);
    }
}
