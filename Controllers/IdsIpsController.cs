using Microsoft.AspNetCore.Mvc;
using vulnerability_management.Models;
using vulnerability_management.Services;

namespace vulnerability_management.Controllers;

public class IdsIpsController : Controller
{
    private readonly IIdsIpsService _idsIpsService;

    public IdsIpsController(IIdsIpsService idsIpsService)
    {
        _idsIpsService = idsIpsService;
    }

    [HttpGet]
    public IActionResult Index(string? tab)
    {
        ViewBag.ActiveTab = tab ?? "dashboard";
        var summary = _idsIpsService.GetSummary();
        return View(summary);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult SetMode(IdsIpsMode mode)
    {
        _idsIpsService.SetMode(mode);
        TempData["SuccessMessage"] = $"IDS/IPS Engine mode updated to: {(mode == IdsIpsMode.IPS_ActivePrevention ? "IPS (Active Prevention & Blocking)" : "IDS (Detection & Alerting Only)")}";
        return RedirectToAction(nameof(Index), new { tab = "dashboard" });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult SimulateAttack(AttackSimulationRequest request)
    {
        var ev = _idsIpsService.SimulateAttack(request);
        TempData["SimulationResult"] = System.Text.Json.JsonSerializer.Serialize(ev);
        return RedirectToAction(nameof(Index), new { tab = "sandbox" });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult BanIp(string ip, string reason, int durationMinutes)
    {
        if (!string.IsNullOrWhiteSpace(ip))
        {
            _idsIpsService.BanIp(ip, reason ?? "Manual Administrator Blacklist", durationMinutes);
            TempData["SuccessMessage"] = $"IP Address {ip} successfully added to active IPS blacklist.";
        }
        return RedirectToAction(nameof(Index), new { tab = "bans" });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult UnbanIp(string ip)
    {
        if (!string.IsNullOrWhiteSpace(ip))
        {
            _idsIpsService.UnbanIp(ip);
            TempData["SuccessMessage"] = $"IP Address {ip} removed from IPS blacklist.";
        }
        return RedirectToAction(nameof(Index), new { tab = "bans" });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult ToggleRule(int sid, bool enabled)
    {
        _idsIpsService.ToggleRule(sid, enabled);
        TempData["SuccessMessage"] = $"Rule SID {sid} {(enabled ? "enabled" : "disabled")}.";
        return RedirectToAction(nameof(Index), new { tab = "rules" });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult ClearEvents()
    {
        _idsIpsService.ClearEvents();
        TempData["SuccessMessage"] = "IDS/IPS event history cleared.";
        return RedirectToAction(nameof(Index), new { tab = "alerts" });
    }
}
