using Microsoft.AspNetCore.Mvc;
using vulnerability_management.Services;

namespace vulnerability_management.Controllers;

public class FirewallController : Controller
{
    private readonly IFirewallService _firewallService;

    public FirewallController(IFirewallService firewallService)
    {
        _firewallService = firewallService;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var result = await _firewallService.GetFirewallStatusAsync();
        return View(result);
    }
}
