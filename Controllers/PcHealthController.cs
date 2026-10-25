using Microsoft.AspNetCore.Mvc;
using vulnerability_management.Services;

namespace vulnerability_management.Controllers;

public class PcHealthController : Controller
{
    private readonly IPcHealthCheckService _pcHealthCheckService;

    public PcHealthController(IPcHealthCheckService pcHealthCheckService)
    {
        _pcHealthCheckService = pcHealthCheckService;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var result = await _pcHealthCheckService.PerformFullHealthCheckAsync();
        return View(result);
    }
}
