using Microsoft.AspNetCore.Mvc;
using vulnerability_management.Services;

namespace vulnerability_management.Controllers;

public class DashboardController : Controller
{
    private readonly IRiskScoringService _riskScoringService;

    public DashboardController(IRiskScoringService riskScoringService)
    {
        _riskScoringService = riskScoringService;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var model = await _riskScoringService.GetDashboardMetricsAsync();
        return View(model);
    }
}
