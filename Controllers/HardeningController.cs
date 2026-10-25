using Microsoft.AspNetCore.Mvc;
using vulnerability_management.Services;

namespace vulnerability_management.Controllers;

public class HardeningController : Controller
{
    private readonly IHardeningService _hardeningService;

    public HardeningController(IHardeningService hardeningService)
    {
        _hardeningService = hardeningService;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var result = await _hardeningService.EvaluateHardeningPostureAsync();
        return View(result);
    }
}
