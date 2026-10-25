using Microsoft.AspNetCore.Mvc;
using vulnerability_management.Models;
using vulnerability_management.Services;

namespace vulnerability_management.Controllers;

public class CryptiiController : Controller
{
    private readonly ICryptiiService _cryptiiService;

    public CryptiiController(ICryptiiService cryptiiService)
    {
        _cryptiiService = cryptiiService;
    }

    [HttpGet]
    public IActionResult Index(string? method, string? input)
    {
        var model = new CryptiiTransformRequest
        {
            Method = method ?? "base64_encode",
            InputText = input ?? "Hello, VulnGuard Security Workbench!"
        };

        var result = _cryptiiService.Transform(model);
        ViewBag.Result = result;

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Transform(CryptiiTransformRequest request)
    {
        var result = _cryptiiService.Transform(request);
        ViewBag.Result = result;
        return View("Index", request);
    }

    [HttpPost]
    public IActionResult GenerateRsa([FromQuery] int keySize = 2048)
    {
        var keys = _cryptiiService.GenerateRsaKeyPair(keySize);
        return Json(keys);
    }
}
