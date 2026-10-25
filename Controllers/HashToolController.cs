using Microsoft.AspNetCore.Mvc;
using vulnerability_management.Models;
using vulnerability_management.Services;

namespace vulnerability_management.Controllers;

public class HashToolController : Controller
{
    private readonly IHashToolService _hashToolService;

    public HashToolController(IHashToolService hashToolService)
    {
        _hashToolService = hashToolService;
    }

    [HttpGet]
    public IActionResult Index(string? tab, string? hash)
    {
        ViewBag.ActiveTab = tab ?? "lookup";

        if (!string.IsNullOrWhiteSpace(hash))
        {
            var lookupResult = _hashToolService.LookupHash(hash);
            ViewBag.LookupResult = lookupResult;
            ViewBag.HashInput = hash;
        }

        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Lookup(HashLookupRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.HashValue))
        {
            ModelState.AddModelError("HashValue", "Please provide a valid MD5, SHA-1, SHA-256, or SHA-512 hash.");
            ViewBag.ActiveTab = "lookup";
            return View("Index");
        }

        var result = _hashToolService.LookupHash(request.HashValue);
        ViewBag.LookupResult = result;
        ViewBag.HashInput = request.HashValue;
        ViewBag.ActiveTab = "lookup";

        return View("Index");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CalculateFile(IFormFile? fileUpload, string? localPath, string? expectedHash)
    {
        ViewBag.ActiveTab = "calculate";
        ViewBag.ExpectedHash = expectedHash;
        ViewBag.LocalPath = localPath;

        try
        {
            if (fileUpload != null && fileUpload.Length > 0)
            {
                using var stream = fileUpload.OpenReadStream();
                var result = await _hashToolService.CalculateHashesForStreamAsync(stream, fileUpload.FileName, expectedHash);
                ViewBag.FileResult = result;
            }
            else if (!string.IsNullOrWhiteSpace(localPath) && System.IO.File.Exists(localPath))
            {
                var result = await _hashToolService.CalculateHashesForFileAsync(localPath, expectedHash);
                ViewBag.FileResult = result;
            }
            else
            {
                ModelState.AddModelError("", "Please upload a file or specify a valid local file path.");
            }
        }
        catch (Exception ex)
        {
            ModelState.AddModelError("", $"Error calculating file hashes: {ex.Message}");
        }

        return View("Index");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult ParseBulk(string bulkText)
    {
        ViewBag.ActiveTab = "bulk";
        ViewBag.BulkText = bulkText;

        if (!string.IsNullOrWhiteSpace(bulkText))
        {
            var result = _hashToolService.ParseAndAnalyzeBulkText(bulkText);
            ViewBag.BulkResult = result;
        }
        else
        {
            ModelState.AddModelError("bulkText", "Please paste text containing hashes to parse.");
        }

        return View("Index");
    }
}
