using Microsoft.AspNetCore.Mvc;
using vulnerability_management.Models;
using vulnerability_management.Services;

namespace vulnerability_management.Controllers;

public class ScannerController : Controller
{
    private readonly IScannerService _scannerService;
    private readonly ILocalSmartScanService _localSmartScanService;
    private readonly IFileScannerService _fileScannerService;

    public ScannerController(
        IScannerService scannerService,
        ILocalSmartScanService localSmartScanService,
        IFileScannerService fileScannerService)
    {
        _scannerService = scannerService;
        _localSmartScanService = localSmartScanService;
        _fileScannerService = fileScannerService;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var scans = await _scannerService.GetAllScansAsync();
        return View(scans);
    }

    [HttpGet]
    public IActionResult New()
    {
        return View(new ScanRequestViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> StartScan(ScanRequestViewModel request)
    {
        if (string.IsNullOrWhiteSpace(request.Target))
        {
            ModelState.AddModelError("Target", "Target IP or hostname is required.");
            return View("New", request);
        }

        var scan = await _scannerService.StartScanAsync(request);
        return RedirectToAction(nameof(Live), new { id = scan.Id });
    }

    [HttpGet]
    public async Task<IActionResult> Live(int id)
    {
        var scan = await _scannerService.GetScanJobAsync(id);
        if (scan == null) return NotFound();
        return View(scan);
    }

    [HttpGet]
    public async Task<IActionResult> Status(int id)
    {
        var scan = await _scannerService.GetScanJobAsync(id);
        if (scan == null) return NotFound();
        return Json(new
        {
            id = scan.Id,
            status = scan.Status.ToString(),
            progressPercent = scan.ProgressPercent,
            assetsScanned = scan.AssetsScanned,
            vulnerabilitiesFound = scan.VulnerabilitiesFound,
            logOutput = scan.LogOutput,
            isFinished = scan.Status == ScanStatus.Completed || scan.Status == ScanStatus.Failed
        });
    }

    [HttpGet]
    public async Task<IActionResult> SmartScan()
    {
        var result = await _localSmartScanService.PerformSmartScanAsync();
        return View("LocalSmartScan", result);
    }

    [HttpGet]
    public IActionResult FileScan(string? preset)
    {
        var request = new FileScanRequest();
        if (!string.IsNullOrWhiteSpace(preset))
        {
            request.TargetPath = _fileScannerService.GetPresetFolderPath(preset);
        }
        else
        {
            request.TargetPath = _fileScannerService.GetPresetFolderPath("Downloads");
        }

        ViewBag.Preset = preset ?? "Downloads";
        return View(request);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RunFileScan(FileScanRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.TargetPath))
        {
            ModelState.AddModelError("TargetPath", "Please specify a valid folder or file path to scan.");
            return View("FileScan", request);
        }

        var result = await _fileScannerService.ScanPathAsync(request);
        ViewBag.ScanResult = result;
        return View("FileScan", request);
    }
}
