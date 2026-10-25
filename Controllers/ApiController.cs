using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using vulnerability_management.Data;
using vulnerability_management.Models;
using vulnerability_management.Services;

namespace vulnerability_management.Controllers;

[ApiController]
[Route("api")]
public class ApiController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly IRiskScoringService _riskScoringService;
    private readonly IScannerService _scannerService;
    private readonly IThreatIntelService _threatIntelService;
    private readonly ILocalSmartScanService _localSmartScanService;
    private readonly IFileScannerService _fileScannerService;
    private readonly IFirewallService _firewallService;
    private readonly IPcHealthCheckService _pcHealthCheckService;

    public ApiController(
        AppDbContext context,
        IRiskScoringService riskScoringService,
        IScannerService scannerService,
        IThreatIntelService threatIntelService,
        ILocalSmartScanService localSmartScanService,
        IFileScannerService fileScannerService,
        IFirewallService firewallService,
        IPcHealthCheckService pcHealthCheckService)
    {
        _context = context;
        _riskScoringService = riskScoringService;
        _scannerService = scannerService;
        _threatIntelService = threatIntelService;
        _localSmartScanService = localSmartScanService;
        _fileScannerService = fileScannerService;
        _firewallService = firewallService;
        _pcHealthCheckService = pcHealthCheckService;
    }

    [HttpGet("metrics")]
    public async Task<IActionResult> GetMetrics()
    {
        var metrics = await _riskScoringService.GetDashboardMetricsAsync();
        return Ok(metrics);
    }

    [HttpGet("assets")]
    public async Task<IActionResult> GetAssets()
    {
        var assets = await _context.Assets
            .Include(a => a.Findings)
            .ThenInclude(f => f.Vulnerability)
            .ToListAsync();
        return Ok(assets);
    }

    [HttpGet("findings")]
    public async Task<IActionResult> GetFindings()
    {
        var findings = await _context.VulnerabilityFindings
            .Include(f => f.Vulnerability)
            .Include(f => f.Asset)
            .ToListAsync();
        return Ok(findings);
    }

    [HttpPost("scans/launch")]
    public async Task<IActionResult> LaunchScan([FromBody] ScanRequestViewModel request)
    {
        if (string.IsNullOrWhiteSpace(request.Target))
        {
            return BadRequest(new { error = "Target is required." });
        }

        var scan = await _scannerService.StartScanAsync(request);
        return Ok(scan);
    }

    [HttpGet("scans/{id}/status")]
    public async Task<IActionResult> GetScanStatus(int id)
    {
        var scan = await _scannerService.GetScanJobAsync(id);
        if (scan == null) return NotFound();
        return Ok(scan);
    }

    [HttpGet("scans/smart-scan")]
    public async Task<IActionResult> RunSmartScan()
    {
        var result = await _localSmartScanService.PerformSmartScanAsync();
        return Ok(result);
    }

    [HttpPost("scans/file-scan")]
    public async Task<IActionResult> RunFileScan([FromBody] FileScanRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.TargetPath))
        {
            return BadRequest(new { error = "TargetPath is required." });
        }

        var result = await _fileScannerService.ScanPathAsync(request);
        return Ok(result);
    }

    [HttpGet("firewall")]
    public async Task<IActionResult> GetFirewallStatus()
    {
        var result = await _firewallService.GetFirewallStatusAsync();
        return Ok(result);
    }

    [HttpGet("pc-health")]
    public async Task<IActionResult> GetPcHealth()
    {
        var result = await _pcHealthCheckService.PerformFullHealthCheckAsync();
        return Ok(result);
    }

    [HttpGet("hardening")]
    public async Task<IActionResult> GetHardeningStatus([FromServices] IHardeningService hardeningService)
    {
        var result = await hardeningService.EvaluateHardeningPostureAsync();
        return Ok(result);
    }

    [HttpGet("threat-intel/kev")]
    public async Task<IActionResult> GetCisaKev()
    {
        var kevs = await _threatIntelService.GetCisaKevCatalogAsync();
        return Ok(kevs);
    }

    [HttpPost("hash/lookup")]
    public IActionResult LookupHash([FromBody] HashLookupRequest request, [FromServices] IHashToolService hashToolService)
    {
        if (string.IsNullOrWhiteSpace(request.HashValue))
        {
            return BadRequest(new { error = "HashValue is required." });
        }
        var result = hashToolService.LookupHash(request.HashValue);
        return Ok(result);
    }

    [HttpPost("hash/bulk-parse")]
    public IActionResult ParseBulkHashes([FromBody] string text, [FromServices] IHashToolService hashToolService)
    {
        var result = hashToolService.ParseAndAnalyzeBulkText(text);
        return Ok(result);
    }

    [HttpGet("ids-ips/summary")]
    public IActionResult GetIdsIpsSummary([FromServices] IIdsIpsService idsIpsService)
    {
        var summary = idsIpsService.GetSummary();
        return Ok(summary);
    }

    [HttpPost("ids-ips/simulate")]
    public IActionResult SimulateAttack([FromBody] AttackSimulationRequest request, [FromServices] IIdsIpsService idsIpsService)
    {
        var ev = idsIpsService.SimulateAttack(request);
        return Ok(ev);
    }

    [HttpPost("cryptii/transform")]
    public IActionResult TransformCryptii([FromBody] CryptiiTransformRequest request, [FromServices] ICryptiiService cryptiiService)
    {
        var result = cryptiiService.Transform(request);
        return Ok(result);
    }

    [HttpPost("cryptii/rsa-keys")]
    public IActionResult GenerateRsaKeys([FromQuery] int keySize, [FromServices] ICryptiiService cryptiiService)
    {
        var keys = cryptiiService.GenerateRsaKeyPair(keySize > 0 ? keySize : 2048);
        return Ok(keys);
    }

    [HttpGet("vpn/servers")]
    public IActionResult GetVpnServers([FromServices] IVpnService vpnService)
    {
        var servers = vpnService.GetServerLocations();
        return Ok(servers);
    }

    [HttpGet("vpn/status")]
    public IActionResult GetVpnStatus([FromServices] IVpnService vpnService)
    {
        var status = vpnService.GetConnectionStatus();
        return Ok(status);
    }

    [HttpPost("vpn/generate-profile")]
    public IActionResult GenerateVpnProfile([FromBody] VpnProfileRequest request, [FromServices] IVpnService vpnService)
    {
        var profile = vpnService.GenerateProfile(request);
        return Ok(profile);
    }
}
