using System.Text;
using Microsoft.AspNetCore.Mvc;
using vulnerability_management.Models;
using vulnerability_management.Services;

namespace vulnerability_management.Controllers;

public class VpnController : Controller
{
    private readonly IVpnService _vpnService;

    public VpnController(IVpnService vpnService)
    {
        _vpnService = vpnService;
    }

    [HttpGet]
    public IActionResult Index(string? serverId)
    {
        var vm = new VpnDashboardViewModel
        {
            Status = _vpnService.GetConnectionStatus(),
            ServerLocations = _vpnService.GetServerLocations(),
            CurrentRequest = new VpnProfileRequest
            {
                ServerId = serverId ?? "ch-zurich"
            }
        };

        // Pre-generate default Zurich WireGuard profile for instant preview
        vm.GeneratedProfile = _vpnService.GenerateProfile(vm.CurrentRequest);

        return View(vm);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Generate(VpnProfileRequest request)
    {
        var profile = _vpnService.GenerateProfile(request);
        var vm = new VpnDashboardViewModel
        {
            Status = _vpnService.GetConnectionStatus(),
            ServerLocations = _vpnService.GetServerLocations(),
            CurrentRequest = request,
            GeneratedProfile = profile
        };

        TempData["SuccessMessage"] = $"Generated {request.Protocol} SecureVPN profile for [{profile.Server.Country} - {profile.Server.City}]";
        return View("Index", vm);
    }

    [HttpGet]
    public IActionResult DownloadConfig(string serverId, string clientName, VpnProtocol protocol)
    {
        var profile = _vpnService.GenerateProfile(new VpnProfileRequest
        {
            ServerId = serverId,
            ClientName = clientName,
            Protocol = protocol
        });

        var bytes = Encoding.UTF8.GetBytes(profile.ConfigFileContent);
        var contentType = protocol == VpnProtocol.WireGuard ? "application/x-wireguard-profile" : "application/x-openvpn-profile";

        return File(bytes, contentType, profile.FileName);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult ToggleConnection(bool connect, string? serverId)
    {
        _vpnService.SetConnectionState(connect, serverId);
        TempData["SuccessMessage"] = connect ? "SecureVPN Tunnel Connected. Encrypted traffic routing is ACTIVE." : "SecureVPN Tunnel Disconnected.";
        return RedirectToAction(nameof(Index));
    }
}
