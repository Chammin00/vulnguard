namespace vulnerability_management.Models;

public enum VpnProtocol
{
    WireGuard,
    OpenVPN_UDP,
    OpenVPN_TCP,
    IKEv2
}

public class VpnServerLocation
{
    public string Id { get; set; } = string.Empty;
    public string Country { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public string FlagEmoji { get; set; } = "🌐";
    public string EndpointHost { get; set; } = string.Empty;
    public int WireGuardPort { get; set; } = 51820;
    public int OpenVpnPort { get; set; } = 1194;
    public int LatencyMs { get; set; } = 25;
    public int LoadPercent { get; set; } = 35;
    public string ServerPublicKey { get; set; } = string.Empty;
    public string Jurisdiction { get; set; } = "Switzerland (Strict No-Logs)";
    public bool P2PAllowed { get; set; } = true;
    public bool DoubleVpnAvailable { get; set; } = true;
}

public class VpnProfileRequest
{
    public string ServerId { get; set; } = "ch-zurich";
    public string ClientName { get; set; } = "VulnGuard-Client-PC";
    public VpnProtocol Protocol { get; set; } = VpnProtocol.WireGuard;
    public string DnsProvider { get; set; } = "CloudflareMalwareBlock"; // CloudflareMalwareBlock, Quad9, AdGuard, Custom
    public string CustomDns { get; set; } = "1.1.1.2";
    public bool EnableKillSwitch { get; set; } = true;
    public bool BlockIpv6Leak { get; set; } = true;
}

public class VpnProfileResult
{
    public string ProfileId { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string ClientName { get; set; } = string.Empty;
    public VpnProtocol Protocol { get; set; }
    public VpnServerLocation Server { get; set; } = new();

    public string ClientPrivateKey { get; set; } = string.Empty;
    public string ClientPublicKey { get; set; } = string.Empty;
    public string PresharedKey { get; set; } = string.Empty;
    public string AssignedIp { get; set; } = "10.8.0.2/32";
    public string DnsServer { get; set; } = "1.1.1.2, 1.0.0.2";

    public string ConfigFileContent { get; set; } = string.Empty;
    public string FileName { get; set; } = "vulnguard.conf";
    public string KillSwitchScript { get; set; } = string.Empty;
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
}

public class VpnConnectionStatus
{
    public bool IsConnected { get; set; } = true;
    public string VirtualIp { get; set; } = "10.8.0.2";
    public string PublicMaskedIp { get; set; } = "185.220.101.5";
    public string RealIspLocation { get; set; } = "Local Endpoint (Exposed without VPN)";
    public VpnServerLocation ActiveServer { get; set; } = new();
    public VpnProtocol ActiveProtocol { get; set; } = VpnProtocol.WireGuard;
    public string CipherSuite { get; set; } = "ChaCha20-Poly1305 (256-bit AEAD)";
    public double BytesSentMb { get; set; } = 48.2;
    public double BytesReceivedMb { get; set; } = 215.7;
    public TimeSpan Uptime { get; set; } = TimeSpan.FromMinutes(34);
    public bool KillSwitchActive { get; set; } = true;
    public bool DnsLeakProtected { get; set; } = true;
    public bool Ipv6LeakProtected { get; set; } = true;
}

public class VpnDashboardViewModel
{
    public VpnConnectionStatus Status { get; set; } = new();
    public List<VpnServerLocation> ServerLocations { get; set; } = new();
    public VpnProfileResult? GeneratedProfile { get; set; }
    public VpnProfileRequest CurrentRequest { get; set; } = new();
}
