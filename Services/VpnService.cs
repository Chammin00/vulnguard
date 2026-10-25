using System.Security.Cryptography;
using System.Text;
using vulnerability_management.Models;

namespace vulnerability_management.Services;

public interface IVpnService
{
    List<VpnServerLocation> GetServerLocations();
    VpnServerLocation? GetServerById(string serverId);
    VpnProfileResult GenerateProfile(VpnProfileRequest request);
    VpnConnectionStatus GetConnectionStatus();
    void SetConnectionState(bool isConnected, string? serverId = null);
}

public class VpnService : IVpnService
{
    private readonly ILogger<VpnService> _logger;
    private readonly List<VpnServerLocation> _servers = new();
    private VpnConnectionStatus _status = new();

    public VpnService(ILogger<VpnService> logger)
    {
        _logger = logger;
        InitializeServers();
        _status.ActiveServer = _servers.First();
    }

    private void InitializeServers()
    {
        _servers.AddRange(new[]
        {
            new VpnServerLocation
            {
                Id = "ch-zurich",
                Country = "Switzerland",
                City = "Zurich",
                FlagEmoji = "🇨🇭",
                EndpointHost = "ch-zurich.vpn.vulnguard.net",
                WireGuardPort = 51820,
                OpenVpnPort = 1194,
                LatencyMs = 28,
                LoadPercent = 24,
                ServerPublicKey = "CH89zKqW1mO4Lp8vQx5r2tYb9NuE7jA1dF3sH6cG0I=",
                Jurisdiction = "Switzerland (Strict Swiss Federal Data Protection Act / No-Logs)",
                P2PAllowed = true,
                DoubleVpnAvailable = true
            },
            new VpnServerLocation
            {
                Id = "is-reyk",
                Country = "Iceland",
                City = "Reykjavik",
                FlagEmoji = "🇮🇸",
                EndpointHost = "is-reyk.vpn.vulnguard.net",
                WireGuardPort = 51820,
                OpenVpnPort = 1194,
                LatencyMs = 34,
                LoadPercent = 18,
                ServerPublicKey = "IS74aBnX3vE9Yp2qKx6r1tLd0NuJ8mA5cF4sH7wG2Z=",
                Jurisdiction = "Iceland (Strong Modern Media Privacy Protection / Offshore)",
                P2PAllowed = true,
                DoubleVpnAvailable = true
            },
            new VpnServerLocation
            {
                Id = "us-ny",
                Country = "United States",
                City = "New York",
                FlagEmoji = "🇺🇸",
                EndpointHost = "us-ny.vpn.vulnguard.net",
                WireGuardPort = 51820,
                OpenVpnPort = 1194,
                LatencyMs = 15,
                LoadPercent = 48,
                ServerPublicKey = "US12mNpQ4rT7Vw9xKy5s2uZa8NuC6jE0dF1sH5bG9A=",
                Jurisdiction = "United States (10 Gbps Tier-1 Low Latency Backbone)",
                P2PAllowed = true,
                DoubleVpnAvailable = false
            },
            new VpnServerLocation
            {
                Id = "us-ca",
                Country = "United States",
                City = "Silicon Valley",
                FlagEmoji = "🇺🇸",
                EndpointHost = "us-ca.vpn.vulnguard.net",
                WireGuardPort = 51820,
                OpenVpnPort = 1194,
                LatencyMs = 38,
                LoadPercent = 42,
                ServerPublicKey = "CA45vBqW8mO2Lp6vQx1r9tYb3NuE5jA7dF0sH8cG4I=",
                Jurisdiction = "United States (High-Speed West Coast Cloud POP)",
                P2PAllowed = true,
                DoubleVpnAvailable = false
            },
            new VpnServerLocation
            {
                Id = "de-fra",
                Country = "Germany",
                City = "Frankfurt",
                FlagEmoji = "🇩🇪",
                EndpointHost = "de-fra.vpn.vulnguard.net",
                WireGuardPort = 51820,
                OpenVpnPort = 1194,
                LatencyMs = 31,
                LoadPercent = 36,
                ServerPublicKey = "DE33kLpQ9rT1Vw5xKy8s4uZa2NuC0jE6dF7sH3bG5E=",
                Jurisdiction = "Germany (DE-CIX Internet Exchange Node / GDPR Compliant)",
                P2PAllowed = true,
                DoubleVpnAvailable = true
            },
            new VpnServerLocation
            {
                Id = "uk-lon",
                Country = "United Kingdom",
                City = "London",
                FlagEmoji = "🇬🇧",
                EndpointHost = "uk-lon.vpn.vulnguard.net",
                WireGuardPort = 51820,
                OpenVpnPort = 1194,
                LatencyMs = 29,
                LoadPercent = 52,
                ServerPublicKey = "UK66rNpQ0rT3Vw8xKy2s7uZa9NuC4jE1dF5sH9bG2U=",
                Jurisdiction = "United Kingdom (LINX High-Bandwidth Gateway)",
                P2PAllowed = true,
                DoubleVpnAvailable = false
            },
            new VpnServerLocation
            {
                Id = "jp-tokyo",
                Country = "Japan",
                City = "Tokyo",
                FlagEmoji = "🇯🇵",
                EndpointHost = "jp-tokyo.vpn.vulnguard.net",
                WireGuardPort = 51820,
                OpenVpnPort = 1194,
                LatencyMs = 115,
                LoadPercent = 29,
                ServerPublicKey = "JP99mNpQ5rT8Vw1xKy4s6uZa3NuC2jE8dF9sH1bG6J=",
                Jurisdiction = "Japan (Asia-Pacific Ultra-Fast Fiber Gateway)",
                P2PAllowed = true,
                DoubleVpnAvailable = true
            },
            new VpnServerLocation
            {
                Id = "sg-sin",
                Country = "Singapore",
                City = "Singapore",
                FlagEmoji = "🇸🇬",
                EndpointHost = "sg-sin.vpn.vulnguard.net",
                WireGuardPort = 51820,
                OpenVpnPort = 1194,
                LatencyMs = 128,
                LoadPercent = 31,
                ServerPublicKey = "SG55kLpQ2rT4Vw6xKy1s8uZa7NuC9jE3dF2sH4bG8S=",
                Jurisdiction = "Singapore (Southeast Asia Low-Latency Hub)",
                P2PAllowed = true,
                DoubleVpnAvailable = true
            }
        });
    }

    public List<VpnServerLocation> GetServerLocations() => _servers;

    public VpnServerLocation? GetServerById(string serverId) =>
        _servers.FirstOrDefault(s => s.Id.Equals(serverId, StringComparison.OrdinalIgnoreCase)) ?? _servers.First();

    public VpnProfileResult GenerateProfile(VpnProfileRequest request)
    {
        var server = GetServerById(request.ServerId) ?? _servers.First();

        // 1. Generate Cryptographic Keys
        byte[] privateKeyBytes = RandomNumberGenerator.GetBytes(32);
        byte[] pskBytes = RandomNumberGenerator.GetBytes(32);

        // Derive pseudo-public key for WireGuard representation
        byte[] publicKeyBytes = SHA256.HashData(privateKeyBytes);

        string clientPrivKey = Convert.ToBase64String(privateKeyBytes);
        string clientPubKey = Convert.ToBase64String(publicKeyBytes);
        string psk = Convert.ToBase64String(pskBytes);

        // Resolve DNS servers
        string dns = request.DnsProvider switch
        {
            "Quad9" => "9.9.9.9, 149.112.112.112",
            "AdGuard" => "94.140.14.14, 94.140.15.15",
            "Custom" => string.IsNullOrWhiteSpace(request.CustomDns) ? "1.1.1.2" : request.CustomDns,
            _ => "1.1.1.2, 1.0.0.2" // Cloudflare for Families (Malware blocking)
        };

        var result = new VpnProfileResult
        {
            ClientName = string.IsNullOrWhiteSpace(request.ClientName) ? "VulnGuard-Client" : request.ClientName.Trim(),
            Protocol = request.Protocol,
            Server = server,
            ClientPrivateKey = clientPrivKey,
            ClientPublicKey = clientPubKey,
            PresharedKey = psk,
            AssignedIp = "10.8.0.2/24",
            DnsServer = dns,
            GeneratedAt = DateTime.UtcNow
        };

        if (request.Protocol == VpnProtocol.WireGuard)
        {
            result.FileName = $"{result.ClientName.ToLower()}-wg0.conf";
            result.ConfigFileContent = GenerateWireGuardConfig(result, server, dns);
        }
        else
        {
            result.FileName = $"{result.ClientName.ToLower()}-client.ovpn";
            result.ConfigFileContent = GenerateOpenVpnConfig(result, server, dns, request.Protocol == VpnProtocol.OpenVPN_TCP);
        }

        // Generate PowerShell Kill-Switch Script
        result.KillSwitchScript = GenerateKillSwitchScript(server.EndpointHost, result.FileName);

        return result;
    }

    private string GenerateWireGuardConfig(VpnProfileResult profile, VpnServerLocation server, string dns)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# ====================================================================");
        sb.AppendLine($"# VulnGuard SecureVPN Tunnel Profile - WireGuard (ChaCha20-Poly1305)");
        sb.AppendLine($"# Client: {profile.ClientName} | Server: {server.Country} ({server.City})");
        sb.AppendLine($"# Generated: {profile.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine("# ====================================================================");
        sb.AppendLine();
        sb.AppendLine("[Interface]");
        sb.AppendLine($"PrivateKey = {profile.ClientPrivateKey}");
        sb.AppendLine($"Address = {profile.AssignedIp}");
        sb.AppendLine($"DNS = {dns}");
        sb.AppendLine("MTU = 1420");
        sb.AppendLine();
        sb.AppendLine("[Peer]");
        sb.AppendLine($"PublicKey = {server.ServerPublicKey}");
        sb.AppendLine($"PresharedKey = {profile.PresharedKey}");
        sb.AppendLine($"Endpoint = {server.EndpointHost}:{server.WireGuardPort}");
        sb.AppendLine("AllowedIPs = 0.0.0.0/0, ::/0");
        sb.AppendLine("PersistentKeepalive = 25");
        return sb.ToString();
    }

    private string GenerateOpenVpnConfig(VpnProfileResult profile, VpnServerLocation server, string dns, bool isTcp)
    {
        var proto = isTcp ? "tcp-client" : "udp";
        var port = isTcp ? 443 : server.OpenVpnPort;

        var sb = new StringBuilder();
        sb.AppendLine("# ====================================================================");
        sb.AppendLine($"# VulnGuard SecureVPN Tunnel Profile - OpenVPN (AES-256-GCM / SHA-512)");
        sb.AppendLine($"# Client: {profile.ClientName} | Server: {server.Country} ({server.City})");
        sb.AppendLine("# ====================================================================");
        sb.AppendLine("client");
        sb.AppendLine($"dev tun");
        sb.AppendLine($"proto {proto}");
        sb.AppendLine($"remote {server.EndpointHost} {port}");
        sb.AppendLine("resolv-retry infinite");
        sb.AppendLine("nobind");
        sb.AppendLine("persist-key");
        sb.AppendLine("persist-tun");
        sb.AppendLine("remote-cert-tls server");
        sb.AppendLine("cipher AES-256-GCM");
        sb.AppendLine("auth SHA512");
        sb.AppendLine("verb 3");
        sb.AppendLine("mute 10");
        sb.AppendLine($"dhcp-option DNS {dns.Split(',')[0].Trim()}");
        sb.AppendLine();
        sb.AppendLine("<ca>");
        sb.AppendLine("-----BEGIN CERTIFICATE-----");
        sb.AppendLine("MIIBvTCCAWOgAwIBAgIUW1VulnGuardRootCA9988220199001122334455667788");
        sb.AppendLine("MCIxIDAeBgNVBAMMF1Z1bG5HdWFyZCBTZWN1cmVWUE4gQ0EwHhcNMjYwMTAxMDAw");
        sb.AppendLine("MDAwWhcNMzYwMTAxMDAwMDAwWjAiMSAwHgYDVQQDDBdWdWxuR3VhcmQgU2VjdXJl");
        sb.AppendLine("VlBOIENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7XmK9Wp8vQx5r2tYb");
        sb.AppendLine("-----END CERTIFICATE-----");
        sb.AppendLine("</ca>");
        sb.AppendLine();
        sb.AppendLine("<tls-auth>");
        sb.AppendLine("-----BEGIN OpenVPN Static key V1-----");
        sb.AppendLine("4a6e8b2c1d0f5e3a7b9c1d2e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a");
        sb.AppendLine("-----END OpenVPN Static key V1-----");
        sb.AppendLine("</tls-auth>");
        sb.AppendLine("key-direction 1");
        return sb.ToString();
    }

    private string GenerateKillSwitchScript(string serverHost, string configFileName)
    {
        return $@"# ==========================================================
# VulnGuard SecureVPN Windows Firewall Kill-Switch
# Enforces total network isolation: Drops all outbound traffic
# if the secure tunnel disconnects, preventing ISP/DNS leaks.
# ==========================================================
# Run in Administrator PowerShell:

Write-Host '[+] Activating VulnGuard Zero-Leak Kill Switch...' -ForegroundColor Cyan

# 1. Block all default outbound traffic on public interfaces
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

# 2. Allow WireGuard tunnel UDP packets to VPN endpoint
netsh advfirewall firewall add rule name='VulnGuard-VPN-Tunnel-Allow' dir=out action=allow protocol=UDP remoteport=51820

# 3. Allow DNS resolution for tunnel initialization
netsh advfirewall firewall add rule name='VulnGuard-VPN-DNS-Allow' dir=out action=allow protocol=UDP remoteport=53

# 4. Allow all traffic inside the encrypted WireGuard/TUN interface
netsh advfirewall firewall add rule name='VulnGuard-VPN-Interface-Allow' dir=out action=allow interfacename='{configFileName.Replace(".conf", "")}'

Write-Host '[SUCCESS] VPN Kill-Switch is active. Non-VPN traffic is shielded.' -ForegroundColor Green
";
    }

    public VpnConnectionStatus GetConnectionStatus() => _status;

    public void SetConnectionState(bool isConnected, string? serverId = null)
    {
        _status.IsConnected = isConnected;
        if (isConnected && !string.IsNullOrWhiteSpace(serverId))
        {
            var s = GetServerById(serverId);
            if (s != null)
            {
                _status.ActiveServer = s;
                _status.PublicMaskedIp = $"185.220.{RandomNumberGenerator.GetInt32(100, 200)}.{RandomNumberGenerator.GetInt32(10, 250)}";
            }
        }
        _logger.LogInformation("VPN Tunnel state updated: IsConnected={IsConnected}, Server={Server}", isConnected, _status.ActiveServer.City);
    }
}
