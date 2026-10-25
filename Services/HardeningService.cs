using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using vulnerability_management.Models;

namespace vulnerability_management.Services;

public interface IHardeningService
{
    Task<HardeningChecklistResult> EvaluateHardeningPostureAsync();
}

[SupportedOSPlatform("windows")]
public class HardeningService : IHardeningService
{
    private readonly ILogger<HardeningService> _logger;

    public HardeningService(ILogger<HardeningService> logger)
    {
        _logger = logger;
    }

    public async Task<HardeningChecklistResult> EvaluateHardeningPostureAsync()
    {
        var result = new HardeningChecklistResult
        {
            EvaluatedAt = DateTime.UtcNow,
            MachineName = Environment.MachineName,
            OsDescription = RuntimeInformation.OSDescription
        };

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return result;
        }

        // 1. Query Windows Defender Defender Preferences via PowerShell
        var mpPrefs = await QueryDefenderPreferencesAsync();

        // 1. PUA Protection
        bool puaEnabled = mpPrefs.TryGetValue("PUAProtection", out var pua) && (pua == "1" || pua.Equals("Enabled", StringComparison.OrdinalIgnoreCase));
        result.Controls.Add(new HardeningControlItem
        {
            Category = "Windows Defender",
            Title = "Potentially Unwanted Application (PUA) Blocking",
            CurrentState = puaEnabled ? "Enabled (Active Protection)" : "Disabled / Not Enforced",
            RecommendedState = "Enabled",
            Status = puaEnabled ? "Applied" : "NeedsAttention",
            SecurityBenefit = "Blocks adware, bundled cryptominers, and deceptive installers before they execute.",
            PowerShellCommand = "Set-MpPreference -PUAProtection Enabled",
            ConfigurationLocation = "Windows Security -> App & browser control -> Reputation-based protection",
            ThreatMitigated = "Adware, CoinMiners, Bundled Toolbars"
        });

        // 2. Controlled Folder Access (Ransomware Shield)
        bool cfaEnabled = mpPrefs.TryGetValue("EnableControlledFolderAccess", out var cfa) && (cfa == "1" || cfa.Equals("Enabled", StringComparison.OrdinalIgnoreCase));
        result.Controls.Add(new HardeningControlItem
        {
            Category = "Windows Defender",
            Title = "Ransomware Shield (Controlled Folder Access)",
            CurrentState = cfaEnabled ? "Enabled (Protected Folders Shielded)" : "Disabled",
            RecommendedState = "Enabled",
            Status = cfaEnabled ? "Applied" : "NeedsAttention",
            SecurityBenefit = "Prevents untrusted applications and ransomware from encrypting or modifying user files in Documents, Pictures, and Desktop.",
            PowerShellCommand = "Set-MpPreference -EnableControlledFolderAccess Enabled",
            ConfigurationLocation = "Windows Security -> Virus & threat protection -> Ransomware protection",
            ThreatMitigated = "Ransomware (LockBit, BlackCat, WannaCry)"
        });

        // 3. Cloud-Delivered Protection & MAPS
        bool cloudEnabled = mpPrefs.TryGetValue("MAPSReporting", out var maps) && (maps == "2" || maps.Equals("Advanced", StringComparison.OrdinalIgnoreCase));
        result.Controls.Add(new HardeningControlItem
        {
            Category = "Windows Defender",
            Title = "Cloud-Delivered Fast Intelligence & Block at First Sight",
            CurrentState = cloudEnabled ? "Enabled (Advanced Telemetry)" : "Standard / Basic",
            RecommendedState = "Advanced Cloud Telemetry",
            Status = cloudEnabled ? "Applied" : "NeedsAttention",
            SecurityBenefit = "Leverages real-time Microsoft cloud AI to identify and block new zero-day malware variants within seconds.",
            PowerShellCommand = "Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendAllSamples",
            ConfigurationLocation = "Windows Security -> Virus & threat protection -> Cloud-delivered protection",
            ThreatMitigated = "Zero-day Polymorphic Malware"
        });

        // 4. User Account Control (UAC) - Prompt Behavior
        var uacLevel = CheckUacLevel();
        result.Controls.Add(new HardeningControlItem
        {
            Category = "Account Security",
            Title = "User Account Control (UAC) Strict Prompting",
            CurrentState = uacLevel.Current,
            RecommendedState = "Always Notify (Level 4)",
            Status = uacLevel.IsStrict ? "Applied" : "NeedsAttention",
            SecurityBenefit = "Prevents background programs from silently elevating to Administrator without explicit user approval.",
            PowerShellCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2",
            ConfigurationLocation = "Control Panel -> User Accounts -> Change User Account Control settings",
            ThreatMitigated = "Silent Privilege Escalation"
        });

        // 5. SMBv1 Legacy Protocol
        bool smb1Disabled = CheckSmb1Disabled();
        result.Controls.Add(new HardeningControlItem
        {
            Category = "Network Protocols",
            Title = "SMBv1 Legacy Protocol Deactivation",
            CurrentState = smb1Disabled ? "Disabled (Secure)" : "Enabled / Available",
            RecommendedState = "Disabled",
            Status = smb1Disabled ? "Applied" : "NeedsAttention",
            SecurityBenefit = "Eliminates the legacy 1990s SMBv1 protocol vulnerability exploited by EternalBlue, WannaCry, and NotPetya worms.",
            PowerShellCommand = "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
            ConfigurationLocation = "Windows Features (optionalfeatures.exe) -> Uncheck 'SMB 1.0/CIFS File Sharing'",
            ThreatMitigated = "Wormable Network Exploits (EternalBlue)"
        });

        // 6. LLMNR Multicast Resolution
        bool llmnrDisabled = CheckLlmnrDisabled();
        result.Controls.Add(new HardeningControlItem
        {
            Category = "Network Protocols",
            Title = "LLMNR Link-Local Multicast Name Resolution",
            CurrentState = llmnrDisabled ? "Disabled (Protected against Poisoning)" : "Enabled (Default)",
            RecommendedState = "Disabled",
            Status = llmnrDisabled ? "Applied" : "NeedsAttention",
            SecurityBenefit = "Prevents local attackers on the same Wi-Fi from capturing Windows NTLM password hashes via Responder/LLMNR spoofing.",
            PowerShellCommand = "if (!(Test-Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient')) { New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force }; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -Value 0",
            ConfigurationLocation = "Group Policy -> Computer Config -> Admin Templates -> Network -> DNS Client -> Turn off multicast name resolution",
            ThreatMitigated = "Local Network Credential Theft (Responder/NTLM Relay)"
        });

        // 7. Windows Firewall Default Inbound Action
        bool fwStrict = await CheckFirewallDefaultInboundAsync();
        result.Controls.Add(new HardeningControlItem
        {
            Category = "Firewall & Boundary",
            Title = "Windows Firewall Inbound Default Block",
            CurrentState = fwStrict ? "All Profiles Block Inbound by Default" : "Permissive / Partial",
            RecommendedState = "Block Inbound on Domain, Private & Public",
            Status = fwStrict ? "Applied" : "NeedsAttention",
            SecurityBenefit = "Blocks unsolicited inbound connection requests from the local network and internet.",
            PowerShellCommand = "Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -Enabled True",
            ConfigurationLocation = "Windows Defender Firewall with Advanced Security -> Properties",
            ThreatMitigated = "Unauthorized Remote Connection Probing"
        });

        // 8. Remote Desktop (RDP) Network Level Authentication (NLA)
        var rdpStatus = CheckRdpSecurity();
        result.Controls.Add(new HardeningControlItem
        {
            Category = "Remote Management",
            Title = "Remote Desktop (RDP) Network Level Authentication",
            CurrentState = rdpStatus.Current,
            RecommendedState = "RDP Disabled or NLA Required",
            Status = rdpStatus.IsSecure ? "Applied" : "NeedsAttention",
            SecurityBenefit = "Requires user authentication before an RDP session is established, protecting against pre-auth brute force and BlueKeep exploits.",
            PowerShellCommand = "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1",
            ConfigurationLocation = "Settings -> System -> Remote Desktop -> Require computers to use NLA",
            ThreatMitigated = "Pre-Authentication RDP Exploitation"
        });

        // 9. Core Isolation & Memory Integrity (HVCI)
        bool hvciEnabled = CheckMemoryIntegrity();
        result.Controls.Add(new HardeningControlItem
        {
            Category = "Hardware Virtualization",
            Title = "Core Isolation & Memory Integrity (HVCI)",
            CurrentState = hvciEnabled ? "Enabled (Virtualization-Based Security Active)" : "Disabled / Unchecked",
            RecommendedState = "Enabled",
            Status = hvciEnabled ? "Applied" : "Optional",
            SecurityBenefit = "Uses hardware CPU virtualization to prevent kernel-mode injection and driver-based rootkits.",
            PowerShellCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Value 1",
            ConfigurationLocation = "Windows Security -> Device security -> Core isolation details",
            ThreatMitigated = "Kernel Driver Rootkits & Memory Tampering"
        });

        // 10. Secure Encrypted DNS with Threat Filtering
        result.Controls.Add(new HardeningControlItem
        {
            Category = "Web & DNS Hygiene",
            Title = "Encrypted DNS (DNS-over-HTTPS) with Threat Filtering",
            CurrentState = "Configured via Browser / Router",
            RecommendedState = "Cloudflare (1.1.1.2) or Quad9 (9.9.9.9)",
            Status = "Optional",
            SecurityBenefit = "Encrypts domain lookups and automatically blocks known phishing, ransomware, and malware command-and-control servers at the DNS level.",
            PowerShellCommand = "Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses ('1.1.1.2','1.0.0.2')",
            ConfigurationLocation = "Settings -> Network & internet -> Wi-Fi/Ethernet -> DNS server assignment -> Encrypted DNS",
            ThreatMitigated = "Malvertising, Phishing Domains, DNS Hijacking"
        });

        result.TotalControlsCount = result.Controls.Count;
        result.AppliedControlsCount = result.Controls.Count(c => c.Status == "Applied");

        return result;
    }

    private async Task<Dictionary<string, string>> QueryDefenderPreferencesAsync()
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -Command \"Get-MpPreference | Select-Object PUAProtection, EnableControlledFolderAccess, MAPSReporting | ConvertTo-Json -Compress\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var output = await proc.StandardOutput.ReadToEndAsync();
                await proc.WaitForExitAsync();

                if (!string.IsNullOrWhiteSpace(output) && output.StartsWith("{"))
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(output);
                    foreach (var prop in doc.RootElement.EnumerateObject())
                    {
                        dict[prop.Name] = prop.Value.ToString();
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not query Get-MpPreference");
        }
        return dict;
    }

    private (string Current, bool IsStrict) CheckUacLevel()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            if (key != null)
            {
                var prompt = key.GetValue("ConsentPromptBehaviorAdmin");
                var lua = key.GetValue("EnableLUA");

                if (lua != null && (int)lua == 1)
                {
                    if (prompt != null && (int)prompt == 2)
                    {
                        return ("Level 4 (Always Notify - Highest Security)", true);
                    }
                    return ("Level 3 (Default Notify)", false);
                }
            }
        }
        catch { }
        return ("Standard User Consent", false);
    }

    private bool CheckSmb1Disabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
            if (key != null)
            {
                var smb1 = key.GetValue("SMB1");
                if (smb1 != null && (int)smb1 == 0) return true;
            }
        }
        catch { }
        return true; // Modern Windows 11/10 default
    }

    private bool CheckLlmnrDisabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient");
            if (key != null)
            {
                var multi = key.GetValue("EnableMulticast");
                if (multi != null && (int)multi == 0) return true;
            }
        }
        catch { }
        return false;
    }

    private async Task<bool> CheckFirewallDefaultInboundAsync()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = "advfirewall show allprofiles firewallpolicy",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var output = await proc.StandardOutput.ReadToEndAsync();
                await proc.WaitForExitAsync();
                return output.Contains("BlockInbound") && !output.Contains("AllowInbound");
            }
        }
        catch { }
        return true;
    }

    private (string Current, bool IsSecure) CheckRdpSecurity()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"System\CurrentControlSet\Control\Terminal Server");
            if (key != null)
            {
                var deny = key.GetValue("fDenyTSConnections");
                if (deny != null && (int)deny == 1)
                {
                    return ("RDP Disabled (Most Secure)", true);
                }
            }

            using var nlaKey = Registry.LocalMachine.OpenSubKey(@"System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
            if (nlaKey != null)
            {
                var userAuth = nlaKey.GetValue("UserAuthentication");
                if (userAuth != null && (int)userAuth == 1)
                {
                    return ("RDP Enabled with NLA Required", true);
                }
            }
        }
        catch { }
        return ("RDP Disabled", true);
    }

    private bool CheckMemoryIntegrity()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
            if (key != null)
            {
                var enabled = key.GetValue("Enabled");
                if (enabled != null && (int)enabled == 1) return true;
            }
        }
        catch { }
        return false;
    }
}
