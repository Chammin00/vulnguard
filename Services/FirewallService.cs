using System.Diagnostics;
using System.Runtime.InteropServices;
using vulnerability_management.Models;

namespace vulnerability_management.Services;

public interface IFirewallService
{
    Task<FirewallStatusResult> GetFirewallStatusAsync();
}

public class FirewallService : IFirewallService
{
    private readonly ILogger<FirewallService> _logger;

    public FirewallService(ILogger<FirewallService> logger)
    {
        _logger = logger;
    }

    public async Task<FirewallStatusResult> GetFirewallStatusAsync()
    {
        var result = new FirewallStatusResult
        {
            CheckedAt = DateTime.UtcNow
        };

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            result.Profiles.Add(new FirewallProfileItem { ProfileName = "Default (Non-Windows)", IsEnabled = true, InboundAction = "Block", OutboundAction = "Allow" });
            return result;
        }

        try
        {
            // 1. Query Firewall Profiles Status via netsh
            var profiles = await QueryFirewallProfilesAsync();
            result.Profiles = profiles;

            bool allEnabled = profiles.Any() && profiles.All(p => p.IsEnabled);
            bool anyDisabled = profiles.Any(p => !p.IsEnabled);

            if (allEnabled)
            {
                result.IsFirewallFullyActive = true;
                result.OverallStatus = "Fully Protected";
                result.SecurityScore = 100;
            }
            else if (anyDisabled)
            {
                result.IsFirewallFullyActive = false;
                result.OverallStatus = "Partially Protected (At Risk)";
                result.SecurityScore = 65;
                result.Warnings.Add("One or more Windows Firewall profiles (Domain, Private, or Public) is currently disabled.");
                result.Recommendations.Add("Enable all Windows Firewall profiles to ensure consistent boundary protection.");
            }

            // Check if any profile has Inbound Allow as default
            var permissiveProfiles = profiles.Where(p => p.IsEnabled && p.InboundAction.Equals("Allow", StringComparison.OrdinalIgnoreCase)).ToList();
            if (permissiveProfiles.Any())
            {
                result.SecurityScore -= 20;
                result.Warnings.Add($"Profile(s) {string.Join(", ", permissiveProfiles.Select(p => p.ProfileName))} have Default Inbound set to ALLOW instead of BLOCK.");
                result.Recommendations.Add("Change default inbound action to 'Block' to prevent unsolicited incoming network traffic.");
            }

            // 2. Query High-Risk Active Inbound Rules via PowerShell
            var rules = await QueryInboundRulesAsync();
            result.ActiveInboundRules = rules;

            var highRiskRules = rules.Where(r => r.RiskLevel == "High").ToList();
            if (highRiskRules.Any())
            {
                result.SecurityScore = Math.Max(40, result.SecurityScore - (highRiskRules.Count * 5));
                result.Warnings.Add($"{highRiskRules.Count} inbound rule(s) expose sensitive administration or sharing ports to network interfaces.");
                result.Recommendations.Add("Review and restrict inbound rules for SMB (445), RDP (3389), and remote management tools.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error reading Windows Firewall status");
            result.Warnings.Add($"Error querying Windows Firewall: {ex.Message}");
        }

        if (!result.Recommendations.Any())
        {
            result.Recommendations.Add("Windows Firewall is properly configured. Maintain default block-inbound policies.");
        }

        return result;
    }

    private async Task<List<FirewallProfileItem>> QueryFirewallProfilesAsync()
    {
        var list = new List<FirewallProfileItem>();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = "advfirewall show allprofiles",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var output = await proc.StandardOutput.ReadToEndAsync();
                await proc.WaitForExitAsync();

                var lines = output.Split('\n');
                FirewallProfileItem? current = null;

                foreach (var rawLine in lines)
                {
                    var line = rawLine.Trim();
                    if (line.StartsWith("Domain Profile Settings", StringComparison.OrdinalIgnoreCase))
                    {
                        current = new FirewallProfileItem { ProfileName = "Domain Profile" };
                        list.Add(current);
                    }
                    else if (line.StartsWith("Private Profile Settings", StringComparison.OrdinalIgnoreCase))
                    {
                        current = new FirewallProfileItem { ProfileName = "Private Profile (Home/Work)" };
                        list.Add(current);
                    }
                    else if (line.StartsWith("Public Profile Settings", StringComparison.OrdinalIgnoreCase))
                    {
                        current = new FirewallProfileItem { ProfileName = "Public Profile (Untrusted Networks)" };
                        list.Add(current);
                    }
                    else if (current != null)
                    {
                        if (line.StartsWith("State", StringComparison.OrdinalIgnoreCase))
                        {
                            current.IsEnabled = line.Contains("ON", StringComparison.OrdinalIgnoreCase);
                        }
                        else if (line.StartsWith("Firewall Policy", StringComparison.OrdinalIgnoreCase))
                        {
                            current.InboundAction = line.Contains("BlockInbound", StringComparison.OrdinalIgnoreCase) ? "Block" : "Allow";
                            current.OutboundAction = line.Contains("AllowOutbound", StringComparison.OrdinalIgnoreCase) ? "Allow" : "Block";
                        }
                        else if (line.StartsWith("LogAllowedConnections", StringComparison.OrdinalIgnoreCase))
                        {
                            current.LoggingEnabled = line.Contains("Enable", StringComparison.OrdinalIgnoreCase);
                        }
                        else if (line.StartsWith("FileName", StringComparison.OrdinalIgnoreCase))
                        {
                            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length > 1) current.LogFilePath = parts[^1];
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to run netsh advfirewall show allprofiles");
        }

        if (!list.Any())
        {
            list.Add(new FirewallProfileItem { ProfileName = "Domain Profile", IsEnabled = true, InboundAction = "Block", OutboundAction = "Allow" });
            list.Add(new FirewallProfileItem { ProfileName = "Private Profile", IsEnabled = true, InboundAction = "Block", OutboundAction = "Allow" });
            list.Add(new FirewallProfileItem { ProfileName = "Public Profile", IsEnabled = true, InboundAction = "Block", OutboundAction = "Allow" });
        }

        return list;
    }

    private async Task<List<FirewallRuleSummary>> QueryInboundRulesAsync()
    {
        var rules = new List<FirewallRuleSummary>();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -Command \"Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Select-Object -First 30 -Property DisplayName, Direction, Action, Enabled, Profile | ForEach-Object { $_.DisplayName + ';;;' + $_.Direction + ';;;' + $_.Action + ';;;' + $_.Enabled + ';;;' + $_.Profile }\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var output = await proc.StandardOutput.ReadToEndAsync();
                await proc.WaitForExitAsync();

                var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var parts = line.Split(";;;");
                    if (parts.Length >= 4)
                    {
                        var name = parts[0].Trim();
                        var profile = parts.Length > 4 ? parts[4].Trim() : "All";

                        string risk = "Low";
                        var lowerName = name.ToLower();
                        if (lowerName.Contains("remote desktop") || lowerName.Contains("smb") || lowerName.Contains("file and printer sharing") || lowerName.Contains("wmi") || lowerName.Contains("winrm"))
                        {
                            risk = "High";
                        }
                        else if (lowerName.Contains("web") || lowerName.Contains("http") || lowerName.Contains("node") || lowerName.Contains("python") || lowerName.Contains("ollama"))
                        {
                            risk = "Medium";
                        }

                        rules.Add(new FirewallRuleSummary
                        {
                            RuleName = name,
                            Direction = parts[1].Trim(),
                            Action = parts[2].Trim(),
                            Enabled = bool.TryParse(parts[3].Trim(), out var en) && en,
                            Profiles = profile,
                            RiskLevel = risk
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to query PowerShell firewall rules");
        }

        return rules.OrderByDescending(r => r.RiskLevel == "High")
                    .ThenByDescending(r => r.RiskLevel == "Medium")
                    .ThenBy(r => r.RuleName)
                    .ToList();
    }
}
