namespace vulnerability_management.Models;

public class FirewallStatusResult
{
    public DateTime CheckedAt { get; set; } = DateTime.UtcNow;
    public bool IsFirewallFullyActive { get; set; } = true;
    public string OverallStatus { get; set; } = "Protected"; // Protected, Partially Protected, Unprotected
    public int SecurityScore { get; set; } = 100;

    public List<FirewallProfileItem> Profiles { get; set; } = new();
    public List<FirewallRuleSummary> ActiveInboundRules { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public List<string> Recommendations { get; set; } = new();
}

public class FirewallProfileItem
{
    public string ProfileName { get; set; } = string.Empty; // Domain, Private, Public
    public bool IsEnabled { get; set; }
    public string InboundAction { get; set; } = "Block"; // Block, Allow
    public string OutboundAction { get; set; } = "Allow";
    public bool LoggingEnabled { get; set; }
    public string LogFilePath { get; set; } = string.Empty;
}

public class FirewallRuleSummary
{
    public string RuleName { get; set; } = string.Empty;
    public string Direction { get; set; } = "Inbound";
    public string Action { get; set; } = "Allow"; // Allow, Block
    public bool Enabled { get; set; }
    public string Protocol { get; set; } = "TCP";
    public string LocalPort { get; set; } = "Any";
    public string Program { get; set; } = "Any";
    public string Profiles { get; set; } = "All";
    public string RiskLevel { get; set; } = "Low"; // Low, Medium, High
}
