namespace vulnerability_management.Models;

public enum IdsIpsMode
{
    IDS_DetectionOnly,
    IPS_ActivePrevention
}

public enum AttackSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

public enum IpsAction
{
    Alerted,
    Blocked,
    Dropped
}

public class IdsRule
{
    public int Sid { get; set; } // Signature ID (e.g. 10001)
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = "Web Application"; // Web Application, Reconnaissance, Exploit/RCE, Brute Force, Scanning
    public AttackSeverity Severity { get; set; } = AttackSeverity.High;
    public string PatternRegex { get; set; } = string.Empty;
    public bool IsEnabled { get; set; } = true;
    public IpsAction DefaultAction { get; set; } = IpsAction.Blocked;
    public string Description { get; set; } = string.Empty;
    public string MitreAttackId { get; set; } = string.Empty; // e.g. T1190, T1059
}

public class IdsIpsEvent
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string SourceIp { get; set; } = "127.0.0.1";
    public string Method { get; set; } = "GET";
    public string TargetPath { get; set; } = "/";
    public int MatchedSid { get; set; }
    public string RuleName { get; set; } = string.Empty;
    public string Category { get; set; } = "Web Application";
    public AttackSeverity Severity { get; set; } = AttackSeverity.High;
    public IpsAction ActionTaken { get; set; } = IpsAction.Blocked;
    public string PayloadSnippet { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public string MitreAttackId { get; set; } = string.Empty;
}

public class BannedIpEntry
{
    public string IpAddress { get; set; } = string.Empty;
    public DateTime BannedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresAt { get; set; }
    public string Reason { get; set; } = string.Empty;
    public int TriggeredSid { get; set; }
    public bool IsPermanent => !ExpiresAt.HasValue;
    public bool IsActive => !ExpiresAt.HasValue || ExpiresAt.Value > DateTime.UtcNow;
}

public class IdsIpsSummaryViewModel
{
    public IdsIpsMode Mode { get; set; } = IdsIpsMode.IPS_ActivePrevention;
    public long TotalInspected { get; set; }
    public long TotalAlerts { get; set; }
    public long TotalBlocks { get; set; }
    public int ActiveBansCount { get; set; }
    public double PreventionRate => TotalInspected > 0 ? Math.Round(((double)TotalBlocks / (TotalAlerts + TotalBlocks > 0 ? (TotalAlerts + TotalBlocks) : 1)) * 100, 1) : 100;

    public List<IdsIpsEvent> RecentEvents { get; set; } = new();
    public List<BannedIpEntry> BannedIps { get; set; } = new();
    public List<IdsRule> Rules { get; set; } = new();
}

public class AttackSimulationRequest
{
    public string Payload { get; set; } = string.Empty;
    public string TargetPath { get; set; } = "/api/v1/resource";
    public string SourceIp { get; set; } = "192.168.1.185";
    public string UserAgent { get; set; } = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
}
