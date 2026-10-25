namespace vulnerability_management.Models;

public class LocalSmartScanResult
{
    public DateTime ScannedAt { get; set; } = DateTime.UtcNow;
    public string MachineName { get; set; } = Environment.MachineName;
    public string UserName { get; set; } = Environment.UserName;
    public string OsVersion { get; set; } = Environment.OSVersion.ToString();
    public string OsDescription { get; set; } = System.Runtime.InteropServices.RuntimeInformation.OSDescription;
    public string Architecture { get; set; } = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString();
    public int ProcessorCount { get; set; } = Environment.ProcessorCount;
    public double SystemUptimeHours { get; set; }

    // Overall Security Score (0 to 100)
    public int OverallHealthScore { get; set; } = 100;
    public string OverallStatus { get; set; } = "Secure"; // Secure, Attention Needed, Vulnerable

    // Security Controls Checks
    public List<SecurityCheckItem> SecurityChecks { get; set; } = new();

    // Active Local Listening Endpoints & Bound Processes
    public List<LocalListeningPort> ListeningPorts { get; set; } = new();

    // Installed Software Audited
    public List<AuditedApplication> InstalledSoftware { get; set; } = new();

    // High Priority Vulnerability Alerts Identified on this machine
    public List<string> SecurityAlerts { get; set; } = new();
    public List<string> RemediationRecommendations { get; set; } = new();
}

public class SecurityCheckItem
{
    public string Category { get; set; } = string.Empty; // Antivirus, Firewall, OS Updates, Account Security, Network Exposure
    public string Name { get; set; } = string.Empty;
    public string Status { get; set; } = "Pass"; // Pass, Warning, Fail
    public string Details { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
    public int ImpactScore { get; set; } = 10;
}

public class LocalListeningPort
{
    public int Port { get; set; }
    public string Protocol { get; set; } = "TCP";
    public string LocalAddress { get; set; } = "127.0.0.1";
    public string State { get; set; } = "Listen";
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "Unknown";
    public bool IsExposedToNetwork { get; set; } // Listening on 0.0.0.0 vs 127.0.0.1
    public string RiskLevel { get; set; } = "Low"; // Low, Medium, High
}

public class AuditedApplication
{
    public string DisplayName { get; set; } = string.Empty;
    public string DisplayVersion { get; set; } = string.Empty;
    public string Publisher { get; set; } = string.Empty;
    public string? InstallDate { get; set; }
    public bool HasKnownVulnerability { get; set; }
    public string? VulnerabilityWarning { get; set; }
}
