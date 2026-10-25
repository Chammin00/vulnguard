namespace vulnerability_management.Models;

public class DashboardViewModel
{
    public int TotalAssets { get; set; }
    public int TotalFindings { get; set; }
    public int OpenFindings { get; set; }
    public int RemediatedFindings { get; set; }
    public int OverdueSlaCount { get; set; }
    public double SlaComplianceRate { get; set; } // Percentage e.g. 88.5%
    public double AverageRiskScore { get; set; } // 0 - 100
    public double MeanTimeToRemediateDays { get; set; } // MTTR

    // Severity Breakdown for Active Findings
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int InfoCount { get; set; }

    public int CisaKevActiveCount { get; set; } // Vulnerabilities in CISA KEV actively present in environment

    public List<VulnerabilityFinding> CriticalAndHighFindings { get; set; } = new();
    public List<Asset> TopVulnerableAssets { get; set; } = new();
    public List<ScanJob> RecentScans { get; set; } = new();
    public List<ActivityLog> RecentActivity { get; set; } = new();

    // Chart Trend Data (Past 30 Days)
    public List<string> TrendLabels { get; set; } = new();
    public List<int> DiscoveredTrends { get; set; } = new();
    public List<int> ResolvedTrends { get; set; } = new();
}

public class ComplianceReportViewModel
{
    public string StandardName { get; set; } = "Unified Security Compliance Framework";
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    public double OverallComplianceScore { get; set; }
    public int TotalControlsEvaluated { get; set; }
    public int CompliantControls { get; set; }
    public int NonCompliantControls { get; set; }

    public List<ComplianceControl> Controls { get; set; } = new();
}

public class ComplianceControl
{
    public string Framework { get; set; } = string.Empty; // SOC 2, PCI-DSS, ISO 27001, NIST CSF
    public string ControlId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Requirement { get; set; } = string.Empty;
    public string Status { get; set; } = "Pass"; // Pass, Warning, Fail
    public string Evidence { get; set; } = string.Empty;
}

public class ScanRequestViewModel
{
    public string ScanName { get; set; } = "Ad-hoc Vulnerability Scan";
    public string Target { get; set; } = "127.0.0.1";
    public string ScanType { get; set; } = "Full"; // Quick, Full, HostDiscovery
    public bool AutoCreateFindings { get; set; } = true;
}
