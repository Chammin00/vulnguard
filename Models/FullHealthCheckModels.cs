namespace vulnerability_management.Models;

public class FullPcHealthResult
{
    public DateTime AssessedAt { get; set; } = DateTime.UtcNow;
    public string MachineName { get; set; } = Environment.MachineName;
    public string UserName { get; set; } = Environment.UserName;
    public string OsName { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public string Architecture { get; set; } = string.Empty;
    public double UptimeHours { get; set; }

    // Overall Score & Grade
    public int OverallHealthScore { get; set; } = 100; // 0 to 100
    public string HealthGrade { get; set; } = "A+"; // A+, A, B, C, F
    public string HealthVerdict { get; set; } = "Excellent Health";

    // Category Pillars & Scores
    public HealthPillarScore SecurityPillar { get; set; } = new() { Category = "Security & Endpoint Defenses" };
    public HealthPillarScore PerformancePillar { get; set; } = new() { Category = "Memory & Compute Resources" };
    public HealthPillarScore StoragePillar { get; set; } = new() { Category = "Disk Storage & Volume Health" };
    public HealthPillarScore ServicesPillar { get; set; } = new() { Category = "Core Windows System Services" };
    public HealthPillarScore NetworkPillar { get; set; } = new() { Category = "Firewall & Network Exposure" };

    // Detailed Diagnostics
    public List<DiskDriveHealth> Drives { get; set; } = new();
    public MemoryHealthInfo Memory { get; set; } = new();
    public CpuHealthInfo Cpu { get; set; } = new();
    public List<WindowsServiceHealth> CoreServices { get; set; } = new();
    public List<HealthCheckFinding> Findings { get; set; } = new();
    public List<string> RecommendedActions { get; set; } = new();
}

public class HealthPillarScore
{
    public string Category { get; set; } = string.Empty;
    public int Score { get; set; } = 100; // 0 - 100
    public string Status { get; set; } = "Healthy"; // Healthy, Warning, Critical
    public string Summary { get; set; } = string.Empty;
}

public class DiskDriveHealth
{
    public string Name { get; set; } = string.Empty; // C:\
    public string VolumeLabel { get; set; } = string.Empty;
    public string DriveFormat { get; set; } = "NTFS";
    public double TotalGb { get; set; }
    public double FreeGb { get; set; }
    public double UsedGb => Math.Max(0, TotalGb - FreeGb);
    public double PercentUsed => TotalGb > 0 ? Math.Round((UsedGb / TotalGb) * 100, 1) : 0;
    public string Status { get; set; } = "Healthy"; // Healthy, Warning, Critical
}

public class MemoryHealthInfo
{
    public double TotalPhysicalGb { get; set; }
    public double AvailablePhysicalGb { get; set; }
    public double UsedPhysicalGb => Math.Max(0, TotalPhysicalGb - AvailablePhysicalGb);
    public double PercentUsed => TotalPhysicalGb > 0 ? Math.Round((UsedPhysicalGb / TotalPhysicalGb) * 100, 1) : 0;
    public string Status { get; set; } = "Healthy"; // Healthy, Warning, High Pressure
}

public class CpuHealthInfo
{
    public int LogicalProcessors { get; set; }
    public int ActiveProcessCount { get; set; }
    public int ActiveThreadCount { get; set; }
    public string Architecture { get; set; } = "X64";
}

public class WindowsServiceHealth
{
    public string ServiceName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Status { get; set; } = "Running"; // Running, Stopped, Not Installed
    public string StartType { get; set; } = "Automatic";
    public bool IsEssential { get; set; } = true;
    public string RoleDescription { get; set; } = string.Empty;
}

public class HealthCheckFinding
{
    public string Category { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Severity { get; set; } = "Info"; // Info, Warning, Critical
    public string Details { get; set; } = string.Empty;
    public string FixGuidance { get; set; } = string.Empty;
}
