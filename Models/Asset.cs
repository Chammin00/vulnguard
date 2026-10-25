using System.ComponentModel.DataAnnotations;

namespace vulnerability_management.Models;

public enum CriticalityTier
{
    Tier1_MissionCritical = 1,
    Tier2_BusinessImportant = 2,
    Tier3_Standard = 3,
    Tier4_Low = 4
}

public enum EnvironmentType
{
    Production,
    Staging,
    Development,
    Internal,
    DMZ
}

public class Asset
{
    public int Id { get; set; }

    [Required]
    [StringLength(100)]
    public string Hostname { get; set; } = string.Empty;

    [Required]
    [StringLength(45)]
    public string IpAddress { get; set; } = string.Empty;

    [StringLength(50)]
    public string MacAddress { get; set; } = string.Empty;

    [StringLength(100)]
    public string OperatingSystem { get; set; } = string.Empty;

    public EnvironmentType Environment { get; set; } = EnvironmentType.Production;

    public CriticalityTier Criticality { get; set; } = CriticalityTier.Tier2_BusinessImportant;

    [StringLength(100)]
    public string Owner { get; set; } = "SecOps Team";

    [StringLength(200)]
    public string Tags { get; set; } = "web, linux";

    [StringLength(500)]
    public string OpenPorts { get; set; } = "22/SSH, 80/HTTP, 443/HTTPS";

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastScannedAt { get; set; }

    // Navigation properties
    public List<VulnerabilityFinding> Findings { get; set; } = new();
}
