using System.ComponentModel.DataAnnotations;

namespace vulnerability_management.Models;

public class SlaPolicy
{
    public int Id { get; set; }

    [Required]
    public SeverityLevel Severity { get; set; }

    public int MaxDaysToRemediate { get; set; } // e.g. Critical = 7, High = 14, Med = 30, Low = 90

    public string Description { get; set; } = string.Empty;
}

public class ActivityLog
{
    public int Id { get; set; }

    public int? VulnerabilityFindingId { get; set; }
    public VulnerabilityFinding? VulnerabilityFinding { get; set; }

    [Required]
    [StringLength(100)]
    public string Action { get; set; } = string.Empty;

    public string Details { get; set; } = string.Empty;

    [StringLength(100)]
    public string User { get; set; } = "System";

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
