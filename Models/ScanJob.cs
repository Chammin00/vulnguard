using System.ComponentModel.DataAnnotations;

namespace vulnerability_management.Models;

public enum ScanStatus
{
    Queued,
    Running,
    Completed,
    Failed
}

public class ScanJob
{
    public int Id { get; set; }

    [Required]
    [StringLength(100)]
    public string ScanName { get; set; } = string.Empty;

    [Required]
    [StringLength(200)]
    public string Target { get; set; } = string.Empty; // IP, Subnet (e.g. 192.168.1.0/24), or Hostname

    public ScanStatus Status { get; set; } = ScanStatus.Queued;

    public int ProgressPercent { get; set; } = 0;

    public int AssetsScanned { get; set; } = 0;

    public int VulnerabilitiesFound { get; set; } = 0;

    public DateTime StartedAt { get; set; } = DateTime.UtcNow;

    public DateTime? FinishedAt { get; set; }

    public string? LogOutput { get; set; }
}
