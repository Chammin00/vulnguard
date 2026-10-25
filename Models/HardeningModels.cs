namespace vulnerability_management.Models;

public class HardeningChecklistResult
{
    public DateTime EvaluatedAt { get; set; } = DateTime.UtcNow;
    public string MachineName { get; set; } = Environment.MachineName;
    public string OsDescription { get; set; } = System.Runtime.InteropServices.RuntimeInformation.OSDescription;

    public int AppliedControlsCount { get; set; }
    public int TotalControlsCount { get; set; }
    public int HardeningScore => TotalControlsCount > 0 ? (int)Math.Round(((double)AppliedControlsCount / TotalControlsCount) * 100) : 0;
    public string HardeningStatus => HardeningScore >= 90 ? "Maximum Hardening" : HardeningScore >= 70 ? "Moderately Hardened" : "Basic / Action Recommended";

    public List<HardeningControlItem> Controls { get; set; } = new();
}

public class HardeningControlItem
{
    public string Category { get; set; } = string.Empty; // Defender, Network, System, Account, Browser
    public string Title { get; set; } = string.Empty;
    public string CurrentState { get; set; } = string.Empty;
    public string RecommendedState { get; set; } = string.Empty;
    public string Status { get; set; } = "NeedsAttention"; // Applied, NeedsAttention, Optional
    public string SecurityBenefit { get; set; } = string.Empty;
    public string PowerShellCommand { get; set; } = string.Empty;
    public string ConfigurationLocation { get; set; } = string.Empty;
    public string ThreatMitigated { get; set; } = string.Empty;
}
