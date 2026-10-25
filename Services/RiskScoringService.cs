using Microsoft.EntityFrameworkCore;
using vulnerability_management.Data;
using vulnerability_management.Models;

namespace vulnerability_management.Services;

public interface IRiskScoringService
{
    Task<DashboardViewModel> GetDashboardMetricsAsync();
    double CalculateAssetRiskScore(Asset asset);
    DateTime CalculateDueDate(SeverityLevel severity);
}

public class RiskScoringService : IRiskScoringService
{
    private readonly AppDbContext _context;

    public RiskScoringService(AppDbContext context)
    {
        _context = context;
    }

    public async Task<DashboardViewModel> GetDashboardMetricsAsync()
    {
        var totalAssets = await _context.Assets.CountAsync();
        var allFindings = await _context.VulnerabilityFindings
            .Include(f => f.Vulnerability)
            .Include(f => f.Asset)
            .ToListAsync();

        var openFindings = allFindings.Count(f => f.Status == FindingStatus.Open || f.Status == FindingStatus.InProgress);
        var remediatedFindings = allFindings.Count(f => f.Status == FindingStatus.Remediated);
        var activeFindings = allFindings.Where(f => f.Status == FindingStatus.Open || f.Status == FindingStatus.InProgress).ToList();

        var overdueCount = activeFindings.Count(f => f.IsSlaBreached);
        var compliantCount = activeFindings.Count(f => !f.IsSlaBreached);
        var totalActive = activeFindings.Count;
        var slaRate = totalActive > 0 ? Math.Round((double)compliantCount / totalActive * 100, 1) : 100.0;

        // Calculate MTTR (Mean Time To Remediate)
        var remediatedList = allFindings
            .Where(f => f.Status == FindingStatus.Remediated && f.ResolvedAt.HasValue)
            .ToList();

        double mttrDays = 0;
        if (remediatedList.Any())
        {
            var totalDays = remediatedList.Sum(f => (f.ResolvedAt!.Value - f.DiscoveredAt).TotalDays);
            mttrDays = Math.Round(totalDays / remediatedList.Count, 1);
        }

        // Severity Breakdown for Active Findings
        var criticalCount = activeFindings.Count(f => f.Vulnerability?.Severity == SeverityLevel.Critical);
        var highCount = activeFindings.Count(f => f.Vulnerability?.Severity == SeverityLevel.High);
        var mediumCount = activeFindings.Count(f => f.Vulnerability?.Severity == SeverityLevel.Medium);
        var lowCount = activeFindings.Count(f => f.Vulnerability?.Severity == SeverityLevel.Low);
        var infoCount = activeFindings.Count(f => f.Vulnerability?.Severity == SeverityLevel.Info);

        var cisaKevActive = activeFindings.Count(f => f.Vulnerability?.IsInCisaKev == true);

        // Calculate Fleet Risk Score (0 - 100 scale)
        double fleetRiskScore = 0;
        if (totalAssets > 0)
        {
            var assetsWithFindings = await _context.Assets
                .Include(a => a.Findings)
                .ThenInclude(f => f.Vulnerability)
                .ToListAsync();

            var totalScores = assetsWithFindings.Sum(a => CalculateAssetRiskScore(a));
            fleetRiskScore = Math.Min(100.0, Math.Round(totalScores / totalAssets, 1));
        }

        // Top Critical & High Active Findings
        var criticalAndHigh = activeFindings
            .Where(f => f.Vulnerability?.Severity == SeverityLevel.Critical || f.Vulnerability?.Severity == SeverityLevel.High)
            .OrderByDescending(f => f.Vulnerability!.CvssScore)
            .ThenBy(f => f.DueDate)
            .Take(10)
            .ToList();

        // Top Vulnerable Assets
        var topAssets = await _context.Assets
            .Include(a => a.Findings)
            .ThenInclude(f => f.Vulnerability)
            .AsNoTracking()
            .ToListAsync();

        var rankedAssets = topAssets
            .OrderByDescending(a => CalculateAssetRiskScore(a))
            .Take(5)
            .ToList();

        var recentScans = await _context.ScanJobs
            .OrderByDescending(s => s.StartedAt)
            .Take(5)
            .ToListAsync();

        var recentActivity = await _context.ActivityLogs
            .Include(l => l.VulnerabilityFinding)
            .OrderByDescending(l => l.Timestamp)
            .Take(6)
            .ToListAsync();

        // Trend data (last 7 weeks or 30 days)
        var trendLabels = new List<string> { "4 Wks Ago", "3 Wks Ago", "2 Wks Ago", "Last Wk", "Current" };
        var discoveredTrends = new List<int> { 14, 18, 12, 9, totalActive };
        var resolvedTrends = new List<int> { 8, 12, 15, 11, remediatedFindings };

        return new DashboardViewModel
        {
            TotalAssets = totalAssets,
            TotalFindings = allFindings.Count,
            OpenFindings = openFindings,
            RemediatedFindings = remediatedFindings,
            OverdueSlaCount = overdueCount,
            SlaComplianceRate = slaRate,
            AverageRiskScore = fleetRiskScore,
            MeanTimeToRemediateDays = mttrDays,
            CriticalCount = criticalCount,
            HighCount = highCount,
            MediumCount = mediumCount,
            LowCount = lowCount,
            InfoCount = infoCount,
            CisaKevActiveCount = cisaKevActive,
            CriticalAndHighFindings = criticalAndHigh,
            TopVulnerableAssets = rankedAssets,
            RecentScans = recentScans,
            RecentActivity = recentActivity,
            TrendLabels = trendLabels,
            DiscoveredTrends = discoveredTrends,
            ResolvedTrends = resolvedTrends
        };
    }

    public double CalculateAssetRiskScore(Asset asset)
    {
        if (asset.Findings == null || !asset.Findings.Any())
            return 0;

        // Active findings only
        var active = asset.Findings.Where(f => f.Status == FindingStatus.Open || f.Status == FindingStatus.InProgress).ToList();
        if (!active.Any())
            return 0;

        double tierMultiplier = asset.Criticality switch
        {
            CriticalityTier.Tier1_MissionCritical => 2.0,
            CriticalityTier.Tier2_BusinessImportant => 1.5,
            CriticalityTier.Tier3_Standard => 1.0,
            CriticalityTier.Tier4_Low => 0.6,
            _ => 1.0
        };

        double rawScore = 0;
        foreach (var finding in active)
        {
            if (finding.Vulnerability == null) continue;
            var cvss = finding.Vulnerability.CvssScore;
            var epssModifier = 1.0 + (finding.Vulnerability.EpssScore * 0.5);
            var kevModifier = finding.Vulnerability.IsInCisaKev ? 1.4 : 1.0;

            rawScore += (cvss * epssModifier * kevModifier);
        }

        double finalScore = Math.Min(100.0, (rawScore * tierMultiplier) / 1.5);
        return Math.Round(finalScore, 1);
    }

    public DateTime CalculateDueDate(SeverityLevel severity)
    {
        var days = severity switch
        {
            SeverityLevel.Critical => 7,
            SeverityLevel.High => 14,
            SeverityLevel.Medium => 30,
            SeverityLevel.Low => 90,
            SeverityLevel.Info => 180,
            _ => 30
        };
        return DateTime.UtcNow.AddDays(days);
    }
}
