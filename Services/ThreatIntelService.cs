using Microsoft.EntityFrameworkCore;
using vulnerability_management.Data;
using vulnerability_management.Models;

namespace vulnerability_management.Services;

public interface IThreatIntelService
{
    Task<List<Vulnerability>> GetCisaKevCatalogAsync();
    Task<Vulnerability?> LookupCveAsync(string cveId);
    Task<List<Vulnerability>> GetAllVulnerabilitiesAsync(string? search = null, SeverityLevel? severity = null, bool? cisaKevOnly = null);
}

public class ThreatIntelService : IThreatIntelService
{
    private readonly AppDbContext _context;

    public ThreatIntelService(AppDbContext context)
    {
        _context = context;
    }

    public async Task<List<Vulnerability>> GetCisaKevCatalogAsync()
    {
        return await _context.Vulnerabilities
            .Where(v => v.IsInCisaKev)
            .OrderByDescending(v => v.PublishedDate)
            .ToListAsync();
    }

    public async Task<Vulnerability?> LookupCveAsync(string cveId)
    {
        return await _context.Vulnerabilities
            .Include(v => v.Findings)
            .ThenInclude(f => f.Asset)
            .FirstOrDefaultAsync(v => v.CveId.ToLower() == cveId.ToLower().Trim());
    }

    public async Task<List<Vulnerability>> GetAllVulnerabilitiesAsync(string? search = null, SeverityLevel? severity = null, bool? cisaKevOnly = null)
    {
        var query = _context.Vulnerabilities
            .Include(v => v.Findings)
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var s = search.ToLower().Trim();
            query = query.Where(v => v.CveId.ToLower().Contains(s) || v.Title.ToLower().Contains(s) || v.Description.ToLower().Contains(s) || v.AffectedComponent.ToLower().Contains(s));
        }

        if (severity.HasValue)
        {
            query = query.Where(v => v.Severity == severity.Value);
        }

        if (cisaKevOnly.HasValue && cisaKevOnly.Value)
        {
            query = query.Where(v => v.IsInCisaKev);
        }

        return await query.OrderByDescending(v => v.CvssScore).ToListAsync();
    }
}
