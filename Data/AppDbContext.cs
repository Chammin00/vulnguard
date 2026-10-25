using Microsoft.EntityFrameworkCore;
using vulnerability_management.Models;

namespace vulnerability_management.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<Asset> Assets => Set<Asset>();
    public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();
    public DbSet<VulnerabilityFinding> VulnerabilityFindings => Set<VulnerabilityFinding>();
    public DbSet<ScanJob> ScanJobs => Set<ScanJob>();
    public DbSet<SlaPolicy> SlaPolicies => Set<SlaPolicy>();
    public DbSet<ActivityLog> ActivityLogs => Set<ActivityLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Asset indexes
        modelBuilder.Entity<Asset>()
            .HasIndex(a => a.IpAddress);

        modelBuilder.Entity<Asset>()
            .HasIndex(a => a.Hostname);

        // Vulnerability indexes
        modelBuilder.Entity<Vulnerability>()
            .HasIndex(v => v.CveId)
            .IsUnique();

        // VulnerabilityFinding relationships
        modelBuilder.Entity<VulnerabilityFinding>()
            .HasOne(f => f.Asset)
            .WithMany(a => a.Findings)
            .HasForeignKey(f => f.AssetId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<VulnerabilityFinding>()
            .HasOne(f => f.Vulnerability)
            .WithMany(v => v.Findings)
            .HasForeignKey(f => f.VulnerabilityId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<VulnerabilityFinding>()
            .HasMany(f => f.ActivityLogs)
            .WithOne(l => l.VulnerabilityFinding)
            .HasForeignKey(l => l.VulnerabilityFindingId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
