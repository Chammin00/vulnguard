using System.ComponentModel.DataAnnotations;

namespace vulnerability_management.Models;

public enum FileThreatLevel
{
    Clean,
    Suspicious,
    Malicious
}

public class FileScanRequest
{
    [Required]
    public string TargetPath { get; set; } = string.Empty;

    public bool IncludeSubdirectories { get; set; } = true;

    public long MaxFileSizeMb { get; set; } = 250; // Scan files up to 250 MB
}

public class FileScanResult
{
    public string TargetPath { get; set; } = string.Empty;
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;
    public DateTime CompletedAt { get; set; } = DateTime.UtcNow;
    public TimeSpan Duration => CompletedAt - StartedAt;

    public int TotalFilesScanned { get; set; }
    public int CleanFilesCount { get; set; }
    public int SuspiciousFilesCount { get; set; }
    public int MaliciousFilesCount { get; set; }

    public long TotalBytesScanned { get; set; }

    public List<ScannedFileItem> ScannedFiles { get; set; } = new();
}

public class ScannedFileItem
{
    public string FileName { get; set; } = string.Empty;
    public string FullPath { get; set; } = string.Empty;
    public string Extension { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public DateTime LastModified { get; set; }

    public string Sha256Hash { get; set; } = string.Empty;
    public string Md5Hash { get; set; } = string.Empty;

    public FileThreatLevel ThreatLevel { get; set; } = FileThreatLevel.Clean;
    public string ThreatName { get; set; } = "No Threats Detected";
    public string DetectionReason { get; set; } = "Passed signature and heuristic integrity verification.";
    public List<string> HeuristicFlags { get; set; } = new();
}
