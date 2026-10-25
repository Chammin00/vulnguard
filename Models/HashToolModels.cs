namespace vulnerability_management.Models;

public enum HashAlgorithmType
{
    Unknown,
    MD5,
    SHA1,
    SHA256,
    SHA512
}

public enum HashThreatClassification
{
    Clean,
    KnownMalicious,
    Suspicious,
    Unknown
}

public class HashLookupRequest
{
    public string HashValue { get; set; } = string.Empty;
}

public class HashLookupResult
{
    public string QueryHash { get; set; } = string.Empty;
    public HashAlgorithmType Algorithm { get; set; } = HashAlgorithmType.Unknown;
    public bool IsValidFormat { get; set; }

    public HashThreatClassification Classification { get; set; } = HashThreatClassification.Unknown;
    public string ThreatName { get; set; } = "Unknown / Not in Local Catalog";
    public string ThreatCategory { get; set; } = "Unclassified";
    public string ThreatDetails { get; set; } = string.Empty;
    public string FirstSeen { get; set; } = string.Empty;
    public string Severity { get; set; } = "Info"; // Critical, High, Medium, Low, Info, Clean

    // Threat Intelligence Lookup URLs
    public string VirusTotalUrl => !string.IsNullOrWhiteSpace(QueryHash) ? $"https://www.virustotal.com/gui/search/{QueryHash.Trim()}" : "";
    public string MalwareBazaarUrl => !string.IsNullOrWhiteSpace(QueryHash) ? $"https://bazaar.abuse.ch/sample/{QueryHash.Trim()}/" : "";
    public string HybridAnalysisUrl => !string.IsNullOrWhiteSpace(QueryHash) ? $"https://www.hybrid-analysis.com/search?query={QueryHash.Trim()}" : "";
    public string AlienVaultOtxUrl => !string.IsNullOrWhiteSpace(QueryHash) ? $"https://otx.alienvault.com/indicator/file/{QueryHash.Trim()}" : "";
}

public class FileHashCalculateRequest
{
    public string? LocalFilePath { get; set; }
    public string? ExpectedHash { get; set; }
}

public class FileHashCalculateResult
{
    public string FileName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public string FileSizeFormatted => FileSizeBytes > 1024 * 1024 ? $"{(FileSizeBytes / (1024.0 * 1024.0)):F2} MB" : $"{(FileSizeBytes / 1024.0):F2} KB";

    public string Md5 { get; set; } = string.Empty;
    public string Sha1 { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public string Sha512 { get; set; } = string.Empty;

    public bool HasExpectedHash => !string.IsNullOrWhiteSpace(ExpectedHash);
    public string? ExpectedHash { get; set; }
    public bool IsHashMatch { get; set; }
    public string MatchDetails { get; set; } = string.Empty;

    public HashLookupResult ThreatIntelligence { get; set; } = new();
}

public class BulkHashParseResult
{
    public int TotalHashesExtracted { get; set; }
    public int MaliciousCount { get; set; }
    public int CleanCount { get; set; }
    public int UnknownCount { get; set; }

    public List<HashLookupResult> Items { get; set; } = new();
}
