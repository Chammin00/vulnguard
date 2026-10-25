using System.Security.Cryptography;
using System.Text.RegularExpressions;
using vulnerability_management.Models;

namespace vulnerability_management.Services;

public interface IHashToolService
{
    HashLookupResult LookupHash(string rawHash);
    Task<FileHashCalculateResult> CalculateHashesForFileAsync(string filePath, string? expectedHash = null);
    Task<FileHashCalculateResult> CalculateHashesForStreamAsync(Stream stream, string fileName, string? expectedHash = null);
    BulkHashParseResult ParseAndAnalyzeBulkText(string text);
}

public class HashToolService : IHashToolService
{
    private readonly ILogger<HashToolService> _logger;

    // Local curated threat signature catalog
    private static readonly Dictionary<string, (string Name, string Category, string Details, string Severity, string FirstSeen)> KnownThreatDb = new(StringComparer.OrdinalIgnoreCase)
    {
        // 1. EICAR Standard Antivirus Test Signatures
        ["44d88612fea8a8f36de82e1278abb02f"] = ("EICAR-Standard-AV-Test-File", "Test Signature", "Standard European Expert Group for IT-Security test file used to verify AV detection capabilities safely.", "Clean/Test", "1991"),
        ["3395856ce81f2b7382dee72602f798b642f14140"] = ("EICAR-Standard-AV-Test-File", "Test Signature", "Standard European Expert Group for IT-Security test file used to verify AV detection capabilities safely.", "Clean/Test", "1991"),
        ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"] = ("EICAR-Standard-AV-Test-File", "Test Signature", "Standard European Expert Group for IT-Security test file used to verify AV detection capabilities safely.", "Clean/Test", "1991"),
        ["131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267d69317d7486a6a41da13d4b609629e3dac6571131a8b52281e95377195ff5fa0"] = ("EICAR-Standard-AV-Test-File", "Test Signature", "Standard European Expert Group for IT-Security test file used to verify AV detection capabilities safely.", "Clean/Test", "1991"),

        // 2. WannaCry Ransomware
        ["24d004a104d4d54034dbc29c2f810772fd1ad303e1b19f7830f3c6ae2fa90132"] = ("WannaCry (WanaCrypt0r 2.0)", "Ransomware / Worm", "WannaCry ransomware binary with EternalBlue SMBv1 worm propagation module.", "Critical", "May 2017"),
        ["ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"] = ("WannaCry Dropper", "Ransomware Dropper", "Initial executable dropper payload for WannaCry ransomware campaign.", "Critical", "May 2017"),
        ["db349b97c37d22f5b0d77292e5b8e765"] = ("WannaCry Encryptor Component", "Ransomware", "Encrypted payload DLL unpacked by WannaCry dropper.", "Critical", "May 2017"),

        // 3. LockBit 3.0 (LockBit Black) Ransomware
        ["d6f518e9508933b2a2cc09491ea720235334460fa8d7a188f6c3823467b7f14b"] = ("LockBit 3.0 (LockBit Black)", "Ransomware", "High-speed multi-threaded ransomware variant with anti-analysis and VSS shadow deletion.", "Critical", "June 2022"),
        ["7cb4bb8c5a4d4a8e52c8b0a5f5698b671a5c68f18837e2cbbf54d2e8250269f8"] = ("LockBit 2.0 Encryptor", "Ransomware", "LockBit 2.0 encryptor binary used in targeted enterprise intrusions.", "Critical", "2021"),

        // 4. BlackCat / ALPHV Ransomware
        ["1d179612c6a4613bb10825c317bfb9d4e9fce0fae41abac98a6bb52f2073ff1c"] = ("BlackCat (ALPHV)", "Ransomware", "Rust-based ransomware-as-a-service payload with automated network discovery capabilities.", "Critical", "Nov 2021"),

        // 5. Emotet Banking Trojan & Malware Loader
        ["5c889f53e1a06700c9e6bb07e15549045b85a3a70f2f35760ec25227d891e4b8"] = ("Emotet Modular Trojan", "Trojan / Loader", "Polymorphic banking trojan and modular malware delivery botnet payload.", "Critical", "2020"),
        ["41b6cb4a40058e390c5f242146f88d2d0ac94efd"] = ("Emotet Macro Dropper", "Downloader", "Malicious Word document VBA macro dropper communicating with Emotet C2.", "High", "2019"),

        // 6. Mimikatz Credential Dumper
        ["5f67b587a8b61c77840134446b7a5a8f5c357d6b8808dc994df56382103f6f3a"] = ("Mimikatz LSASS Dumper", "HackTool / Credential Dumper", "Post-exploitation utility used to extract plaintext passwords and Kerberos tickets from memory.", "High", "2021"),
        ["b6b442111b15c61a5b8a53e5e4de88bb"] = ("Mimikatz x64 Driver", "HackTool", "Mimidrv.sys kernel driver component used by Mimikatz.", "High", "2020"),

        // 7. Cobalt Strike Beacon
        ["0c90c6819eb312f293026071ea95a8e104e9c7ea01a403fb2424df81f215d2a6"] = ("Cobalt Strike Beacon Stager", "Command & Control / Post-Exploitation", "Cobalt Strike malleable C2 interactive beacon DLL used for lateral movement.", "Critical", "2022"),

        // 8. XMRig Monero Miner
        ["8286a6d639ee80dbba76037e96b797fcb55146c82705e4663e26c63b715975eb"] = ("XMRig Monero CPU Miner", "Riskware / CoinMiner", "High CPU-utilization cryptocurrency mining binary.", "Medium", "2022"),

        // 9. RedLine Stealer
        ["ca0a43fca3603417643b4f62776c5b05adcf8e788c1c4f420c85c276329c3799"] = ("RedLine InfoStealer", "Infostealer", "Malware designed to harvest browser passwords, cookies, credit cards, and crypto wallets.", "Critical", "2023"),

        // 10. SolarWinds Sunburst Backdoor
        ["325ab288e11f2d9f21fa2e09a74d2b380b749f187cb16e4f3414381504e973e4"] = ("Sunburst (SolarWinds Supply Chain Backdoor)", "APT Backdoor", "Backdoored SolarWinds.Orion.Core.BusinessLayer.dll deployed in 2020 supply chain attack.", "Critical", "Dec 2020")
    };

    public HashToolService(ILogger<HashToolService> logger)
    {
        _logger = logger;
    }

    public HashLookupResult LookupHash(string rawHash)
    {
        var clean = CleanHash(rawHash);
        var algo = DetermineAlgorithm(clean);

        var result = new HashLookupResult
        {
            QueryHash = clean,
            Algorithm = algo,
            IsValidFormat = algo != HashAlgorithmType.Unknown
        };

        if (!result.IsValidFormat)
        {
            result.Classification = HashThreatClassification.Unknown;
            result.ThreatName = "Invalid Hash Format";
            result.ThreatDetails = "Input does not match standard hexadecimal MD5 (32 chars), SHA-1 (40 chars), SHA-256 (64 chars), or SHA-512 (128 chars).";
            result.Severity = "Info";
            return result;
        }

        if (KnownThreatDb.TryGetValue(clean, out var threat))
        {
            if (threat.Category == "Test Signature" || threat.Severity.Contains("Clean"))
            {
                result.Classification = HashThreatClassification.Clean;
                result.ThreatName = threat.Name;
                result.ThreatCategory = threat.Category;
                result.ThreatDetails = threat.Details;
                result.Severity = "Clean";
                result.FirstSeen = threat.FirstSeen;
            }
            else
            {
                result.Classification = HashThreatClassification.KnownMalicious;
                result.ThreatName = threat.Name;
                result.ThreatCategory = threat.Category;
                result.ThreatDetails = threat.Details;
                result.Severity = threat.Severity;
                result.FirstSeen = threat.FirstSeen;
            }
        }
        else
        {
            result.Classification = HashThreatClassification.Unknown;
            result.ThreatName = "Not in Local Threat Database";
            result.ThreatCategory = "Uncataloged";
            result.ThreatDetails = "This hash is not in the local threat database. Click the VirusTotal or MalwareBazaar buttons to search live global threat intelligence.";
            result.Severity = "Info";
        }

        return result;
    }

    public async Task<FileHashCalculateResult> CalculateHashesForFileAsync(string filePath, string? expectedHash = null)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"The specified file was not found: {filePath}");
        }

        var fileInfo = new FileInfo(filePath);
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        return await CalculateHashesForStreamAsync(stream, fileInfo.Name, expectedHash);
    }

    public async Task<FileHashCalculateResult> CalculateHashesForStreamAsync(Stream stream, string fileName, string? expectedHash = null)
    {
        var result = new FileHashCalculateResult
        {
            FileName = fileName,
            ExpectedHash = expectedHash?.Trim()
        };

        using var md5 = MD5.Create();
        using var sha1 = SHA1.Create();
        using var sha256 = SHA256.Create();
        using var sha512 = SHA512.Create();

        byte[] buffer = new byte[64 * 1024]; // 64KB read buffer
        int bytesRead;
        long totalBytes = 0;

        if (stream.CanSeek) stream.Position = 0;

        while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
        {
            totalBytes += bytesRead;
            md5.TransformBlock(buffer, 0, bytesRead, null, 0);
            sha1.TransformBlock(buffer, 0, bytesRead, null, 0);
            sha256.TransformBlock(buffer, 0, bytesRead, null, 0);
            sha512.TransformBlock(buffer, 0, bytesRead, null, 0);
        }

        md5.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        sha1.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        sha512.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

        result.FileSizeBytes = totalBytes;
        result.Md5 = Convert.ToHexStringLower(md5.Hash ?? Array.Empty<byte>());
        result.Sha1 = Convert.ToHexStringLower(sha1.Hash ?? Array.Empty<byte>());
        result.Sha256 = Convert.ToHexStringLower(sha256.Hash ?? Array.Empty<byte>());
        result.Sha512 = Convert.ToHexStringLower(sha512.Hash ?? Array.Empty<byte>());

        // Check Expected Hash Matching
        if (!string.IsNullOrWhiteSpace(expectedHash))
        {
            var cleanExpected = CleanHash(expectedHash);
            if (string.Equals(result.Sha256, cleanExpected, StringComparison.OrdinalIgnoreCase))
            {
                result.IsHashMatch = true;
                result.MatchDetails = "Exact MATCH on SHA-256. File integrity is verified and authentic.";
            }
            else if (string.Equals(result.Sha1, cleanExpected, StringComparison.OrdinalIgnoreCase))
            {
                result.IsHashMatch = true;
                result.MatchDetails = "Exact MATCH on SHA-1. File integrity verified.";
            }
            else if (string.Equals(result.Md5, cleanExpected, StringComparison.OrdinalIgnoreCase))
            {
                result.IsHashMatch = true;
                result.MatchDetails = "Exact MATCH on MD5. File integrity verified.";
            }
            else if (string.Equals(result.Sha512, cleanExpected, StringComparison.OrdinalIgnoreCase))
            {
                result.IsHashMatch = true;
                result.MatchDetails = "Exact MATCH on SHA-512. File integrity verified.";
            }
            else
            {
                result.IsHashMatch = false;
                result.MatchDetails = "MISMATCH! The calculated file hash does NOT match the expected value. The file may be modified, corrupted, or tampered with.";
            }
        }

        // Correlate with threat intelligence on SHA-256
        result.ThreatIntelligence = LookupHash(result.Sha256);

        return result;
    }

    public BulkHashParseResult ParseAndAnalyzeBulkText(string text)
    {
        var result = new BulkHashParseResult();
        if (string.IsNullOrWhiteSpace(text)) return result;

        // Regex patterns for hex strings: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
        var hashRegex = new Regex(@"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b", RegexOptions.Compiled);
        var matches = hashRegex.Matches(text);

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (Match match in matches)
        {
            var h = match.Value.ToLower();
            if (seen.Add(h))
            {
                var lookup = LookupHash(h);
                result.Items.Add(lookup);
                result.TotalHashesExtracted++;

                if (lookup.Classification == HashThreatClassification.KnownMalicious)
                    result.MaliciousCount++;
                else if (lookup.Classification == HashThreatClassification.Clean)
                    result.CleanCount++;
                else
                    result.UnknownCount++;
            }
        }

        return result;
    }

    private static string CleanHash(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        return Regex.Replace(raw.Trim().ToLower(), @"[^a-f0-9]", "");
    }

    private static HashAlgorithmType DetermineAlgorithm(string cleanHash)
    {
        return cleanHash.Length switch
        {
            32 => HashAlgorithmType.MD5,
            40 => HashAlgorithmType.SHA1,
            64 => HashAlgorithmType.SHA256,
            128 => HashAlgorithmType.SHA512,
            _ => HashAlgorithmType.Unknown
        };
    }
}
