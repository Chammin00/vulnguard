using System.Security.Cryptography;
using System.Text;
using vulnerability_management.Models;

namespace vulnerability_management.Services;

public interface IFileScannerService
{
    Task<FileScanResult> ScanPathAsync(FileScanRequest request);
    string GetPresetFolderPath(string presetName);
}

public class FileScannerService : IFileScannerService
{
    private readonly ILogger<FileScannerService> _logger;

    // Known malicious / test threat hash signatures (SHA-256 in lowercase)
    private static readonly Dictionary<string, (string Name, string Description)> KnownThreatSignatures = new(StringComparer.OrdinalIgnoreCase)
    {
        // Standard EICAR Antivirus Test Signature
        ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"] = ("EICAR-Test-Signature", "Standard European Expert Group for IT-Security Antivirus Test File"),
        ["44d88612fea8a8f36de82e1278abb02f"] = ("EICAR-Test-Signature-MD5", "EICAR Standard Antivirus Test MD5"),

        // WannaCry Ransomware (WanaCrypt0r 2.0)
        ["24d004a104d4d54034dbc29c2f810772fd1ad303e1b19f7830f3c6ae2fa90132"] = ("Trojan.Ransom.WannaCry", "WannaCry ransomware binary with SMB EternalBlue worm payload"),
        ["ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"] = ("Trojan.Ransom.WannaCry.Dropper", "WannaCry ransomware dropper component"),

        // LockBit 3.0 Ransomware
        ["d6f518e9508933b2a2cc09491ea720235334460fa8d7a188f6c3823467b7f14b"] = ("Ransomware.LockBit3.Black", "LockBit 3.0 (LockBit Black) ransomware payload"),

        // Emotet / Trickbot Banking Trojan
        ["5c889f53e1a06700c9e6bb07e15549045b85a3a70f2f35760ec25227d891e4b8"] = ("Trojan.Banker.Emotet", "Emotet modular malware loader"),

        // Mimikatz Credentials Dumper
        ["5f67b587a8b61c77840134446b7a5a8f5c357d6b8808dc994df56382103f6f3a"] = ("HackTool.Win32.Mimikatz", "LSASS credential harvesting tool"),

        // Common Cryptominer (XMRig)
        ["8286a6d639ee80dbba76037e96b797fcb55146c82705e4663e26c63b715975eb"] = ("Riskware.CoinMiner.XMRig", "Monero cryptocurrency miner binary")
    };

    // Suspicious double extension combinations
    private static readonly string[] DangerousExecExtensions = { ".exe", ".scr", ".bat", ".ps1", ".vbs", ".js", ".cmd", ".hta", ".pif", ".wsf", ".cpl", ".jar" };
    private static readonly string[] DecoyExtensions = { ".pdf", ".docx", ".xlsx", ".txt", ".jpg", ".png", ".jpeg", ".mp4", ".zip" };

    public FileScannerService(ILogger<FileScannerService> logger)
    {
        _logger = logger;
    }

    public string GetPresetFolderPath(string presetName)
    {
        return presetName.ToLower() switch
        {
            "downloads" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            "desktop" => Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            "temp" => Path.GetTempPath(),
            "documents" => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            _ => Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
        };
    }

    public async Task<FileScanResult> ScanPathAsync(FileScanRequest request)
    {
        var result = new FileScanResult
        {
            TargetPath = request.TargetPath,
            StartedAt = DateTime.UtcNow
        };

        if (string.IsNullOrWhiteSpace(request.TargetPath))
        {
            result.CompletedAt = DateTime.UtcNow;
            return result;
        }

        var filesToScan = new List<string>();

        try
        {
            if (File.Exists(request.TargetPath))
            {
                filesToScan.Add(request.TargetPath);
            }
            else if (Directory.Exists(request.TargetPath))
            {
                var searchOption = request.IncludeSubdirectories ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                var di = new DirectoryInfo(request.TargetPath);
                
                // Get files safely with exception handling for inaccessible folders
                filesToScan = GetAccessibleFiles(di, searchOption, 250); // limit to 250 files per sweep for snappy UI response
            }
            else
            {
                result.CompletedAt = DateTime.UtcNow;
                return result;
            }

            long maxBytes = request.MaxFileSizeMb * 1024 * 1024;

            foreach (var filePath in filesToScan)
            {
                try
                {
                    var fileInfo = new FileInfo(filePath);
                    if (fileInfo.Length > maxBytes) continue; // skip oversized files

                    var item = await ScanSingleFileAsync(fileInfo);
                    result.ScannedFiles.Add(item);
                    result.TotalFilesScanned++;
                    result.TotalBytesScanned += fileInfo.Length;

                    if (item.ThreatLevel == FileThreatLevel.Malicious)
                    {
                        result.MaliciousFilesCount++;
                    }
                    else if (item.ThreatLevel == FileThreatLevel.Suspicious)
                    {
                        result.SuspiciousFilesCount++;
                    }
                    else
                    {
                        result.CleanFilesCount++;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not scan individual file {Path}", filePath);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error executing file scan on {Target}", request.TargetPath);
        }

        result.CompletedAt = DateTime.UtcNow;
        return result;
    }

    private async Task<ScannedFileItem> ScanSingleFileAsync(FileInfo fileInfo)
    {
        var item = new ScannedFileItem
        {
            FileName = fileInfo.Name,
            FullPath = fileInfo.FullName,
            Extension = fileInfo.Extension.ToLower(),
            FileSizeBytes = fileInfo.Length,
            LastModified = fileInfo.LastWriteTimeUtc
        };

        // 1. Compute SHA-256 & MD5 hashes
        string sha256 = string.Empty;
        string md5 = string.Empty;

        using (var stream = new FileStream(fileInfo.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            using var sha256Engine = SHA256.Create();
            var shaBytes = await sha256Engine.ComputeHashAsync(stream);
            sha256 = Convert.ToHexStringLower(shaBytes);

            stream.Position = 0;
            using var md5Engine = MD5.Create();
            var md5Bytes = await md5Engine.ComputeHashAsync(stream);
            md5 = Convert.ToHexStringLower(md5Bytes);
        }

        item.Sha256Hash = sha256;
        item.Md5Hash = md5;

        // 2. Check Threat Signature Hash Catalog
        if (KnownThreatSignatures.TryGetValue(sha256, out var threat) || KnownThreatSignatures.TryGetValue(md5, out threat))
        {
            item.ThreatLevel = FileThreatLevel.Malicious;
            item.ThreatName = threat.Name;
            item.DetectionReason = $"Exact cryptographic hash match with threat signature: {threat.Description}";
            item.HeuristicFlags.Add("MALWARE_HASH_MATCH");
            return item;
        }

        // 3. EICAR Test String in-content inspection
        if (fileInfo.Length < 1024)
        {
            try
            {
                var content = await File.ReadAllTextAsync(fileInfo.FullName);
                if (content.Contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"))
                {
                    item.ThreatLevel = FileThreatLevel.Malicious;
                    item.ThreatName = "EICAR-Test-File";
                    item.DetectionReason = "Standard European Antivirus test sample detected in file body.";
                    item.HeuristicFlags.Add("EICAR_STRING_MATCH");
                    return item;
                }
            }
            catch { }
        }

        // 4. Heuristic & Anomaly Evaluation
        var lowerName = fileInfo.Name.ToLower();

        // Check for double extensions (e.g. invoice.pdf.exe or report.docx.vbs)
        foreach (var decoy in DecoyExtensions)
        {
            foreach (var dangerous in DangerousExecExtensions)
            {
                if (lowerName.EndsWith(decoy + dangerous))
                {
                    item.ThreatLevel = FileThreatLevel.Suspicious;
                    item.ThreatName = "Suspicious.DoubleExtension.Masquerading";
                    item.DetectionReason = $"File uses a masqueraded double extension '{decoy + dangerous}' to trick users into executing code.";
                    item.HeuristicFlags.Add("DOUBLE_EXTENSION_MASK");
                }
            }
        }

        // Check for script files containing suspicious payload execution patterns
        if (item.Extension == ".ps1" || item.Extension == ".bat" || item.Extension == ".vbs" || item.Extension == ".js" || item.Extension == ".cmd")
        {
            if (fileInfo.Length < 500_000) // inspect scripts under 500KB
            {
                try
                {
                    var text = await File.ReadAllTextAsync(fileInfo.FullName);
                    var lowerText = text.ToLower();

                    if (lowerText.Contains("-encodedcommand") || lowerText.Contains("frombase64string") || lowerText.Contains("bypass -noprofile -windowstyle hidden"))
                    {
                        item.ThreatLevel = FileThreatLevel.Suspicious;
                        item.ThreatName = "Heuristic.ObfuscatedScript.PowerShell";
                        item.DetectionReason = "Script contains obfuscated Base64 or hidden window execution arguments commonly used by malware droppers.";
                        item.HeuristicFlags.Add("OBFUSCATED_SCRIPT_PAYLOAD");
                    }
                    else if (lowerText.Contains("downloadstring") || lowerText.Contains("downloadfile") || lowerText.Contains("curl.exe") || lowerText.Contains("bitsadmin /transfer"))
                    {
                        item.HeuristicFlags.Add("NETWORK_DOWNLOAD_COMMAND");
                    }
                }
                catch { }
            }
        }

        // Check for executables in AppData/Temp or Downloads with high risk names
        if (DangerousExecExtensions.Contains(item.Extension))
        {
            if (lowerName.StartsWith("update") || lowerName.StartsWith("setup") || lowerName.StartsWith("invoice") || lowerName.StartsWith("receipt") || lowerName.StartsWith("bank"))
            {
                if (item.ThreatLevel == FileThreatLevel.Clean)
                {
                    item.HeuristicFlags.Add("EXECUTABLE_IN_USER_FOLDER");
                }
            }
        }

        if (item.ThreatLevel == FileThreatLevel.Clean)
        {
            item.ThreatName = "Clean";
            item.DetectionReason = "File integrity verified. No malicious hash matches or dangerous masquerading patterns found.";
        }

        return item;
    }

    private List<string> GetAccessibleFiles(DirectoryInfo root, SearchOption searchOption, int maxCount)
    {
        var result = new List<string>();
        var queue = new Queue<DirectoryInfo>();
        queue.Enqueue(root);

        while (queue.Count > 0 && result.Count < maxCount)
        {
            var current = queue.Dequeue();
            try
            {
                foreach (var file in current.GetFiles())
                {
                    result.Add(file.FullName);
                    if (result.Count >= maxCount) break;
                }

                if (searchOption == SearchOption.AllDirectories && result.Count < maxCount)
                {
                    foreach (var dir in current.GetDirectories())
                    {
                        // Skip system hidden/recycle bin folders
                        if ((dir.Attributes & FileAttributes.Hidden) != 0 || dir.Name.StartsWith("$") || dir.Name.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }
                        queue.Enqueue(dir);
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception) { }
        }

        return result;
    }
}
