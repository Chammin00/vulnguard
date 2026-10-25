using vulnerability_management.Models;

namespace vulnerability_management.Data;

public static class DbInitializer
{
    public static void Initialize(AppDbContext context)
    {
        context.Database.EnsureCreated();

        if (context.Assets.Any())
        {
            return; // DB has been seeded
        }

        // 1. Seed SLA Policies
        var slaPolicies = new List<SlaPolicy>
        {
            new() { Severity = SeverityLevel.Critical, MaxDaysToRemediate = 7, Description = "Critical vulnerabilities must be remediated within 7 days." },
            new() { Severity = SeverityLevel.High, MaxDaysToRemediate = 14, Description = "High severity vulnerabilities must be remediated within 14 days." },
            new() { Severity = SeverityLevel.Medium, MaxDaysToRemediate = 30, Description = "Medium severity vulnerabilities must be remediated within 30 days." },
            new() { Severity = SeverityLevel.Low, MaxDaysToRemediate = 90, Description = "Low severity vulnerabilities must be remediated within 90 days." },
            new() { Severity = SeverityLevel.Info, MaxDaysToRemediate = 180, Description = "Informational items should be tracked." }
        };
        context.SlaPolicies.AddRange(slaPolicies);
        context.SaveChanges();

        // 2. Seed Real-world CVE Catalog
        var vulnerabilities = new List<Vulnerability>
        {
            new()
            {
                CveId = "CVE-2021-44228",
                Title = "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
                Description = "Apache Log4j2 versions 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints, allowing remote unauthenticated code execution.",
                Severity = SeverityLevel.Critical,
                CvssScore = 10.0,
                CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                EpssScore = 0.975,
                IsInCisaKev = true,
                AffectedComponent = "Apache Log4j <= 2.14.1",
                RemediationGuidance = "Upgrade to Log4j 2.17.1 or higher, or set log4j2.formatMsgNoLookups=true in JVM arguments.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                PublishedDate = new DateTime(2021, 12, 10)
            },
            new()
            {
                CveId = "CVE-2023-34362",
                Title = "Progress MOVEit Transfer SQL Injection Vulnerability",
                Description = "SQL injection vulnerability in MOVEit Transfer web application that could allow an unauthenticated attacker to gain unauthorized access to the database and execute arbitrary SQL commands.",
                Severity = SeverityLevel.Critical,
                CvssScore = 9.8,
                CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                EpssScore = 0.942,
                IsInCisaKev = true,
                AffectedComponent = "MOVEit Transfer < 2023.0.1",
                RemediationGuidance = "Apply May 2023 / June 2023 Progress security patch immediately and review IIS logs for unauthorized payload delivery.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2023-34362",
                PublishedDate = new DateTime(2023, 6, 2)
            },
            new()
            {
                CveId = "CVE-2023-4966",
                Title = "Citrix NetScaler ADC / Gateway Information Disclosure (Citrix Bleed)",
                Description = "Sensitive information disclosure in NetScaler ADC and Gateway allows unauthenticated attackers to hijack active user sessions including MFA tokens.",
                Severity = SeverityLevel.Critical,
                CvssScore = 9.4,
                CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                EpssScore = 0.961,
                IsInCisaKev = true,
                AffectedComponent = "Citrix NetScaler ADC / Gateway < 13.1-49.13",
                RemediationGuidance = "Apply firmware upgrade and terminate all active ICA/AAA sessions to invalidate compromised session tokens.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2023-4966",
                PublishedDate = new DateTime(2023, 10, 10)
            },
            new()
            {
                CveId = "CVE-2022-22965",
                Title = "Spring Framework Data Binding Remote Code Execution (Spring4Shell)",
                Description = "Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via data binding with ClassLoader access.",
                Severity = SeverityLevel.Critical,
                CvssScore = 9.8,
                CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                EpssScore = 0.884,
                IsInCisaKev = true,
                AffectedComponent = "Spring Framework 5.3.0 to 5.3.17, 5.2.0 to 5.2.19",
                RemediationGuidance = "Upgrade Spring Framework to 5.3.18+ or 5.2.20+, or upgrade Spring Boot to 2.6.6+ / 2.5.12+.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
                PublishedDate = new DateTime(2022, 4, 1)
            },
            new()
            {
                CveId = "CVE-2021-34527",
                Title = "Windows Print Spooler Remote Code Execution (PrintNightmare)",
                Description = "Remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations.",
                Severity = SeverityLevel.High,
                CvssScore = 8.8,
                CvssVector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                EpssScore = 0.890,
                IsInCisaKev = true,
                AffectedComponent = "Windows Server Print Spooler",
                RemediationGuidance = "Install KB5004945 / latest cumulative update or disable Print Spooler on non-print server Domain Controllers.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
                PublishedDate = new DateTime(2021, 7, 1)
            },
            new()
            {
                CveId = "CVE-2023-46604",
                Title = "Apache ActiveMQ OpenWire Remote Code Execution",
                Description = "The OpenWire protocol marshaler in Apache ActiveMQ allows remote code execution via ClassPathXmlApplicationContext manipulation.",
                Severity = SeverityLevel.Critical,
                CvssScore = 9.8,
                CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                EpssScore = 0.958,
                IsInCisaKev = true,
                AffectedComponent = "Apache ActiveMQ < 5.18.3, < 5.17.6",
                RemediationGuidance = "Upgrade to Apache ActiveMQ 5.18.3, 5.17.6, 5.16.7 or 5.15.16.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2023-46604",
                PublishedDate = new DateTime(2023, 10, 27)
            },
            new()
            {
                CveId = "CVE-2022-31629",
                Title = "PHP Cookie Pre-auth Hash Collision Injection",
                Description = "In PHP versions prior to 8.1.8, standard cookie parsing logic fails to validate internal field lengths leading to pre-auth array corruption.",
                Severity = SeverityLevel.High,
                CvssScore = 7.5,
                CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                EpssScore = 0.124,
                IsInCisaKev = false,
                AffectedComponent = "PHP 8.1.0 to 8.1.7",
                RemediationGuidance = "Upgrade PHP engine to version 8.1.8 or higher.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2022-31629",
                PublishedDate = new DateTime(2022, 9, 28)
            },
            new()
            {
                CveId = "CVE-2023-22515",
                Title = "Atlassian Confluence Data Center & Server Broken Access Control",
                Description = "Improper authorization vulnerability in Confluence Data Center and Server allows unauthenticated attackers to create unauthorized admin accounts.",
                Severity = SeverityLevel.Critical,
                CvssScore = 10.0,
                CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                EpssScore = 0.971,
                IsInCisaKev = true,
                AffectedComponent = "Atlassian Confluence 8.0.0 to 8.5.1",
                RemediationGuidance = "Upgrade Confluence to 8.3.3, 8.4.3, 8.5.2 or newer, and check /setup/* setup wizard request logs.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2023-22515",
                PublishedDate = new DateTime(2023, 10, 4)
            },
            new()
            {
                CveId = "CVE-2023-38606",
                Title = "OpenSSL AES-GCM Key Stream Reuse Flaw",
                Description = "A flaw in crypto block chaining within OpenSSL crypto engine allows theoretical plaintext recovery under specific multi-threaded cipher re-init conditions.",
                Severity = SeverityLevel.Medium,
                CvssScore = 5.9,
                CvssVector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                EpssScore = 0.045,
                IsInCisaKev = false,
                AffectedComponent = "OpenSSL 3.0.0 to 3.0.9",
                RemediationGuidance = "Upgrade OpenSSL to version 3.0.10 or 3.1.2.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2023-38606",
                PublishedDate = new DateTime(2023, 8, 14)
            },
            new()
            {
                CveId = "CVE-2024-1709",
                Title = "ConnectWise ScreenConnect Authentication Bypass",
                Description = "Authentication bypass using an alternate path or channel in ConnectWise ScreenConnect allows an attacker with network access to execute administrative actions and deploy malware.",
                Severity = SeverityLevel.Critical,
                CvssScore = 10.0,
                CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                EpssScore = 0.973,
                IsInCisaKev = true,
                AffectedComponent = "ScreenConnect < 23.9.8",
                RemediationGuidance = "Upgrade to ScreenConnect 23.9.8 or higher immediately.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2024-1709",
                PublishedDate = new DateTime(2024, 2, 20)
            },
            new()
            {
                CveId = "CVE-2023-27997",
                Title = "Fortinet FortiOS Heap-based Buffer Overflow (XORtigate)",
                Description = "A heap-based buffer overflow in FortiOS and FortiProxy SSL-VPN module may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.",
                Severity = SeverityLevel.Critical,
                CvssScore = 9.8,
                CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                EpssScore = 0.966,
                IsInCisaKev = true,
                AffectedComponent = "FortiOS SSL-VPN",
                RemediationGuidance = "Update to FortiOS 7.2.5, 7.0.12, 6.4.13 or disable SSL-VPN interface.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2023-27997",
                PublishedDate = new DateTime(2023, 6, 12)
            },
            new()
            {
                CveId = "CVE-2024-21887",
                Title = "Ivanti Connect Secure Command Injection Vulnerability",
                Description = "A command injection vulnerability in web components of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure allows an authenticated administrator to send specially crafted requests and execute arbitrary commands.",
                Severity = SeverityLevel.High,
                CvssScore = 9.1,
                CvssVector = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
                EpssScore = 0.968,
                IsInCisaKev = true,
                AffectedComponent = "Ivanti Connect Secure / Policy Secure",
                RemediationGuidance = "Apply official Ivanti patch or mitigation XML file provided in security advisory.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2024-21887",
                PublishedDate = new DateTime(2024, 1, 12)
            },
            new()
            {
                CveId = "CVE-2023-38545",
                Title = "cURL SOCKS5 Heap-based Buffer Overflow",
                Description = "This flaw makes curl overflow a heap-based buffer in the SOCKS5 proxy handshake when curl is told to pass along the hostname to the SOCKS5 proxy.",
                Severity = SeverityLevel.High,
                CvssScore = 8.8,
                CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                EpssScore = 0.285,
                IsInCisaKev = false,
                AffectedComponent = "libcurl 7.69.0 to 8.3.0",
                RemediationGuidance = "Upgrade curl/libcurl to 8.4.0 or avoid using socks5h:// host proxy schemes.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2023-38545",
                PublishedDate = new DateTime(2023, 10, 11)
            },
            new()
            {
                CveId = "CVE-2022-26134",
                Title = "Atlassian Confluence OGNL Injection Remote Code Execution",
                Description = "An OGNL injection vulnerability in Confluence Server and Data Center allows an unauthenticated attacker to execute arbitrary code.",
                Severity = SeverityLevel.Critical,
                CvssScore = 9.8,
                CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                EpssScore = 0.974,
                IsInCisaKev = true,
                AffectedComponent = "Atlassian Confluence < 7.18.1",
                RemediationGuidance = "Upgrade Confluence to 7.18.1, 7.17.4, 7.16.5, 7.15.3, 7.14.3 or newer.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2022-26134",
                PublishedDate = new DateTime(2022, 6, 2)
            },
            new()
            {
                CveId = "CVE-2021-26855",
                Title = "Microsoft Exchange Server SSRF (ProxyLogon)",
                Description = "A server-side request forgery (SSRF) vulnerability in Microsoft Exchange Server allows remote unauthenticated attackers to authenticate as the Exchange server.",
                Severity = SeverityLevel.Critical,
                CvssScore = 9.8,
                CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                EpssScore = 0.975,
                IsInCisaKev = true,
                AffectedComponent = "Microsoft Exchange Server 2013/2016/2019",
                RemediationGuidance = "Install March 2021 Microsoft Security Updates (KB5000871) immediately.",
                ReferenceUrl = "https://nvd.nist.gov/vuln/detail/CVE-2021-26855",
                PublishedDate = new DateTime(2021, 3, 2)
            }
        };

        context.Vulnerabilities.AddRange(vulnerabilities);
        context.SaveChanges();

        // 3. Seed Enterprise Assets
        var assets = new List<Asset>
        {
            new()
            {
                Hostname = "prd-edge-gateway-01.corp",
                IpAddress = "10.0.1.1",
                MacAddress = "00:50:56:A1:2B:01",
                OperatingSystem = "FortiOS 7.0.10",
                Environment = EnvironmentType.DMZ,
                Criticality = CriticalityTier.Tier1_MissionCritical,
                Owner = "SecOps / Network Team",
                Tags = "gateway, vpn, perimeter, dmz",
                OpenPorts = "443/HTTPS (SSL-VPN), 8443/HTTPS (Admin), 22/SSH",
                CreatedAt = DateTime.UtcNow.AddMonths(-6),
                LastScannedAt = DateTime.UtcNow.AddDays(-1)
            },
            new()
            {
                Hostname = "prd-auth-dc01.corp",
                IpAddress = "10.0.10.5",
                MacAddress = "00:50:56:A1:2B:10",
                OperatingSystem = "Windows Server 2022 Standard",
                Environment = EnvironmentType.Production,
                Criticality = CriticalityTier.Tier1_MissionCritical,
                Owner = "Identity & Infrastructure",
                Tags = "ad, domain-controller, kerberos, production",
                OpenPorts = "53/DNS, 88/Kerberos, 135/RPC, 389/LDAP, 445/SMB, 3389/RDP",
                CreatedAt = DateTime.UtcNow.AddMonths(-8),
                LastScannedAt = DateTime.UtcNow.AddDays(-2)
            },
            new()
            {
                Hostname = "prd-web-app01.internal",
                IpAddress = "10.0.20.14",
                MacAddress = "00:50:56:B2:3C:22",
                OperatingSystem = "Ubuntu 22.04 LTS",
                Environment = EnvironmentType.Production,
                Criticality = CriticalityTier.Tier2_BusinessImportant,
                Owner = "Web Platform Engineering",
                Tags = "web, java, spring-boot, nginx, production",
                OpenPorts = "80/HTTP, 443/HTTPS, 8080/HTTP-Proxy, 22/SSH",
                CreatedAt = DateTime.UtcNow.AddMonths(-4),
                LastScannedAt = DateTime.UtcNow.AddHours(-12)
            },
            new()
            {
                Hostname = "prd-wiki-confluence.corp",
                IpAddress = "10.0.20.25",
                MacAddress = "00:50:56:B2:3C:40",
                OperatingSystem = "Red Hat Enterprise Linux 8.8",
                Environment = EnvironmentType.Production,
                Criticality = CriticalityTier.Tier2_BusinessImportant,
                Owner = "IT Enterprise Apps",
                Tags = "confluence, collaboration, java, production",
                OpenPorts = "80/HTTP, 443/HTTPS, 8090/Confluence, 22/SSH",
                CreatedAt = DateTime.UtcNow.AddMonths(-5),
                LastScannedAt = DateTime.UtcNow.AddDays(-3)
            },
            new()
            {
                Hostname = "stg-file-transfer01.corp",
                IpAddress = "10.0.30.8",
                MacAddress = "00:50:56:C3:4D:15",
                OperatingSystem = "Windows Server 2019 Datacenter",
                Environment = EnvironmentType.Staging,
                Criticality = CriticalityTier.Tier3_Standard,
                Owner = "Data Integration Team",
                Tags = "sftp, moveit, staging, transfer",
                OpenPorts = "21/FTP, 22/SFTP, 80/HTTP, 443/HTTPS",
                CreatedAt = DateTime.UtcNow.AddMonths(-3),
                LastScannedAt = DateTime.UtcNow.AddDays(-1)
            },
            new()
            {
                Hostname = "dev-queue-msg01.dev",
                IpAddress = "10.0.40.12",
                MacAddress = "00:50:56:D4:5E:80",
                OperatingSystem = "Debian 12 Bookworm",
                Environment = EnvironmentType.Development,
                Criticality = CriticalityTier.Tier4_Low,
                Owner = "Backend Services Team",
                Tags = "activemq, jms, broker, dev",
                OpenPorts = "61616/OpenWire, 8161/WebConsole, 5672/AMQP, 22/SSH",
                CreatedAt = DateTime.UtcNow.AddMonths(-2),
                LastScannedAt = DateTime.UtcNow.AddHours(-6)
            },
            new()
            {
                Hostname = "prd-db-cluster01.internal",
                IpAddress = "10.0.10.50",
                MacAddress = "00:50:56:E5:6F:99",
                OperatingSystem = "Ubuntu 24.04 LTS",
                Environment = EnvironmentType.Production,
                Criticality = CriticalityTier.Tier1_MissionCritical,
                Owner = "Database Reliability Engineering",
                Tags = "postgresql, redis, production, database",
                OpenPorts = "5432/Postgres, 6379/Redis, 22/SSH",
                CreatedAt = DateTime.UtcNow.AddMonths(-7),
                LastScannedAt = DateTime.UtcNow.AddDays(-1)
            }
        };

        context.Assets.AddRange(assets);
        context.SaveChanges();

        // 4. Seed Vulnerability Findings with SLA Tracking
        var now = DateTime.UtcNow;

        var vLog4j = vulnerabilities.First(v => v.CveId == "CVE-2021-44228");
        var vMoveit = vulnerabilities.First(v => v.CveId == "CVE-2023-34362");
        var vCitrix = vulnerabilities.First(v => v.CveId == "CVE-2023-4966");
        var vSpring = vulnerabilities.First(v => v.CveId == "CVE-2022-22965");
        var vPrint = vulnerabilities.First(v => v.CveId == "CVE-2021-34527");
        var vActiveMQ = vulnerabilities.First(v => v.CveId == "CVE-2023-46604");
        var vConfluence = vulnerabilities.First(v => v.CveId == "CVE-2023-22515");
        var vOpenSsl = vulnerabilities.First(v => v.CveId == "CVE-2023-38606");
        var vForti = vulnerabilities.First(v => v.CveId == "CVE-2023-27997");
        var vCurl = vulnerabilities.First(v => v.CveId == "CVE-2023-38545");

        var aGateway = assets[0];
        var aDc = assets[1];
        var aWebApp = assets[2];
        var aWiki = assets[3];
        var aTransfer = assets[4];
        var aMsg = assets[5];
        var aDb = assets[6];

        var findings = new List<VulnerabilityFinding>
        {
            // 1. Critical FortiOS flaw on Gateway - Open, SLA Breached
            new()
            {
                AssetId = aGateway.Id,
                VulnerabilityId = vForti.Id,
                Status = FindingStatus.Open,
                AffectedPort = "443/HTTPS",
                ProofOfConcept = "SSL-VPN web interface banner identified as FortiOS 7.0.10 vulnerable to heap overflow in auth handler.",
                AssignedTo = "Alex Miller (SecOps)",
                DiscoveredAt = now.AddDays(-12),
                DueDate = now.AddDays(-5), // Breached
                RemediationNotes = "Awaiting maintenance window scheduled for tonight to flash firmware 7.0.12.",
                ActivityLogs = new List<ActivityLog>
                {
                    new() { Action = "Discovered", Details = "Vulnerability identified during automated perimeter scan.", User = "VulnGuard Engine", Timestamp = now.AddDays(-12) },
                    new() { Action = "Assigned", Details = "Assigned finding to Alex Miller (SecOps).", User = "SecOps Lead", Timestamp = now.AddDays(-11) }
                }
            },

            // 2. Critical Log4Shell on Web App - In Progress
            new()
            {
                AssetId = aWebApp.Id,
                VulnerabilityId = vLog4j.Id,
                Status = FindingStatus.InProgress,
                AffectedPort = "8080/HTTP",
                ProofOfConcept = "JNDI payload header reflection trigger matched log4j-core 2.14.1 dependency in app lib classpath.",
                AssignedTo = "Sarah Connor (AppSec)",
                DiscoveredAt = now.AddDays(-3),
                DueDate = now.AddDays(4), // Within SLA
                RemediationNotes = "Pull request #418 created in backend repo updating log4j to 2.20.0. Staging tests passing.",
                ActivityLogs = new List<ActivityLog>
                {
                    new() { Action = "Discovered", Details = "Vulnerability flagged by host package analyzer.", User = "VulnGuard Engine", Timestamp = now.AddDays(-3) },
                    new() { Action = "Status Changed", Details = "Status moved from Open to InProgress. Branch fix staged.", User = "Sarah Connor", Timestamp = now.AddDays(-1) }
                }
            },

            // 3. Spring4Shell on Web App - Open
            new()
            {
                AssetId = aWebApp.Id,
                VulnerabilityId = vSpring.Id,
                Status = FindingStatus.Open,
                AffectedPort = "80/HTTP",
                ProofOfConcept = "Spring Framework classloader manipulation binding enabled on OpenJDK 11 runtime.",
                AssignedTo = "Sarah Connor (AppSec)",
                DiscoveredAt = now.AddDays(-2),
                DueDate = now.AddDays(5),
                RemediationNotes = "Targeted for deployment alongside Log4j upgrade in release 2.14.",
                ActivityLogs = new List<ActivityLog>
                {
                    new() { Action = "Discovered", Details = "Discovered during web endpoint scan.", User = "VulnGuard Engine", Timestamp = now.AddDays(-2) }
                }
            },

            // 4. Confluence Access Control on Wiki - In Progress
            new()
            {
                AssetId = aWiki.Id,
                VulnerabilityId = vConfluence.Id,
                Status = FindingStatus.InProgress,
                AffectedPort = "8090/Confluence",
                ProofOfConcept = "/setup/setupadministrator.action endpoint exposed without proper session verification on Confluence 8.5.1.",
                AssignedTo = "David Chang (IT Ops)",
                DiscoveredAt = now.AddDays(-4),
                DueDate = now.AddDays(3),
                RemediationNotes = "Temporary nginx block applied to /setup/* path while official 8.5.2 patch is downloaded.",
                ActivityLogs = new List<ActivityLog>
                {
                    new() { Action = "Discovered", Details = "Automated scanner identified setup path exposure.", User = "VulnGuard Engine", Timestamp = now.AddDays(-4) },
                    new() { Action = "Mitigation Added", Details = "Nginx WAF rule applied to drop setup requests.", User = "David Chang", Timestamp = now.AddDays(-3) }
                }
            },

            // 5. ActiveMQ OpenWire RCE on Dev Queue - Open
            new()
            {
                AssetId = aMsg.Id,
                VulnerabilityId = vActiveMQ.Id,
                Status = FindingStatus.Open,
                AffectedPort = "61616/OpenWire",
                ProofOfConcept = "ActiveMQ OpenWire service banner 5.17.2 detected on TCP port 61616.",
                AssignedTo = "Elena Rostova (DevOps)",
                DiscoveredAt = now.AddDays(-1),
                DueDate = now.AddDays(6),
                RemediationNotes = "Development environment broker will be upgraded to 5.18.3 in tomorrow's pipeline.",
                ActivityLogs = new List<ActivityLog>
                {
                    new() { Action = "Discovered", Details = "Detected during subnet inventory scan.", User = "VulnGuard Engine", Timestamp = now.AddDays(-1) }
                }
            },

            // 6. MOVEit Transfer SQLi on Staging - Remediated
            new()
            {
                AssetId = aTransfer.Id,
                VulnerabilityId = vMoveit.Id,
                Status = FindingStatus.Remediated,
                AffectedPort = "443/HTTPS",
                ProofOfConcept = "MOVEit web interface version 2023.0.0 vulnerable to guest session SQLi.",
                AssignedTo = "Alex Miller (SecOps)",
                DiscoveredAt = now.AddDays(-20),
                DueDate = now.AddDays(-13),
                ResolvedAt = now.AddDays(-15),
                RemediationNotes = "Progress Service Pack 2023.0.2 applied and verified with re-scan.",
                ActivityLogs = new List<ActivityLog>
                {
                    new() { Action = "Discovered", Details = "Discovered in routine staging scan.", User = "VulnGuard Engine", Timestamp = now.AddDays(-20) },
                    new() { Action = "Remediated", Details = "Hotfix applied and verification scan completed successfully.", User = "Alex Miller", Timestamp = now.AddDays(-15) }
                }
            },

            // 7. PrintNightmare on Domain Controller - Remediated
            new()
            {
                AssetId = aDc.Id,
                VulnerabilityId = vPrint.Id,
                Status = FindingStatus.Remediated,
                AffectedPort = "445/SMB",
                ProofOfConcept = "Spooler service spoolsv.exe active and listening on RPC endpoints.",
                AssignedTo = "James Kelly (SysAdmin)",
                DiscoveredAt = now.AddDays(-30),
                DueDate = now.AddDays(-16),
                ResolvedAt = now.AddDays(-25),
                RemediationNotes = "Print Spooler service disabled via Group Policy on all domain controllers.",
                ActivityLogs = new List<ActivityLog>
                {
                    new() { Action = "Discovered", Details = "Detected during Active Directory security audit.", User = "VulnGuard Engine", Timestamp = now.AddDays(-30) },
                    new() { Action = "Remediated", Details = "Print Spooler service disabled via GPO.", User = "James Kelly", Timestamp = now.AddDays(-25) }
                }
            },

            // 8. OpenSSL Flaw on Database Server - Accepted Risk
            new()
            {
                AssetId = aDb.Id,
                VulnerabilityId = vOpenSsl.Id,
                Status = FindingStatus.AcceptedRisk,
                AffectedPort = "5432/Postgres",
                ProofOfConcept = "Postgres TLS library statically linked with OpenSSL 3.0.8.",
                AssignedTo = "Security Review Board",
                DiscoveredAt = now.AddDays(-18),
                DueDate = now.AddDays(12),
                RiskAcceptanceReason = "Database server is isolated on a non-routable private VPC subnet with strict mTLS authentication and no external internet exposure. Risk accepted until next major OS upgrade cycle.",
                ActivityLogs = new List<ActivityLog>
                {
                    new() { Action = "Discovered", Details = "Package inspection finding.", User = "VulnGuard Engine", Timestamp = now.AddDays(-18) },
                    new() { Action = "Risk Accepted", Details = "CISO and SecOps board approved risk acceptance exception EX-2024-008.", User = "Security Committee", Timestamp = now.AddDays(-10) }
                }
            },

            // 9. cURL Buffer Overflow on Web App - Open
            new()
            {
                AssetId = aWebApp.Id,
                VulnerabilityId = vCurl.Id,
                Status = FindingStatus.Open,
                AffectedPort = "22/SSH",
                ProofOfConcept = "curl 8.2.1 installed in base system OS package manager.",
                AssignedTo = "Sarah Connor (AppSec)",
                DiscoveredAt = now.AddDays(-5),
                DueDate = now.AddDays(9),
                RemediationNotes = "apt-get upgrade scheduled during monthly maintenance.",
                ActivityLogs = new List<ActivityLog>
                {
                    new() { Action = "Discovered", Details = "OS package baseline audit.", User = "VulnGuard Engine", Timestamp = now.AddDays(-5) }
                }
            }
        };

        context.VulnerabilityFindings.AddRange(findings);
        context.SaveChanges();

        // 5. Seed Scan Jobs History
        var scanJobs = new List<ScanJob>
        {
            new()
            {
                ScanName = "Perimeter DMZ Nightly Sweep",
                Target = "10.0.1.0/24",
                Status = ScanStatus.Completed,
                ProgressPercent = 100,
                AssetsScanned = 12,
                VulnerabilitiesFound = 3,
                StartedAt = now.AddHours(-14),
                FinishedAt = now.AddHours(-13).AddMinutes(-40),
                LogOutput = "[INFO] Starting perimeter scan on 10.0.1.0/24\n[INFO] 12 live hosts identified.\n[ALERT] Host 10.0.1.1 port 443 detected FortiOS SSL-VPN matching CVE-2023-27997.\n[SUCCESS] Scan job finished in 20 minutes."
            },
            new()
            {
                ScanName = "Production Core Network Audit",
                Target = "10.0.10.0/24, 10.0.20.0/24",
                Status = ScanStatus.Completed,
                ProgressPercent = 100,
                AssetsScanned = 28,
                VulnerabilitiesFound = 5,
                StartedAt = now.AddDays(-1),
                FinishedAt = now.AddDays(-1).AddMinutes(45),
                LogOutput = "[INFO] Initiated TCP full port probe.\n[INFO] Probed 28 servers across production zones.\n[WARN] High severity CVEs identified on 10.0.20.14 and 10.0.20.25.\n[SUCCESS] Findings recorded to central database."
            },
            new()
            {
                ScanName = "Staging & Dev Environment Check",
                Target = "10.0.30.0/24, 10.0.40.0/24",
                Status = ScanStatus.Completed,
                ProgressPercent = 100,
                AssetsScanned = 16,
                VulnerabilitiesFound = 2,
                StartedAt = now.AddDays(-3),
                FinishedAt = now.AddDays(-3).AddMinutes(22),
                LogOutput = "[INFO] Scanned staging network.\n[INFO] OpenWire broker identified on 10.0.40.12.\n[SUCCESS] Completed."
            }
        };

        context.ScanJobs.AddRange(scanJobs);
        context.SaveChanges();
    }
}
