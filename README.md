# 🛡️ VulnGuard Enterprise - Vulnerability Management Platform

VulnGuard is an enterprise-grade Vulnerability Management and Attack Surface Monitoring web application built on **ASP.NET Core (.NET 10)**, **Entity Framework Core**, and **SQLite**. It offers end-to-end vulnerability lifecycle tracking, active socket network scanning, SLA remediation workflows, threat intelligence feeds (CISA KEV, CVSS v3.1, EPSS), and unified regulatory compliance reporting.

---

## 🌟 Key Features

### 1. Executive Dashboard & Risk Analytics
- **Fleet-Wide Risk Score**: Dynamic 0–100 index weighted by CVSS scores, asset criticality tiers, and weaponization metrics.
- **Real-Time KPIs**: Total Assets, Active Findings, Critical & High counts, Overdue SLA Tickets, and Mean Time to Remediate (MTTR).
- **Interactive Visualizations**:
  - Donut chart of severity breakdown (Critical, High, Medium, Low).
  - 30-day vulnerability discovery vs. resolution velocity trend lines.
  - Top 5 most vulnerable fleet assets & critical CVE threats.
  - Active CISA Known Exploited Vulnerabilities (KEV) banner alerts.

### 2. Asset Management & Attack Surface CMDB
- Detailed inventory tracking: Hostname, IP Address, MAC, Operating System, Environment (*Production, Staging, Dev, DMZ*), Criticality Tier (*Tier 1 Mission-Critical to Tier 4 Low*), and Owner/Custodian.
- Open network ports & services fingerprinting (*SSH, HTTP, HTTPS, RDP, SMB, Postgres, MySQL, Redis, ActiveMQ, Confluence*).
- Individual asset profile inspection and risk score breakdown.
- Export entire asset inventory to formatted JSON.

### 3. Vulnerability Catalog & CVE Tracker
- Master CVE database with CVSS v3.1 base scores, severity vectors, EPSS (Exploit Prediction Scoring System) likelihood, and CISA KEV flags.
- Lifecycle state machine: **Open**, **In Progress**, **Remediated**, **Accepted Risk (Exception)**, and **False Positive**.
- Detailed finding view with proof-of-concept scanner evidence, official remediation guidance, assignee ownership, and complete activity audit history.
- One-click CSV export of all findings for spreadsheets and external audits.

### 4. Vulnerability Scanner Engine
- **Target Prober**: Run scans against single IPs, hostnames, or subnet ranges.
- **Port Probing & Banner Grabbing**: Socket-level TCP prober detecting live open services.
- **Signature CVE Matcher**: Evaluates service signatures against known vulnerabilities (e.g., Log4Shell, Citrix Bleed, MoveIT SQLi, Spring4Shell, ActiveMQ RCE).
- **Live Terminal Console**: Real-time progress bar, live socket logs, and findings counters with AJAX streaming.

### 5. SLA & Remediation Workflow
- Configurable SLA thresholds per severity level (Default: Critical = 7 days, High = 14 days, Medium = 30 days, Low = 90 days).
- Real-time SLA countdown and overdue breach alerts.
- Filterable views for Overdue tickets, In-Progress work, and approved Risk Acceptance exceptions.

### 6. Threat Intelligence (CISA KEV Feed)
- Real-time stream of CISA Known Exploited Vulnerabilities with active exploitation tags and severity metrics.
- Direct CVE lookup inspector with immediate fleet correlation.

### 7. Unified Compliance & Executive Reporting
- **Multi-Framework Audit Mapping**: Controls pre-mapped for **SOC 2 Type II** (CC6.6 & CC7.1), **PCI-DSS v4.0** (Req 6.3.1 & 11.3.1), **ISO/IEC 27001:2022** (A.8.8), and **NIST CSF 2.0** (DE.CM-08 & RS.MI-03).
- **Executive Security Posture Briefing**: Printable / PDF-ready executive summary report with sign-off blocks.

### 8. REST Web APIs
- Full REST API surface (`/api/metrics`, `/api/assets`, `/api/findings`, `/api/scans/launch`, `/api/scans/{id}/status`, `/api/threat-intel/kev`) for CI/CD and SIEM integrations.

---

## 🚀 Getting Started

### Prerequisites
- [.NET 10.0 SDK](https://dotnet.microsoft.com/)

### Running the Application
From the project directory:
```powershell
dotnet run
```
By default, the application will start on `http://localhost:5000` (or `http://localhost:5178` depending on launch profile).

Open your browser and navigate to:
```
http://localhost:5178
```

The database (`vulnguard.db`) will be automatically created and pre-seeded with realistic enterprise assets, servers, network appliances, and real-world CVE findings on first launch.

---

## 📁 Project Structure

```
├── Controllers/
│   ├── ApiController.cs             # REST API endpoints for automation
│   ├── AssetsController.cs          # Asset inventory CRUD and inspection
│   ├── DashboardController.cs       # Executive KPI dashboard and risk charts
│   ├── RemediationController.cs     # SLA ticket workflows and policy config
│   ├── ReportsController.cs         # Compliance matrices & executive reports
│   ├── ScannerController.cs         # Vulnerability scan jobs & live console
│   ├── ThreatIntelController.cs     # CISA KEV catalog & CVE lookup
│   └── VulnerabilitiesController.cs # Finding lifecycle & CVE catalog
├── Data/
│   ├── AppDbContext.cs              # EF Core SQLite database context
│   └── DbInitializer.cs             # Pre-seeded assets, CVEs & sample findings
├── Models/
│   ├── ActivityLog.cs               # Audit trail records
│   ├── Asset.cs                     # CMDB host entity model
│   ├── ScanJob.cs                   # Scanner execution history
│   ├── SlaPolicy.cs                 # SLA threshold definitions
│   ├── ViewModels.cs                # Dashboard and compliance models
│   ├── Vulnerability.cs             # Master CVE catalog item
│   └── VulnerabilityFinding.cs      # Fleet finding instance with SLA tracking
├── Services/
│   ├── IReportService.cs            # Compliance framework generator
│   ├── IRiskScoringService.cs       # Risk scoring and SLA calculator
│   ├── IScannerService.cs           # TCP socket prober and signature engine
│   └── IThreatIntelService.cs       # CISA KEV threat feed provider
└── Views/                           # Razor Views with Cyber Theme & Chart.js
```
