export type LogSourceEntry = {
  label: string;
  vendors: string;
  whatMonitors: string[];
  keyFields: string[];
  redFlag: string;
};

export const LOG_SOURCE_GUIDE: Record<string, LogSourceEntry> = {
  edr: {
    label: "EDR — Endpoint Detection & Response",
    vendors: "CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne",
    whatMonitors: ["Process creation and termination", "File writes and modifications", "Network connections from processes", "Registry changes"],
    keyFields: ["process.name", "process.parent.name", "process.cmdline", "file.hash.sha256"],
    redFlag: "Office app (Word/Excel) spawning PowerShell or cmd.exe",
  },
  sysmon: {
    label: "Sysmon — System Monitor",
    vendors: "Microsoft Sysinternals (free Windows tool)",
    whatMonitors: ["Process creation (Event ID 1)", "Network connections (Event ID 3)", "File creation (Event ID 11)", "Registry events (Event ID 12/13)"],
    keyFields: ["process.name", "process.parent.name", "process.cmdline", "network.dst_ip"],
    redFlag: "PowerShell with -EncodedCommand or -WindowStyle Hidden",
  },
  ad: {
    label: "Active Directory — Domain Auth",
    vendors: "Microsoft Windows Server (built-in)",
    whatMonitors: ["User login and logout events", "Failed login attempts", "Group membership changes", "Password resets and account locks"],
    keyFields: ["user.name", "event.id", "source.ip", "logon.type"],
    redFlag: "Many failed logins from one IP followed by a success (password spray)",
  },
  o365: {
    label: "Office 365 / Microsoft 365",
    vendors: "Microsoft (Exchange, SharePoint, Teams, OneDrive)",
    whatMonitors: ["Emails sent and received", "File access in SharePoint/OneDrive", "Teams messages", "App permissions granted"],
    keyFields: ["user.email", "operation", "client_ip", "object_id"],
    redFlag: "Third-party app granted full mailbox access (OAuth consent)",
  },
  gws: {
    label: "Google Workspace — Collaboration & Identity",
    vendors: "Google (Gmail, Drive, Calendar, Admin Console)",
    whatMonitors: ["Emails sent and received", "Drive file sharing and access", "Calendar events created", "Admin console changes (OAuth apps, forwarding rules)"],
    keyFields: ["gws.eventName", "gws.actorEmail", "gws.to", "action_result"],
    redFlag: "Auto-forwarding rule created to an external personal Gmail address",
  },
  firewall: {
    label: "Firewall — Network Traffic",
    vendors: "Palo Alto Networks, Fortinet FortiGate, Cisco ASA, Check Point",
    whatMonitors: ["Inbound and outbound network connections", "Blocked traffic attempts", "Port scans", "Traffic volume by destination"],
    keyFields: ["source.ip", "destination.ip", "destination.port", "action"],
    redFlag: "Internal host connecting to a known TOR exit node or C2 IP",
  },
  dns: {
    label: "DNS — Domain Name System",
    vendors: "Windows DNS, BIND, Infoblox, Cisco Umbrella",
    whatMonitors: ["All domain name lookups from hosts", "DNS query types (A, MX, TXT)", "Failed lookups (NXDOMAIN)", "Response IP addresses"],
    keyFields: ["dns.question.name", "dns.resolved_ip", "source.ip", "dns.response_code"],
    redFlag: "Very long subdomain queries — may be DNS tunneling to exfiltrate data",
  },
  proxy: {
    label: "Web Proxy — HTTP/HTTPS Traffic",
    vendors: "Zscaler, BlueCoat, Squid, Cisco WSA",
    whatMonitors: ["Websites visited by users", "Files downloaded", "HTTP methods (GET/POST)", "Response codes and sizes"],
    keyFields: ["url.full", "user.name", "http.response.status_code", "network.bytes_out"],
    redFlag: "Large POST request to a newly registered or uncategorized domain",
  },
  vpn: {
    label: "VPN — Remote Access",
    vendors: "Cisco AnyConnect, Palo Alto GlobalProtect, Fortinet, Zscaler",
    whatMonitors: ["VPN login and logout events", "Source IP and country of connection", "Session duration and data transferred", "MFA results"],
    keyFields: ["user.name", "source.ip", "geo.country", "session.duration"],
    redFlag: "Login from a country the user has never connected from before",
  },
  dlp: {
    label: "DLP — Data Loss Prevention",
    vendors: "Microsoft Purview, Symantec DLP, Forcepoint, Digital Guardian",
    whatMonitors: ["Files copied to USB drives", "Sensitive data in emails", "Cloud uploads (Google Drive, Dropbox)", "Screenshots of sensitive content"],
    keyFields: ["file.name", "user.name", "destination.type", "policy.name"],
    redFlag: "Large volume of files copied to USB by an employee who recently resigned",
  },
  cloud: {
    label: "Cloud Audit — AWS / Azure / GCP",
    vendors: "AWS CloudTrail, Azure Activity Log, GCP Audit Logs",
    whatMonitors: ["API calls to cloud services", "IAM permission changes", "Storage bucket access", "Resource creation and deletion"],
    keyFields: ["event.name", "user.arn", "source.ip", "aws.region"],
    redFlag: "Admin IAM role created outside of business hours from an unknown IP",
  },
  ueba: {
    label: "UEBA — User Behavior Analytics",
    vendors: "Microsoft Sentinel UEBA, Splunk UBA, Exabeam, Securonix",
    whatMonitors: ["Unusual login times or locations", "Abnormal data download volumes", "Peer group comparison (is this user acting like their colleagues?)", "Risk score changes over time"],
    keyFields: ["user.name", "behavior.score", "behavior.baseline", "anomaly.type"],
    redFlag: "User downloads 50× more data than their 30-day average in a single day",
  },
  nac: {
    label: "NAC — Network Access Control",
    vendors: "Cisco ISE, Aruba ClearPass, Forescout, Fortinet FortiNAC",
    whatMonitors: ["Devices connecting to the network", "Device compliance status (is antivirus up to date?)", "VLAN assignments", "Guest network access"],
    keyFields: ["device.mac", "device.os", "auth.result", "vlan.id"],
    redFlag: "Unknown device connected to internal network switch — possible rogue device",
  },
  windows_security: {
    label: "Windows Security Log — Host & Domain Auth",
    vendors: "Microsoft Windows (Security event channel), forwarded via WEF/agent",
    whatMonitors: ["Logon / logoff (4624, 4625, 4634)", "Account & group changes (4720, 4728, 4732)", "Process creation with command line (4688)", "Kerberos/NTLM ticket requests (4768, 4769, 4776)"],
    keyFields: ["winlog.event_id", "winlog.event_data.TargetUserName", "winlog.event_data.IpAddress", "winlog.event_data.LogonType"],
    redFlag: "A burst of 4625 failures on one account then a 4624 success from the same source — brute force that worked",
  },
  linux_audit: {
    label: "Linux auditd — Kernel Audit Framework",
    vendors: "Linux auditd (built-in), shipped by Auditbeat / the endpoint agent",
    whatMonitors: ["User logins and sudo escalation", "Process execution (execve)", "File access on watched paths", "Cron and systemd persistence changes"],
    keyFields: ["auditd.data.exe", "auditd.data.acct", "auditd.summary.actor.primary", "process.args"],
    redFlag: "sshd accepts a login for a service account, then curl/wget pulls a binary and a cron job is added",
  },
  email_gateway: {
    label: "Secure Email Gateway",
    vendors: "Proofpoint, Mimecast, Microsoft Defender for Office 365, Cisco ESA",
    whatMonitors: ["Inbound / outbound mail and attachments", "URL rewriting and click-time verdicts", "Sender authentication (SPF/DKIM/DMARC)", "Phishing and malware verdicts"],
    keyFields: ["email.from.address", "email.subject", "url.original", "verdict"],
    redFlag: "A lookalike-domain sender whose link is a freshly-registered site the user clicked (AiTM lure)",
  },
  waf: {
    label: "WAF — Web Application Firewall",
    vendors: "AWS WAF, Azure App Gateway WAF, Cloudflare, F5, Imperva, Akamai",
    whatMonitors: ["HTTP requests to public web apps", "Signature matches (SQLi, XSS, LFI, RCE)", "Bot / scraping detection", "Rate and geo anomalies"],
    keyFields: ["http.request.uri", "http.request.method", "waf.rule_id", "waf.action"],
    redFlag: "SQL-injection strings in a query parameter that return 200 instead of being blocked — the WAF was in detect-only mode",
  },
  db_monitor: {
    label: "DAM — Database Activity Monitoring",
    vendors: "IBM Guardium, Imperva DAM, native SQL/Oracle/PostgreSQL audit",
    whatMonitors: ["Every SQL statement against sensitive tables", "Rows returned and query duration", "Privilege and schema changes", "Bulk exports and stored-procedure calls"],
    keyFields: ["query.text", "query.rows_returned", "db.user", "db.command"],
    redFlag: "A web-app service account running SELECT * on a customer table and returning tens of thousands of rows",
  },
  iam: {
    label: "IAM / Identity Provider",
    vendors: "Microsoft Entra ID (Azure AD), Okta, Ping, ADFS",
    whatMonitors: ["Sign-ins and MFA prompts", "Conditional-access / risk evaluations", "Token issuance and refresh", "App consent and role assignment"],
    keyFields: ["user.principal_name", "source.ip", "geo.country", "auth.result"],
    redFlag: "A successful sign-in from a new country minutes after one in the home country — impossible travel",
  },
  siem: {
    label: "SIEM — Correlation & Alerting",
    vendors: "Microsoft Sentinel, Splunk ES, Elastic Security, QRadar",
    whatMonitors: ["Correlation rules across many sources", "Analytics / detection alerts", "Watchlist and threat-intel matches", "Incident aggregation"],
    keyFields: ["rule.name", "alert.severity", "entities", "mitre.technique"],
    redFlag: "A correlation alert firing is the START of triage, not the verdict — always pivot to the raw source logs it fired on",
  },
  soar: {
    label: "SOAR — Automation & Response",
    vendors: "Palo Alto XSOAR, Splunk SOAR, Microsoft Sentinel playbooks",
    whatMonitors: ["Automated playbook runs", "Enrichment and case actions", "Containment (disable user, isolate host)", "Ticketing and notifications"],
    keyFields: ["playbook.name", "action.type", "action.result", "case.id"],
    redFlag: "A containment playbook that failed or was skipped — the host you assumed was isolated may still be live",
  },
};
