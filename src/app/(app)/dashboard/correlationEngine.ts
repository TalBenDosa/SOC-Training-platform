import type { LiveEvent } from "./useLiveEvents";

export interface CorrelationAlert {
  id: string;
  rule: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  mitre: string;
  affectedAssets: string[];
  eventIds: string[];
  triggeredAt: string;
  confidence: number;
  // ── Authentic detection-rule metadata (shown to the analyst) ───────────────
  /** Plain-English summary of what the rule looks for */
  logic: string;
  /** The real detection query, KQL (Microsoft Sentinel) style */
  query: string;
  /** MITRE ATT&CK tactic this rule maps to */
  tactic: string;
  /** The SIEM data source / table the rule runs against */
  dataSource: string;
}

const SEV_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

interface RuleDef { logic: string; query: string; tactic: string; dataSource: string; }

/**
 * The rule book — one authentic analytic rule per correlation ID, in the shape a
 * real SOC documents them: a plain-English summary, the actual KQL detection
 * query (Microsoft Sentinel style, against real tables), the MITRE tactic, and
 * the data source. Shown to the analyst so the correlation is a genuine
 * detection artifact they can learn — maximum fidelity to a live SOC.
 */
export const RULE_BOOK: Record<string, RuleDef> = {
  CORR_001: {
    logic: "One source IP fails authentication against 3+ distinct accounts in a short window (spraying a shared password across many users).",
    tactic: "Credential Access",
    dataSource: "SigninLogs / Okta System Log",
    query:
`SigninLogs
| where ResultType == "50126"          // invalid username or password
| summarize Fails = count(),
            Accounts = dcount(UserPrincipalName)
        by IPAddress, bin(TimeGenerated, 10m)
| where Fails >= 5 and Accounts >= 3`,
  },
  CORR_002: {
    logic: "3+ failed logins for one account immediately followed by a success from the same account — a brute force that finally landed.",
    tactic: "Credential Access",
    dataSource: "SigninLogs / SecurityEvent 4625→4624",
    query:
`SigninLogs
| summarize Fails   = countif(ResultType != "0"),
            Success = countif(ResultType == "0"),
            SuccessTime = maxif(TimeGenerated, ResultType == "0")
        by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where Fails >= 3 and Success >= 1`,
  },
  CORR_003: {
    logic: "The same user authenticates successfully from 2+ distinct IPs/countries within a window too short to physically travel.",
    tactic: "Initial Access",
    dataSource: "SigninLogs (Location, IPAddress)",
    query:
`SigninLogs
| where ResultType == "0"
| summarize Countries = dcount(Location),
            IPs = make_set(IPAddress)
        by UserPrincipalName, bin(TimeGenerated, 1h)
| where Countries >= 2`,
  },
  CORR_004: {
    logic: "An Office application (Word/Excel/Outlook) spawns a scripting shell — the classic macro-to-PowerShell execution.",
    tactic: "Execution",
    dataSource: "DeviceProcessEvents (Defender for Endpoint / Sysmon 1)",
    query:
`DeviceProcessEvents
| where InitiatingProcessFileName in~
        ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName in~
        ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe")`,
  },
  CORR_005: {
    logic: "One host makes repeated connections to the same external domain at regular intervals — command-and-control beaconing.",
    tactic: "Command and Control",
    dataSource: "DeviceNetworkEvents / DNS logs",
    query:
`DeviceNetworkEvents
| summarize Conns = count()
        by DeviceName, RemoteUrl, bin(TimeGenerated, 1h)
| where Conns >= 3        // tune to expected beacon interval`,
  },
  CORR_006: {
    logic: "PsExec / PSEXESVC executes on a host — a remote-execution tool commonly used for lateral movement.",
    tactic: "Lateral Movement",
    dataSource: "DeviceProcessEvents (Sysmon 1) / SecurityEvent 7045",
    query:
`DeviceProcessEvents
| where FileName =~ "PSEXESVC.exe"
     or ProcessCommandLine has "psexec"`,
  },
  CORR_007: {
    logic: "A process reads LSASS memory via comsvcs MiniDump or mimikatz — credential dumping to harvest passwords/hashes.",
    tactic: "Credential Access",
    dataSource: "DeviceProcessEvents / Sysmon 10 (LSASS access)",
    query:
`DeviceProcessEvents
| where ProcessCommandLine has_all ("comsvcs.dll","MiniDump")
     or FileName =~ "mimikatz.exe"
     or ProcessCommandLine has "sekurlsa"`,
  },
  CORR_008: {
    logic: "An inbox / transport forwarding rule is created around the same time as mailbox activity — hidden email exfiltration.",
    tactic: "Collection",
    dataSource: "OfficeActivity (Exchange)",
    query:
`OfficeActivity
| where Operation in
        ("New-InboxRule","Set-InboxRule","New-TransportRule")
| where Parameters has_any ("ForwardTo","RedirectTo","DeleteMessage")`,
  },
  CORR_009: {
    logic: "Volume Shadow Copies are deleted (or several critical alerts hit one host) — pre-ransomware destruction of recovery points.",
    tactic: "Impact",
    dataSource: "DeviceProcessEvents (Sysmon 1)",
    query:
`DeviceProcessEvents
| where ProcessCommandLine has_all ("vssadmin","delete","shadows")
     or ProcessCommandLine has_all ("wmic","shadowcopy","delete")`,
  },
  CORR_010: {
    logic: "A user consents to an OAuth application and account changes follow — an app granted standing access for persistence.",
    tactic: "Persistence",
    dataSource: "AuditLogs (Entra ID) / OfficeActivity",
    query:
`AuditLogs
| where OperationName in
        ("Consent to application","Add app role assignment grant to user")
| where TargetResources has_any ("Mail.Read","Files.Read","offline_access")`,
  },
  CORR_011: {
    logic: "5+ MFA prompts/denials for one user in minutes, then an approval — MFA fatigue (push bombing) to slip past MFA.",
    tactic: "Credential Access",
    dataSource: "SigninLogs / Okta MFA events",
    query:
`SigninLogs
| where ResultType == "50074"          // strong auth required / MFA denied
| summarize Prompts = count()
        by UserPrincipalName, bin(TimeGenerated, 15m)
| where Prompts >= 5`,
  },
  CORR_012: {
    logic: "Many Kerberos service-ticket (TGS) requests using weak RC4 encryption — Kerberoasting to crack service-account passwords offline.",
    tactic: "Credential Access",
    dataSource: "SecurityEvent 4769",
    query:
`SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"   // RC4-HMAC (weak)
| summarize Services = dcount(ServiceName)
        by Account, bin(TimeGenerated, 1h)
| where Services >= 5`,
  },
  CORR_013: {
    logic: "A Kerberos AS-REQ for an account with pre-authentication disabled (PreAuthType 0) — AS-REP Roasting; the reply hash cracks offline.",
    tactic: "Credential Access",
    dataSource: "SecurityEvent 4768",
    query:
`SecurityEvent
| where EventID == 4768
| where PreAuthType == "0"               // pre-auth NOT required
| project TimeGenerated, TargetUserName, IpAddress`,
  },
  CORR_014: {
    logic: "High volume of DNS queries to one parent domain with long, high-entropy subdomains — data tunnelled out over DNS.",
    tactic: "Exfiltration",
    dataSource: "DnsEvents / Sysmon 22",
    query:
`DnsEvents
| extend Sub = tostring(split(Name, ".")[0])
| summarize Queries = count(), AvgLen = avg(strlen(Sub))
        by ClientIP, bin(TimeGenerated, 1h)
| where Queries >= 50 or AvgLen > 30`,
  },
  CORR_015: {
    logic: "A directory-replication request (DS-Replication-Get-Changes) from an account that is NOT a domain controller — DCSync hash theft.",
    tactic: "Credential Access",
    dataSource: "SecurityEvent 4662",
    query:
`SecurityEvent
| where EventID == 4662
| where Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"  // Replicating Directory Changes
| where Account !endswith "$"           // exclude real DCs`,
  },
  CORR_016: {
    logic: "A container or process reaches the cloud metadata IP 169.254.169.254 (or breaks out via nsenter) to steal the node's IAM role credentials.",
    tactic: "Credential Access",
    dataSource: "DeviceNetworkEvents / EDR + K8s audit",
    query:
`DeviceNetworkEvents
| where RemoteIP == "169.254.169.254"    // cloud instance metadata service
| where InitiatingProcessFileName in~ ("curl","wget","nsenter","bash")`,
  },
  CORR_017: {
    logic: "Bulk object reads from cloud storage (e.g. S3 GetObject) by one principal — large-volume data theft from the cloud.",
    tactic: "Exfiltration",
    dataSource: "AWSCloudTrail / Azure Storage logs",
    query:
`AWSCloudTrail
| where EventName in ("GetObject","ListObjects")
| summarize Reads = count(), Bytes = sum(todouble(bytesTransferredOut))
        by userIdentityArn, bin(TimeGenerated, 1h)
| where Reads >= 100 or Bytes > 100000000`,
  },
};

type RawAlert = Omit<CorrelationAlert, "logic" | "query" | "tactic" | "dataSource">;

export function runCorrelations(events: LiveEvent[]): CorrelationAlert[] {
  const alerts: RawAlert[] = [];

  // ── CORR_001 — Password Spray ─────────────────────────────────────────────
  // 3+ auth_failure from same src_ip targeting 3+ different user_email
  {
    const authFailures = events.filter(e => e.event_type === "auth_failure" && e.src_ip);
    const byIp: Record<string, LiveEvent[]> = {};
    for (const e of authFailures) {
      const ip = e.src_ip!;
      if (!byIp[ip]) byIp[ip] = [];
      byIp[ip].push(e);
    }
    for (const [ip, evts] of Object.entries(byIp)) {
      const uniqueUsers = new Set(evts.map(e => e.user_email).filter(Boolean));
      if (evts.length >= 3 && uniqueUsers.size >= 3) {
        const id = `CORR_001_${ip}`;
        alerts.push({
          id,
          rule: "CORR_001",
          title: "Password Spray Detected",
          description: `${evts.length} authentication failures from ${ip} targeting ${uniqueUsers.size} distinct accounts.`,
          severity: "high",
          mitre: "T1110.003",
          affectedAssets: [ip],
          eventIds: evts.map(e => e.id),
          triggeredAt: new Date().toISOString(),
          confidence: 85,
        });
      }
    }
  }

  // ── CORR_002 — Brute Force → Success ─────────────────────────────────────
  // 3+ auth_failure for same user, followed by auth_success for same user
  {
    const byUser: Record<string, LiveEvent[]> = {};
    for (const e of events) {
      if ((e.event_type === "auth_failure" || e.event_type === "auth_success") && e.user_email) {
        const u = e.user_email;
        if (!byUser[u]) byUser[u] = [];
        byUser[u].push(e);
      }
    }
    for (const [user, evts] of Object.entries(byUser)) {
      // events is newest-first; find auth_success (lower index = more recent)
      const successIdx = evts.findIndex(e => e.event_type === "auth_success");
      if (successIdx === -1) continue;
      // failures that appear AFTER the success in time = higher array index (older)
      const failures = evts.slice(successIdx + 1).filter(e => e.event_type === "auth_failure");
      if (failures.length >= 3) {
        const id = `CORR_002_${user}`;
        const allEvtIds = [evts[successIdx].id, ...failures.map(e => e.id)];
        alerts.push({
          id,
          rule: "CORR_002",
          title: "Brute Force Succeeded",
          description: `${failures.length} failed login attempts for ${user} followed by successful authentication.`,
          severity: "critical",
          mitre: "T1110.001",
          affectedAssets: [user],
          eventIds: allEvtIds,
          triggeredAt: new Date().toISOString(),
          confidence: 90,
        });
      }
    }
  }

  // ── CORR_003 — Impossible Travel ──────────────────────────────────────────
  // Same user_email with auth_success from 2+ distinct src_ip values
  {
    const byUser: Record<string, LiveEvent[]> = {};
    for (const e of events) {
      if (e.event_type === "auth_success" && e.user_email && e.src_ip) {
        const u = e.user_email;
        if (!byUser[u]) byUser[u] = [];
        byUser[u].push(e);
      }
    }
    for (const [user, evts] of Object.entries(byUser)) {
      const uniqueIps = new Set(evts.map(e => e.src_ip).filter(Boolean));
      if (uniqueIps.size >= 2) {
        const id = `CORR_003_${user}`;
        alerts.push({
          id,
          rule: "CORR_003",
          title: "Impossible Travel Detected",
          description: `User ${user} authenticated from ${uniqueIps.size} distinct IP addresses suggesting impossible travel or credential sharing.`,
          severity: "high",
          mitre: "T1078",
          affectedAssets: [user],
          eventIds: evts.map(e => e.id),
          triggeredAt: new Date().toISOString(),
          confidence: 75,
        });
      }
    }
  }

  // ── CORR_004 — Office App Spawning Shell ──────────────────────────────────
  // process_create where parent is office app and process is shell
  {
    const OFFICE_PARENTS = new Set(["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]);
    const SHELL_PROCS = new Set(["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"]);
    const matches = events.filter(e =>
      e.event_type === "process_create" &&
      e.process?.parent_name &&
      OFFICE_PARENTS.has(e.process.parent_name.toLowerCase()) &&
      e.process?.name &&
      SHELL_PROCS.has(e.process.name.toLowerCase())
    );
    for (const e of matches) {
      const host = e.hostname ?? "unknown";
      const id = `CORR_004_${host}_${e.process!.name}`;
      alerts.push({
        id,
        rule: "CORR_004",
        title: "Office Application Spawning Shell",
        description: `${e.process!.parent_name} spawned ${e.process!.name} on ${host} — potential macro/document exploit.`,
        severity: "critical",
        mitre: "T1218",
        affectedAssets: [host],
        eventIds: [e.id],
        triggeredAt: new Date().toISOString(),
        confidence: 95,
      });
    }
  }

  // ── CORR_005 — C2 Beaconing ───────────────────────────────────────────────
  // Same hostname + same network.domain in 3+ net_connection or dns_query events
  {
    const beaconEvents = events.filter(e =>
      (e.event_type === "net_connection" || e.event_type === "dns_query") &&
      e.hostname &&
      e.network?.domain
    );
    const grouped: Record<string, LiveEvent[]> = {};
    for (const e of beaconEvents) {
      const key = `${e.hostname}||${e.network!.domain}`;
      if (!grouped[key]) grouped[key] = [];
      grouped[key].push(e);
    }
    for (const [key, evts] of Object.entries(grouped)) {
      if (evts.length >= 3) {
        const [host, domain] = key.split("||");
        const id = `CORR_005_${host}_${domain}`;
        alerts.push({
          id,
          rule: "CORR_005",
          title: "C2 Beaconing Pattern",
          description: `${host} made ${evts.length} connections to ${domain} — repeated beaconing pattern detected.`,
          severity: "high",
          mitre: "T1071.001",
          affectedAssets: [host],
          eventIds: evts.map(e => e.id),
          triggeredAt: new Date().toISOString(),
          confidence: 80,
        });
      }
    }
  }

  // ── CORR_006 — PsExec Lateral Movement ───────────────────────────────────
  // process_create where process.name matches /psexec/i or cmdline matches /psexesvc/i
  {
    const matches = events.filter(e =>
      e.event_type === "process_create" &&
      (
        /psexec/i.test(e.process?.name ?? "") ||
        /psexesvc/i.test(e.process?.cmdline ?? "")
      )
    );
    for (const e of matches) {
      const host = e.hostname ?? "unknown";
      const id = `CORR_006_${host}_${e.id}`;
      alerts.push({
        id,
        rule: "CORR_006",
        title: "PsExec Lateral Movement",
        description: `PsExec execution detected on ${host} — possible lateral movement attempt.`,
        severity: "critical",
        mitre: "T1569.002",
        affectedAssets: [host],
        eventIds: [e.id],
        triggeredAt: new Date().toISOString(),
        confidence: 95,
      });
    }
  }

  // ── CORR_007 — Credential Dumping ────────────────────────────────────────
  // cmdline contains comsvcs AND minidump, OR process.name is mimikatz.exe, OR mitre_technique is T1003.001
  {
    const matches = events.filter(e =>
      e.event_type === "process_create" && (
        (
          /comsvcs/i.test(e.process?.cmdline ?? "") &&
          /minidump/i.test(e.process?.cmdline ?? "")
        ) ||
        /mimikatz\.exe/i.test(e.process?.name ?? "") ||
        e.mitre_technique === "T1003.001"
      )
    );
    for (const e of matches) {
      const host = e.hostname ?? "unknown";
      const id = `CORR_007_${host}_${e.id}`;
      alerts.push({
        id,
        rule: "CORR_007",
        title: "Credential Dumping Detected",
        description: `Credential dumping activity detected on ${host} via ${e.process?.name ?? "unknown process"}.`,
        severity: "critical",
        mitre: "T1003.001",
        affectedAssets: [host],
        eventIds: [e.id],
        triggeredAt: new Date().toISOString(),
        confidence: 98,
      });
    }
  }

  // ── CORR_008 — Mailbox Rule Abuse ─────────────────────────────────────────
  // account_modify event for user who also has email_received or email_sent events
  {
    const modifyEvents = events.filter(e => e.event_type === "account_modify" && e.user_email);
    for (const mod of modifyEvents) {
      const user = mod.user_email!;
      const emailEvts = events.filter(e =>
        (e.event_type === "email_received" || e.event_type === "email_sent") &&
        e.user_email === user
      );
      if (emailEvts.length > 0) {
        const id = `CORR_008_${user}`;
        alerts.push({
          id,
          rule: "CORR_008",
          title: "Mailbox Rule Abuse Suspected",
          description: `Account modification for ${user} coincides with email activity — potential hidden forwarding rule.`,
          severity: "high",
          mitre: "T1114.001",
          affectedAssets: [user],
          eventIds: [mod.id, ...emailEvts.map(e => e.id)],
          triggeredAt: new Date().toISOString(),
          confidence: 70,
        });
      }
    }
  }

  // ── CORR_009 — Ransomware Indicators ─────────────────────────────────────
  // cmdline contains vssadmin AND delete, OR 3+ events on same host with ruleLevel >= 9
  {
    // Pattern A: vssadmin delete
    const vssMatches = events.filter(e =>
      /vssadmin/i.test(e.process?.cmdline ?? "") &&
      /delete/i.test(e.process?.cmdline ?? "")
    );
    for (const e of vssMatches) {
      const host = e.hostname ?? "unknown";
      const id = `CORR_009_vss_${host}`;
      alerts.push({
        id,
        rule: "CORR_009",
        title: "Ransomware Indicator — VSS Deletion",
        description: `Shadow copy deletion attempt detected on ${host} — pre-ransomware activity.`,
        severity: "critical",
        mitre: "T1486",
        affectedAssets: [host],
        eventIds: [e.id],
        triggeredAt: new Date().toISOString(),
        confidence: 92,
      });
    }

    // Pattern B: 3+ high-severity events on same host
    const highByHost: Record<string, LiveEvent[]> = {};
    for (const e of events) {
      if (e.ruleLevel >= 9 && e.hostname) {
        if (!highByHost[e.hostname]) highByHost[e.hostname] = [];
        highByHost[e.hostname].push(e);
      }
    }
    for (const [host, evts] of Object.entries(highByHost)) {
      if (evts.length >= 3) {
        const id = `CORR_009_high_${host}`;
        // Don't duplicate if vss alert already fired for same host
        if (!alerts.find(a => a.id === `CORR_009_vss_${host}`)) {
          alerts.push({
            id,
            rule: "CORR_009",
            title: "Ransomware Indicators — High Severity Cluster",
            description: `${evts.length} critical-severity events on ${host} — ransomware activity pattern.`,
            severity: "critical",
            mitre: "T1486",
            affectedAssets: [host],
            eventIds: evts.map(e => e.id),
            triggeredAt: new Date().toISOString(),
            confidence: 92,
          });
        }
      }
    }
  }

  // ── CORR_010 — OAuth App Persistence ──────────────────────────────────────
  // cloud_api_call + account_modify from same user_email
  {
    const cloudCalls = events.filter(e => e.event_type === "cloud_api_call" && e.user_email);
    const accountMods = events.filter(e => e.event_type === "account_modify" && e.user_email);
    const cloudUsers = new Set(cloudCalls.map(e => e.user_email!));
    for (const mod of accountMods) {
      if (mod.user_email && cloudUsers.has(mod.user_email)) {
        const user = mod.user_email;
        const userCloudEvts = cloudCalls.filter(e => e.user_email === user);
        const id = `CORR_010_${user}`;
        alerts.push({
          id,
          rule: "CORR_010",
          title: "OAuth App Persistence Suspected",
          description: `Cloud API calls and account modification from ${user} — potential OAuth app consent grant for persistence.`,
          severity: "high",
          mitre: "T1098.005",
          affectedAssets: [user],
          eventIds: [mod.id, ...userCloudEvts.map(e => e.id)],
          triggeredAt: new Date().toISOString(),
          confidence: 80,
        });
      }
    }
  }

  // Helper: push a single-event technique detection
  const pushTechnique = (
    rule: string, techniques: string[], title: string,
    severity: CorrelationAlert["severity"], confidence: number,
    describe: (e: LiveEvent) => string,
  ) => {
    for (const e of events) {
      if (!e.mitre_technique || !techniques.includes(e.mitre_technique)) continue;
      const asset = e.hostname ?? e.user_email ?? "unknown";
      const id = `${rule}_${asset}_${e.id}`;
      alerts.push({
        id, rule, title,
        description: describe(e),
        severity, mitre: e.mitre_technique,
        affectedAssets: [asset], eventIds: [e.id],
        triggeredAt: new Date().toISOString(), confidence,
      });
    }
  };

  // ── CORR_011 — MFA Fatigue / Push Bombing ────────────────────────────────
  {
    // Pattern: many MFA prompts/denials for one user in a short window
    const mfaByUser: Record<string, LiveEvent[]> = {};
    for (const e of events) {
      if ((e.event_type === "mfa_denied" || e.event_type === "mfa_push_sent" || e.event_type === "mfa_challenge") && e.user_email) {
        (mfaByUser[e.user_email] ??= []).push(e);
      }
    }
    for (const [user, evts] of Object.entries(mfaByUser)) {
      if (evts.length >= 3) {
        alerts.push({
          id: `CORR_011_${user}`, rule: "CORR_011", title: "MFA Fatigue / Push Bombing",
          description: `${evts.length} MFA prompts sent to ${user} in a short window — the attacker is bombarding the user to get an accidental approval.`,
          severity: "high", mitre: "T1621", affectedAssets: [user],
          eventIds: evts.map(e => e.id), triggeredAt: new Date().toISOString(), confidence: 85,
        });
      }
    }
    // Fallback: any single event explicitly tagged T1621
    pushTechnique("CORR_011", ["T1621"], "MFA Fatigue / Push Bombing", "high", 85,
      e => `MFA request-generation activity for ${e.user_email ?? "an account"} — possible push-bombing to bypass MFA.`);
  }

  // ── CORR_012 — Kerberoasting ─────────────────────────────────────────────
  pushTechnique("CORR_012", ["T1558.003"], "Kerberoasting — Service Ticket Harvesting", "high", 88,
    e => `Kerberos service-ticket (TGS) request pattern for service accounts on ${e.hostname ?? "the domain"} — tickets can be cracked offline to recover service-account passwords.`);

  // ── CORR_013 — AS-REP Roasting ───────────────────────────────────────────
  pushTechnique("CORR_013", ["T1558.004"], "AS-REP Roasting", "high", 88,
    e => `AS-REP request for an account with Kerberos pre-authentication disabled (${e.user_email ?? e.hostname ?? "unknown"}) — the reply hash can be cracked offline.`);

  // ── CORR_014 — DNS Tunneling / Exfiltration ──────────────────────────────
  {
    pushTechnique("CORR_014", ["T1071.004", "T1048", "T1048.003"], "DNS Tunneling / Exfiltration", "high", 82,
      e => `Suspicious DNS activity from ${e.hostname ?? "a host"}${e.network?.domain ? ` to ${e.network.domain}` : ""} — long/high-entropy subdomains are a hallmark of data smuggled over DNS.`);
    // Volume pattern: many DNS queries from one host to one parent domain
    const dnsByKey: Record<string, LiveEvent[]> = {};
    for (const e of events) {
      if (e.event_type === "dns_query" && e.hostname && e.network?.domain) {
        (dnsByKey[`${e.hostname}||${e.network.domain}`] ??= []).push(e);
      }
    }
    for (const [key, evts] of Object.entries(dnsByKey)) {
      if (evts.length >= 5) {
        const [host, domain] = key.split("||");
        const id = `CORR_014_vol_${host}_${domain}`;
        if (!alerts.find(a => a.id === id)) {
          alerts.push({
            id, rule: "CORR_014", title: "DNS Tunneling / Exfiltration",
            description: `${host} made ${evts.length} DNS queries to ${domain} — abnormally high volume consistent with DNS tunneling.`,
            severity: "high", mitre: "T1071.004", affectedAssets: [host],
            eventIds: evts.map(e => e.id), triggeredAt: new Date().toISOString(), confidence: 82,
          });
        }
      }
    }
  }

  // ── CORR_015 — DCSync ────────────────────────────────────────────────────
  pushTechnique("CORR_015", ["T1003.006"], "DCSync — Directory Replication Abuse", "critical", 95,
    e => `Directory-replication (DsGetNCChanges) request${e.user_email ? ` by ${e.user_email}` : ""} — a non-DC principal is pulling password hashes straight from Active Directory.`);

  // ── CORR_016 — Container Escape → Cloud Credential Theft ──────────────────
  pushTechnique("CORR_016", ["T1552.005", "T1610", "T1611"], "Container Escape → Cloud Credential Theft", "critical", 93,
    e => `Container/host boundary or cloud-metadata (169.254.169.254) access on ${e.hostname ?? "a node"} — the attacker is stealing the node's IAM role credentials.`);

  // ── CORR_017 — Cloud Data Exfiltration ───────────────────────────────────
  pushTechnique("CORR_017", ["T1530"], "Cloud Data Exfiltration", "high", 85,
    e => `Bulk read from cloud storage${e.user_email ? ` by ${e.user_email}` : ""}${e.src_ip ? ` from ${e.src_ip}` : ""} — large object-download volume consistent with data theft.`);

  // Deduplicate by id (keep first occurrence) and attach the rule logic
  const seen = new Set<string>();
  const deduped: CorrelationAlert[] = [];
  const FALLBACK: RuleDef = {
    logic: "Correlated detection across multiple events.",
    query: "// custom correlation", tactic: "Unknown", dataSource: "Multiple",
  };
  for (const alert of alerts) {
    if (!seen.has(alert.id)) {
      seen.add(alert.id);
      deduped.push({ ...alert, ...(RULE_BOOK[alert.rule] ?? FALLBACK) });
    }
  }

  // Sort by severity: critical first
  return deduped.sort((a, b) => (SEV_ORDER[a.severity] ?? 99) - (SEV_ORDER[b.severity] ?? 99));
}
