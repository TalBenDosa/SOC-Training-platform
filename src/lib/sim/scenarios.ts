/**
 * High-level scenario builder. Composes generators into coherent attack stories
 * with realistic killchain, alerts, telemetry, IOCs, and analyst questions.
 */
import { generateIdentities, SERVERS } from "./identities";
import {
  genBenignEdr, genPhishingChain, genAdAuth,
  genPasswordSpray, genPhishingEmail, genDnsQueries, genDnsTunneling,
  genVpnLogin, genCloudTrailExfil,
} from "./generators";
import type { Alert, IOC, ScenarioBundle, ScenarioQuestion, Severity, TelemetryEvent } from "./types";
import { rng, hashString, intBetween, pick } from "./rng";
import { makeSha256 } from "./iocs";

/** Convert a noisy event stream into curated SIEM-style alerts. */
function eventsToAlerts(events: TelemetryEvent[], scenario_id: string): Alert[] {
  const alerts: Alert[] = [];
  let aid = 0;
  for (const e of events) {
    if (!e.mitre_technique) continue;
    if (!e.severity || e.severity === "informational" || e.severity === "low") continue;

    aid += 1;
    const sevToConf: Record<Severity, number> = { critical: 95, high: 86, medium: 72, low: 55, informational: 30 };
    const sevToRisk: Record<Severity, number> = { critical: 92, high: 78, medium: 60, low: 40, informational: 15 };

    const title = titleForTechnique(e.mitre_technique, e);
    const desc  = descForTechnique(e.mitre_technique, e);
    const tactic = tacticForTechnique(e.mitre_technique);

    alerts.push({
      id: `alt_${scenario_id.slice(0,6)}_${aid}`,
      alert_uid: vendorAlertId(e.vendor ?? e.source, scenario_id, aid),
      title, description: desc,
      source: e.source, vendor: e.vendor ?? e.source.toUpperCase(),
      severity: e.severity,
      status: "new",
      confidence: sevToConf[e.severity],
      risk_score: sevToRisk[e.severity],
      mitre_tactic: tactic, mitre_technique: e.mitre_technique,
      hostname: e.hostname, user_email: e.user_email,
      src_ip: e.src_ip, dst_ip: e.dst_ip,
      process: e.process ? {
        name: e.process.name, cmdline: e.process.cmdline,
        parent: e.process.parent_name, sha256: e.file?.sha256,
      } : undefined,
      url: e.network?.url, domain: e.network?.domain,
      detected_at: e.ts,
      related_events: [e.id],
    });
  }
  return alerts;
}

function vendorAlertId(vendor: string, scenarioId: string, n: number): string {
  const v = vendor.toLowerCase();
  const tag = v.includes("crowd") ? "CRWD" :
              v.includes("sentinel") || v.includes("microsoft") ? "MDE" :
              v.includes("splunk") ? "SPL" :
              v.includes("palo") ? "PAN" :
              v.includes("okta") ? "OKTA" :
              v.includes("aws") || v.includes("cloudtrail") ? "AWS" :
              v.includes("sysmon") ? "SYSMON" : "SIEM";
  const h = (hashString(scenarioId + n).toString(16).toUpperCase().padStart(8, "0")).slice(0, 8);
  return `${tag}-${h}`;
}

function titleForTechnique(t: string, e: TelemetryEvent): string {
  switch (t) {
    case "T1566.001": return "Suspicious Office document with macro received";
    case "T1059.001": return "Encoded PowerShell command spawned by Office process";
    case "T1071.001": return "Outbound web traffic to uncategorized domain";
    case "T1027":     return "Suspicious DLL written to user TEMP directory";
    case "T1218.011": return "rundll32.exe executing user-writable DLL";
    case "T1547.001": return "Registry Run key persistence created";
    case "T1003.001": return "LSASS memory dump via comsvcs.dll MiniDump";
    case "T1110.003": return "Password spraying detected against multiple accounts";
    case "T1078":     return "Anomalous successful sign-in from new geography";
    case "T1071.004": return "DNS tunneling - high-entropy subdomain pattern";
    case "T1567.002": return "Large S3 object download to corporate user";
    default:          return `Detection: ${t}`;
  }
}

function descForTechnique(t: string, e: TelemetryEvent): string {
  const host = e.hostname ? ` on ${e.hostname}` : "";
  const user = e.user_email ? ` by ${e.user_email}` : "";
  switch (t) {
    case "T1566.001": return `Inbound email with macro-enabled attachment failed SPF/DKIM/DMARC and was delivered${user}.`;
    case "T1059.001": return `WINWORD.EXE spawned powershell.exe with -EncodedCommand and Hidden window${host}.`;
    case "T1071.001": return `powershell.exe initiated TLS connection to a recently-registered domain${host}.`;
    case "T1027":     return `An executable DLL was dropped to %TEMP% by a non-installer process${host}.`;
    case "T1218.011": return `rundll32.exe loaded a DLL from a user-writable path - common LOLBin abuse${host}.`;
    case "T1547.001": return `A new HKCU Run key was added pointing to a binary in %TEMP%${host}.`;
    case "T1003.001": return `comsvcs.dll MiniDump used to dump LSASS memory - classic credential theft pattern${host}.`;
    case "T1110.003": return `Multiple authentication failures across accounts from the same source IP indicates spraying${user}.`;
    case "T1078":     return `Successful authentication from country never seen for this user${user}.`;
    case "T1071.004": return `DNS queries with 48+ char base32-like subdomains and TXT record types${host}.`;
    case "T1567.002": return `Large data transfer (>100MB) to S3 outside normal business pattern${user}.`;
    default:          return `Detection triggered: ${t}`;
  }
}

function tacticForTechnique(t: string): string | undefined {
  if (t.startsWith("T1566")) return "TA0001";
  if (t.startsWith("T1059")) return "TA0002";
  if (t.startsWith("T1547") || t.startsWith("T1543")) return "TA0003";
  if (t.startsWith("T1218") || t.startsWith("T1027") || t.startsWith("T1562")) return "TA0005";
  if (t.startsWith("T1003") || t.startsWith("T1110") || t.startsWith("T1555")) return "TA0006";
  if (t.startsWith("T1071")) return "TA0011";
  if (t.startsWith("T1567") || t.startsWith("T1041")) return "TA0010";
  if (t.startsWith("T1486") || t.startsWith("T1490")) return "TA0040";
  if (t === "T1078") return "TA0001";
  return undefined;
}

function eventsToIocs(events: TelemetryEvent[]): IOC[] {
  const m = new Map<string, IOC>();
  const add = (type: IOC["type"], value: string, sev?: Severity, ts?: string) => {
    if (!value) return;
    const k = `${type}:${value}`;
    const ex = m.get(k);
    if (ex) { ex.count = (ex.count ?? 0) + 1; ex.last_seen = ts ?? ex.last_seen; }
    else m.set(k, {
      type, value, count: 1, first_seen: ts, last_seen: ts,
      reputation: sev === "critical" || sev === "high" ? "malicious" : sev === "medium" ? "suspicious" : "unknown",
    });
  };
  for (const e of events) {
    if (!e.mitre_technique) continue;
    add("host", e.hostname ?? "", e.severity, e.ts);
    add("user", e.user_email ?? "", e.severity, e.ts);
    add("ip", e.dst_ip ?? "", e.severity, e.ts);
    add("domain", e.network?.domain ?? "", e.severity, e.ts);
    add("url", e.network?.url ?? "", e.severity, e.ts);
    add("sha256", e.file?.sha256 ?? "", e.severity, e.ts);
  }
  return [...m.values()].filter(i => i.value);
}

// =========================================================================
// Scenario: Phishing → Foothold → Credential Theft → Cloud Exfil
// =========================================================================

export function buildPhishingToExfil(scenarioId = "phish-exfil-2026", seed = 1337): ScenarioBundle {
  const base = Date.now() - 86400_000;
  const users = generateIdentities(40, seed);
  const victim = users[0];

  const events: TelemetryEvent[] = [];

  // Background noise
  for (const u of users.slice(0, 12)) events.push(...genBenignEdr(u, base - 3600_000, 4, seed + hashString(u.username)));
  events.push(...genDnsQueries(victim, base - 3600_000, 18, seed));

  // Phishing email
  events.push(genPhishingEmail(victim, base, seed));
  // 30s later user opens it -> chain begins
  events.push(...genPhishingChain(victim, base + 30_000, seed));
  // C2 beaconing - DNS tunneling
  events.push(...genDnsTunneling(victim, base + 600_000, 24, seed + 7));
  // Lateral via stolen creds: anomalous Okta SSO from new geo
  const t78 = genVpnLogin(victim, base + 1800_000, "RU", seed + 11);
  events.push(t78);
  // Cloud exfil
  events.push(...genCloudTrailExfil(victim, base + 2400_000, seed + 13));

  events.sort((a, b) => a.ts.localeCompare(b.ts));

  const alerts = eventsToAlerts(events, scenarioId);
  const iocs = eventsToIocs(events);

  const killchain = [
    { ts: events[0].ts, phase: "Initial Access",      action: "Phishing email with malicious .docm attachment delivered to user inbox" },
    { ts: events[1]?.ts ?? events[0].ts, phase: "Execution", action: "User opens document; macro launches encoded PowerShell" },
    { ts: events.find(e => e.mitre_technique === "T1071.001")?.ts ?? events[0].ts, phase: "Command & Control", action: "PowerShell beacons to attacker C2 over HTTPS" },
    { ts: events.find(e => e.mitre_technique === "T1547.001")?.ts ?? events[0].ts, phase: "Persistence", action: "HKCU Run key added pointing at dropped DLL" },
    { ts: events.find(e => e.mitre_technique === "T1003.001")?.ts ?? events[0].ts, phase: "Credential Access", action: "LSASS dumped via comsvcs.dll MiniDump" },
    { ts: events.find(e => e.mitre_technique === "T1078")?.ts ?? events[0].ts, phase: "Lateral / Identity",  action: "Stolen creds reused from foreign IP" },
    { ts: events.find(e => e.mitre_technique === "T1567.002")?.ts ?? events[0].ts, phase: "Exfiltration",    action: "184MB S3 object downloaded to compromised user" },
  ];

  const questions: ScenarioQuestion[] = [
    { id: "q1", prompt: "Which MITRE technique best matches the initial access vector?", kind: "single",
      options: [
        { value: "T1566.001", label: "T1566.001 - Spearphishing Attachment" },
        { value: "T1190",     label: "T1190 - Exploit Public-Facing Application" },
        { value: "T1078",     label: "T1078 - Valid Accounts" },
        { value: "T1133",     label: "T1133 - External Remote Services" },
      ],
      answer: "T1566.001", xp: 50,
      explanation: "Inbound .docm attachment with macros that spawned a child process matches Spearphishing Attachment." },
    { id: "q2", prompt: "What is the parent process of the suspicious powershell.exe?", kind: "single",
      options: [
        { value: "OUTLOOK.EXE", label: "OUTLOOK.EXE" },
        { value: "WINWORD.EXE", label: "WINWORD.EXE" },
        { value: "explorer.exe",label: "explorer.exe" },
        { value: "rundll32.exe",label: "rundll32.exe" },
      ],
      answer: "WINWORD.EXE", xp: 50,
      explanation: "Office spawning powershell is the canonical macro-execution pattern." },
    { id: "q3", prompt: "Which two artifacts indicate persistence?", kind: "multi",
      options: [
        { value: "run_key", label: "HKCU Run key WindowsUpdater" },
        { value: "lsass",   label: "LSASS MiniDump" },
        { value: "dll",     label: "DLL dropped to %TEMP%" },
        { value: "okta",    label: "Okta SSO from RU" },
      ],
      answer: ["run_key","dll"], xp: 75,
      explanation: "The Run key + the dropped DLL together form the autorun persistence." },
    { id: "q4", prompt: "What single action would best contain the active host?", kind: "single",
      options: [
        { value: "isolate", label: "Network-isolate the endpoint via EDR" },
        { value: "reboot",  label: "Reboot the endpoint" },
        { value: "block_ip",label: "Block the C2 IP at the firewall only" },
        { value: "warn",    label: "Email the user a warning" },
      ],
      answer: "isolate", xp: 50,
      explanation: "Isolation halts both C2 and lateral spread immediately - reboot/IP-block alone leave persistence intact." },
  ];

  return {
    scenario_id: scenarioId,
    title: "Phishing-to-Cloud Exfiltration",
    threat_actor: "TA-COBALTSPIDER (financially motivated)",
    attack_kind: "phishing_to_exfil",
    narrative:
`At 09:47 local time, a finance analyst at ${"Cryotech Industries"} received an invoice email that bypassed mail-flow rules with failed SPF, DKIM, and DMARC. Twenty seconds after the user opened the attachment, an Office process spawned an obfuscated PowerShell command. Within 90 seconds, the host was beaconing to a recently registered domain over TLS, dropping a DLL into %TEMP%, and registering a Run key for persistence. Twelve minutes later, comsvcs.dll was used to dump LSASS memory. Thirty minutes later, the same user's identity authenticated from a foreign geography, and 184MB was downloaded out of an S3 bucket containing customer financial exports. Your job: piece together the full kill chain, scope blast radius, and recommend containment.`,
    alerts, events, iocs, killchain, questions,
  };
}

// =========================================================================
// Scenario: Identity-driven (password spray → BEC → mailbox rules)
// =========================================================================

export function buildBecScenario(scenarioId = "bec-spray-2026", seed = 9001): ScenarioBundle {
  const base = Date.now() - 7200_000;
  const users = generateIdentities(30, seed);
  const targets = users.slice(0, 14);
  const victim = targets[3];

  const events: TelemetryEvent[] = [];
  events.push(...genPasswordSpray(targets, base, seed));
  events.push(genVpnLogin(victim, base + 600_000, "NL", seed + 5));
  events.push({
    id: `evt_mbx_${seed}`,
    ts: new Date(base + 660_000).toISOString(),
    source: "o365", vendor: "Microsoft 365 UAL", event_type: "account_modify",
    user_email: victim.email,
    severity: "high", mitre_technique: "T1078",
    raw: {
      operation: "New-InboxRule",
      rule_name: "..", // attackers use dot/space names to hide
      conditions: { from_contains: ["wire","invoice","banking"] },
      actions: { move_to_folder: "RSS Feeds", mark_as_read: true, delete: false },
      client_ip: "185.220.101.4",
    },
  });

  const alerts = eventsToAlerts(events, scenarioId);
  const iocs = eventsToIocs(events);
  const killchain = [
    { ts: events[0].ts, phase: "Credential Access", action: "Password spray across 14 finance/exec accounts" },
    { ts: events.find(e => e.event_type === "auth_success")?.ts ?? events[0].ts, phase: "Initial Access", action: "Successful auth via push-fatigue MFA" },
    { ts: events.find(e => e.event_type === "account_modify")?.ts ?? events[0].ts, phase: "Persistence / Collection", action: "Hidden inbox rule moves wire/invoice mail to RSS Feeds" },
  ];

  const questions: ScenarioQuestion[] = [
    { id: "q1", prompt: "What is the most likely intent of the inbox rule named '..'?", kind: "single",
      options: [
        { value: "bec",      label: "Business Email Compromise: hide wire-fraud replies from victim" },
        { value: "archival", label: "Personal email archival" },
        { value: "spam",     label: "Anti-spam routing" },
        { value: "delegation",label: "Delegate access to assistant" },
      ],
      answer: "bec", xp: 75,
      explanation: "Hidden rule + wire/invoice keywords + obscure folder = BEC playbook." },
    { id: "q2", prompt: "Which MITRE techniques are present? (multi)", kind: "multi",
      options: [
        { value: "T1110.003", label: "T1110.003 Password Spraying" },
        { value: "T1078",     label: "T1078 Valid Accounts" },
        { value: "T1486",     label: "T1486 Data Encrypted for Impact" },
        { value: "T1098.005", label: "T1098.005 Mail Forwarding Rule" },
      ],
      answer: ["T1110.003","T1078","T1098.005"], xp: 100,
      explanation: "Spray + reused valid creds + mail-rule abuse - no encryption took place." },
  ];

  return {
    scenario_id: scenarioId,
    title: "Password Spray → BEC Mailbox Rule",
    threat_actor: "TA-VOIDPELICAN (BEC operator)",
    attack_kind: "identity_bec",
    narrative:
`Over a 12-minute window, 14 accounts in Finance and Executive were probed by a single foreign IP. One account succeeded - the user accepted a push notification at 02:14 local. Six minutes later, the account authenticated from the Netherlands and immediately added an inbox rule to silently move wire and invoice emails to a rarely-checked folder. The attacker is preparing to impersonate the user for a fraudulent wire transfer.`,
    alerts, events, iocs, killchain, questions,
  };
}

// Registry of available scenarios
export const SCENARIOS = [
  { slug: "phishing-to-cloud-exfil", title: "Phishing → Cloud Exfiltration",
    difficulty: "intermediate", attack_kind: "phishing_to_exfil",
    threat_actor: "TA-COBALTSPIDER", build: buildPhishingToExfil,
    summary: "A finance analyst opens a macro-laced invoice. Track the attacker through PowerShell, credential theft, and a 184MB S3 exfil." },
  { slug: "bec-mailbox-rule",        title: "Password Spray → BEC Mailbox Rule",
    difficulty: "beginner", attack_kind: "identity_bec",
    threat_actor: "TA-VOIDPELICAN", build: buildBecScenario,
    summary: "Spot the spray, the foreign sign-in, and the hidden inbox rule before the wire fraud lands." },
] as const;

export function buildScenarioBySlug(slug: string): ScenarioBundle | null {
  const found = SCENARIOS.find(s => s.slug === slug);
  if (!found) return null;
  return found.build();
}
