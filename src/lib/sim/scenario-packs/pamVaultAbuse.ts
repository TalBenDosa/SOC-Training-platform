/**
 * Scenario pack: "PAM Vault Abuse — an Off-Hours Domain-Admin Checkout Used Outside PSM"
 *
 * ADVANCED tier. The platform's first Privileged-Access-Management scenario. The
 * whole case turns on a distinction that a privileged logon alone can never make:
 * a domain-administrator credential is a legitimate thing to hold, and a 02:00
 * logon by an admin account is, on its own, unremarkable. What makes this an
 * incident is HOW the credential left the vault and HOW it was then used.
 *
 * CyberArk brokers privileged credentials two ways. The sanctioned path is a PSM
 * (Privileged Session Manager) session: the operator never sees the password —
 * CyberArk injects it into a proxied, fully-recorded RDP/SSH session, and on a
 * high-value safe a second person must confirm the request (dual control). The
 * other path is "Retrieve Password": the plaintext is copied to the operator's
 * clipboard and they do whatever they like with it, unmonitored. The tell in this
 * scenario is that the domain-admin credential was RETRIEVED (copied), off-hours,
 * with no dual-control confirmation and no change record — and was then replayed
 * from the engineer's own workstation to log into servers directly, bypassing the
 * monitored PSM proxy the policy requires.
 *
 * THE ATTACK CHAIN (the spine):
 *   1. CyberArk "Retrieve Password" on the vaulted domain-admin object at 02:10,
 *      dual control NOT confirmed, no linked change ticket, from a server-ops
 *      engineer's workstation — a credential copied out, not brokered by PSM.
 *   2. The credential authenticates: a 4768 TGT for the DA account is requested
 *      from that same workstation minutes later.
 *   3. A 4624 LogonType-10 (RemoteInteractive / RDP) lands on the finance SQL
 *      server SRV-FIN-DB-02, sourced from the engineer's workstation — NOT from
 *      the PSM proxy host. A 4672 confirms the session carries admin privileges.
 *   4. Sysmon on SRV-FIN-DB-02 shows the operator querying the finance database
 *      under that session — the credential used interactively, outside PSM.
 *   5. From SRV-FIN-DB-02 the operator pivots on: a 4769 service ticket for the
 *      Domain Controller, then a 4624 LogonType-3 on DC-NEXA-01.
 *
 * THE BENIGN CONTROL (evt 1): a genuine break-glass emergency checkout of the
 * SAME domain-admin object, ALSO off-hours — but with a dual-control approver, a
 * linked change ticket, and used THROUGH a recorded PSM session during an on-call
 * window. Same "privileged credential left the vault" shape, opposite verdict.
 * The discriminators are approval + monitored-session, never the fact of the
 * checkout or the hour.
 *
 * SOURCES: cyberark (CyberArk PAM vault activity — the checkouts, the PSM
 * session, dual control), microsoft-active-directory (the privileged Kerberos /
 * network logons 4768 / 4624 / 4672 / 4769 on the target servers), sysmon (a
 * corroborating process on the target host).
 *
 * NOTE: register in scenarios.ts with difficulty "advanced". The ScenarioBundle
 * itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildPamVaultAbuseScenario(
  scenarioId = "pam-vault-abuse-2026",
): ScenarioBundle {
  const B = new Date("2026-08-30T02:10:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident — the whole checkout-and-reuse chain is a single case.
  const INCIDENT = "inc:pva:1";

  // The estate.
  const dc = { hostname: "DC-NEXA-01", fqdn: "DC-NEXA-01.nexacorp.com", ip: "10.20.5.10" };
  const finDb = { hostname: "SRV-FIN-DB-02", fqdn: "SRV-FIN-DB-02.nexacorp.com", ip: "10.20.7.42" };
  const psmHost = { hostname: "PSM-NEXA-01", fqdn: "PSM-NEXA-01.nexacorp.com", ip: "10.20.9.15" };

  // The on-call server-ops engineer who performs (or is credited with) the
  // checkout. He does not normally hold domain-admin; his role is patching.
  const engineer = { sam: "r.dunphy", email: "r.dunphy@nexacorp.com", title: "Server Operations Engineer" };
  const engineerWs = { hostname: "WKS-ROPS-14", ip: "10.20.6.77" };

  // The vaulted privileged object — a domain-admin account CyberArk manages.
  const daAccount = "adm-nexa-da";
  const daSid = "S-1-5-21-3421479547-3897544621-1789562108-1618";
  const vaultObject = "WinDomain-nexacorp.com-adm-nexa-da";
  const vaultName = "NEXA-PAM-Vault";
  const daSafe = "Windows-Domain-Admins";

  // Break-glass approver for the benign control.
  const approver = "t.marsh";

  // A corroborating process hash on the target host (the DB client the operator
  // ran under the RDP session). Synthetic, structurally a real sha256.
  const dbClientHash = makeSha256("pamvaultabuse_sqlcmd_client_on_srv_fin_db_02_2026");

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — a sanctioned break-glass emergency checkout.
    //    SAME domain-admin object, ALSO off-hours, but dual-control confirmed,
    //    a linked change ticket, and used THROUGH a recorded PSM session.
    //    This is what a legitimate privileged checkout looks like.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_pva_00_breakglass_psm",
      ts: "2026-08-23T03:02:11.000Z",
      source: "iam",
      vendor: "CyberArk PAM",
      event_type: "privileged_operation",
      hostname: psmHost.hostname,
      user_email: engineer.email,
      user_title: engineer.title,
      src_ip: psmHost.ip,
      severity: "informational",
      expected_verdict: "fp",
      incident_id: INCIDENT,
      fp_explanation:
        "This is the control case for the whole scenario, and it should be compared against every later event. It is an emergency break-glass checkout of the exact same domain-admin object, and it is ALSO in the middle of the night — so neither 'a domain-admin credential left the vault' nor 'off-hours' is what makes something an incident. Three things make this one sanctioned: a second person confirmed it (dual control, access request AR-NEXA-77120 approved by t.marsh); it is tied to a real change record (CHG0049211, an emergency DB failover); and the operator never handled the password — CyberArk brokered it into a recorded PSM RDP session (pam.session.type PSM-RDP), and rotated the credential afterwards. The flagged 02:10 checkout does none of these.",
      description:
        "During a prior on-call window CyberArk brokered the domain-admin object adm-nexa-da into a recorded PSM RDP session for r.dunphy: dual-control confirmed by t.marsh under access request AR-NEXA-77120, linked to change CHG0049211, credential rotated at session close.",
      raw: {
        "cyberark.event_type": "PSM Connect",
        "cyberark.safe": daSafe,
        "cyberark.object": vaultObject,
        "cyberark.reason": "Emergency DB failover on SRV-FIN-DB-02 - CHG0049211",
        "cyberark.dual_control": "confirmed",
        "cyberark.station": psmHost.ip,
        "pam.vault.name": vaultName,
        "pam.account.name": daAccount,
        "pam.session.type": "PSM-RDP",
        "pam.session.id": "PSM-8841203",
        "pam.checkout.status": "approved",
        "pam.password.rotation": "true",
        "access.request.id": "AR-NEXA-77120",
        "access.request.status": "approved",
        "access.request.approver": approver,
        "event.category": "session",
        "event.type": "start",
        "event.action": "psm-session-start",
        "event.outcome": "success",
        "user.name": engineer.sam,
        "target.user.name": daAccount,
        "source.ip": psmHost.ip,
        "source.hostname": psmHost.hostname,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE FLAGGED CHECKOUT — Retrieve Password on the DA object at 02:10.
    //    dual control NOT confirmed, no change ticket, from the engineer's own
    //    workstation. The plaintext is copied out, NOT brokered by PSM.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_pva_01_retrieve_password",
      ts: T(0),
      source: "iam",
      vendor: "CyberArk PAM",
      event_type: "privileged_operation",
      hostname: engineerWs.hostname,
      user_email: engineer.email,
      user_title: engineer.title,
      src_ip: engineerWs.ip,
      severity: "high",
      mitre_technique: "T1555.005",
      mitre_tactic: "Credential Access",
      incident_id: INCIDENT,
      description:
        "CyberArk recorded a Retrieve Password on the domain-admin object adm-nexa-da at 02:10 from WKS-ROPS-14: retrieval method Copy, dual control not confirmed, no linked access request or change record, and no PSM session opened.",
      raw: {
        "cyberark.event_type": "Retrieve Password",
        "cyberark.safe": daSafe,
        "cyberark.object": vaultObject,
        "cyberark.reason": "adhoc",
        "cyberark.dual_control": "not confirmed",
        "cyberark.retrieval_method": "Copy",
        "cyberark.station": engineerWs.ip,
        "pam.vault.name": vaultName,
        "pam.account.name": daAccount,
        "pam.session.type": "None",
        "pam.checkout.status": "completed",
        "pam.password.rotation": "false",
        "access.request.id": "-",
        "access.request.status": "not_requested",
        "access.request.approver": "-",
        "event.category": "iam",
        "event.type": "info",
        "event.action": "retrieve-password",
        "event.outcome": "success",
        "user.name": engineer.sam,
        "target.user.name": daAccount,
        "source.ip": engineerWs.ip,
        "source.hostname": engineerWs.hostname,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. THE CREDENTIAL AUTHENTICATES — a 4768 TGT for the DA account is
    //    requested from the engineer's workstation, minutes after the copy.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_pva_02_tgt_request",
      ts: T(3 * MIN),
      source: "ad",
      vendor: "Microsoft Active Directory",
      event_type: "kerberos_tgt",
      hostname: dc.hostname,
      user_email: engineer.email,
      src_ip: engineerWs.ip,
      severity: "medium",
      mitre_technique: "T1078.002",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      description:
        "DC-NEXA-01 logged a 4768 Kerberos TGT request for adm-nexa-da at 02:13, sourced from WKS-ROPS-14 (10.20.6.77) — the domain-admin credential authenticating from a server-ops engineer's workstation.",
      raw: {
        "winlog.event_id": "4768",
        "winlog.channel": "Security",
        "winlog.computer_name": dc.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "10442051",
        "winlog.event_data.TargetUserName": daAccount,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetSid": daSid,
        "winlog.event_data.ServiceName": "krbtgt",
        "winlog.event_data.ServiceSid": "S-1-5-21-3421479547-3897544621-1789562108-502",
        "winlog.event_data.TicketOptions": "0x40810010",
        "winlog.event_data.TicketEncryptionType": "0x12",
        "winlog.event_data.PreAuthType": "2",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.IpAddress": "::ffff:10.20.6.77",
        "winlog.event_data.IpPort": "51122",
        "event.code": "4768",
        "event.action": "kerberos-tgt-requested",
        "event.outcome": "success",
        "source.ip": engineerWs.ip,
        "user.name": daAccount,
        "user.domain": "NEXACORP",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. RDP INTO THE FINANCE DB SERVER — a 4624 LogonType 10 on SRV-FIN-DB-02,
    //    sourced from the engineer's workstation, NOT the PSM proxy host.
    //    The credential used directly, outside the monitored session.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_pva_03_rdp_logon",
      ts: T(4 * MIN),
      source: "ad",
      vendor: "Microsoft Active Directory",
      event_type: "auth_success",
      hostname: finDb.hostname,
      user_email: engineer.email,
      src_ip: engineerWs.ip,
      severity: "high",
      mitre_technique: "T1021.001",
      mitre_tactic: "Lateral Movement",
      incident_id: INCIDENT,
      description:
        "A 4624 RemoteInteractive logon for adm-nexa-da landed on SRV-FIN-DB-02 at 02:14, LogonType 10 over Kerberos, from WKS-ROPS-14 (10.20.6.77) — a direct RDP into the finance database server, whose source is the engineer's workstation rather than the PSM proxy PSM-NEXA-01.",
      authentication: { method: "Kerberos", result: "success", logon_type: 10 },
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": finDb.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "7781140",
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.SubjectLogonId": "0x0",
        "winlog.event_data.TargetUserSid": daSid,
        "winlog.event_data.TargetUserName": daAccount,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0x9F2C41A",
        "winlog.event_data.LogonType": "10",
        "winlog.event_data.LogonProcessName": "User32 ",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": engineerWs.hostname,
        "winlog.event_data.LogonGuid": "{7c9a1f04-2b6e-8d31-5a02-c14477e9a0b3}",
        "winlog.event_data.IpAddress": engineerWs.ip,
        "winlog.event_data.IpPort": "51993",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1842",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "source.ip": engineerWs.ip,
        "user.name": daAccount,
        "user.domain": "NEXACORP",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. 4672 — the RDP session carries admin privileges. Confirms the
    //    checked-out credential is a highly-privileged account.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_pva_04_special_privs",
      ts: T(4 * MIN + 5 * SEC),
      source: "ad",
      vendor: "Microsoft Active Directory",
      event_type: "privilege_escalation",
      hostname: finDb.hostname,
      user_email: engineer.email,
      src_ip: engineerWs.ip,
      severity: "medium",
      mitre_technique: "T1078.002",
      mitre_tactic: "Privilege Escalation",
      incident_id: INCIDENT,
      description:
        "A 4672 on SRV-FIN-DB-02 assigned SeDebugPrivilege, SeTakeOwnershipPrivilege and SeBackupPrivilege to the adm-nexa-da logon session — the RDP session is running with domain-administrator rights on the finance database server.",
      raw: {
        "winlog.event_id": "4672",
        "winlog.channel": "Security",
        "winlog.computer_name": finDb.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "7781141",
        "winlog.event_data.SubjectUserSid": daSid,
        "winlog.event_data.SubjectUserName": daAccount,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x9F2C41A",
        "winlog.event_data.PrivilegeList":
          "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeImpersonatePrivilege",
        "event.code": "4672",
        "event.action": "logged-in-special",
        "event.outcome": "success",
        "user.name": daAccount,
        "user.domain": "NEXACORP",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. Sysmon Event 1 — the operator queries the finance database under the
    //    RDP session. The credential used interactively, on the target host,
    //    outside any PSM recording.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_pva_05_db_query",
      ts: T(6 * MIN),
      source: "sysmon",
      vendor: "Microsoft Sysmon",
      event_type: "process_create",
      hostname: finDb.hostname,
      user_email: engineer.email,
      src_ip: finDb.ip,
      severity: "high",
      mitre_technique: "T1078.002",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      description:
        "Sysmon on SRV-FIN-DB-02 recorded adm-nexa-da running sqlcmd under the interactive RDP session, querying the finance database directly — the vaulted credential being used hands-on-keyboard on the target host.",
      process: {
        name: "sqlcmd.exe",
        pid: 6712,
        path: "C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\sqlcmd.exe",
        parent_name: "cmd.exe",
        parent_pid: 6488,
        cmdline: "sqlcmd -S SRV-FIN-DB-02 -E -Q \"SELECT TOP 500 * FROM Finance.dbo.WireTransfers\"",
        user: `NEXACORP\\${daAccount}`,
        integrity: "high",
        hash: { sha256: dbClientHash },
      },
      raw: {
        "winlog.event_id": "1",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.computer_name": finDb.fqdn,
        "winlog.event_data.Image":
          "C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\sqlcmd.exe",
        "winlog.event_data.OriginalFileName": "sqlcmd.exe",
        "winlog.event_data.CommandLine":
          "sqlcmd -S SRV-FIN-DB-02 -E -Q \"SELECT TOP 500 * FROM Finance.dbo.WireTransfers\"",
        "winlog.event_data.ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "winlog.event_data.ParentProcessId": "6488",
        "winlog.event_data.ProcessId": "6712",
        "winlog.event_data.User": `NEXACORP\\${daAccount}`,
        "winlog.event_data.IntegrityLevel": "High",
        "winlog.event_data.LogonId": "0x9F2C41A",
        "winlog.event_data.Hashes": `SHA256=${dbClientHash}`,
        "host.name": finDb.hostname,
        "host.ip": finDb.ip,
        "process.name": "sqlcmd.exe",
        "process.hash.sha256": dbClientHash,
        "event.code": "1",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. 4769 — a service ticket for the Domain Controller is requested from
    //    the SRV-FIN-DB-02 session. The operator pivoting onward.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_pva_06_tgs_request",
      ts: T(9 * MIN),
      source: "ad",
      vendor: "Microsoft Active Directory",
      event_type: "kerberos_tgs",
      hostname: dc.hostname,
      user_email: engineer.email,
      src_ip: finDb.ip,
      severity: "high",
      mitre_technique: "T1021.002",
      mitre_tactic: "Lateral Movement",
      incident_id: INCIDENT,
      description:
        "DC-NEXA-01 logged a 4769 service-ticket request by adm-nexa-da for the DC's CIFS service, sourced from SRV-FIN-DB-02 (10.20.7.42) — the domain-admin credential reaching from the finance server toward the Domain Controller.",
      raw: {
        "winlog.event_id": "4769",
        "winlog.channel": "Security",
        "winlog.computer_name": dc.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "10442310",
        "winlog.event_data.TargetUserName": `${daAccount}@NEXACORP.COM`,
        "winlog.event_data.TargetDomainName": "NEXACORP.COM",
        "winlog.event_data.ServiceName": "DC-NEXA-01$",
        "winlog.event_data.ServiceSid": "S-1-5-21-3421479547-3897544621-1789562108-1001",
        "winlog.event_data.TicketOptions": "0x40810000",
        "winlog.event_data.TicketEncryptionType": "0x12",
        "winlog.event_data.IpAddress": "::ffff:10.20.7.42",
        "winlog.event_data.IpPort": "52140",
        "winlog.event_data.Status": "0x0",
        "event.code": "4769",
        "event.action": "kerberos-service-ticket-requested",
        "event.outcome": "success",
        "source.ip": finDb.ip,
        "user.name": daAccount,
        "user.domain": "NEXACORP",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. THE PIVOT LANDS — a 4624 LogonType 3 on DC-NEXA-01, same DA account,
    //    now sourced from SRV-FIN-DB-02. The credential reaches the DC.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_pva_07_dc_logon",
      ts: T(10 * MIN),
      source: "ad",
      vendor: "Microsoft Active Directory",
      event_type: "auth_success",
      hostname: dc.hostname,
      user_email: engineer.email,
      src_ip: finDb.ip,
      severity: "critical",
      mitre_technique: "T1021.002",
      mitre_tactic: "Lateral Movement",
      incident_id: INCIDENT,
      description:
        "A 4624 network logon for adm-nexa-da landed on DC-NEXA-01 at 02:20, LogonType 3 over Kerberos, sourced from SRV-FIN-DB-02 (10.20.7.42) — the checked-out credential reaching a Domain Controller one hop on from the finance server.",
      authentication: { method: "Kerberos", result: "success", logon_type: 3 },
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": dc.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "10442355",
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.SubjectLogonId": "0x0",
        "winlog.event_data.TargetUserSid": daSid,
        "winlog.event_data.TargetUserName": daAccount,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0xB1730E2",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.LogonProcessName": "Kerberos",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": finDb.hostname,
        "winlog.event_data.IpAddress": finDb.ip,
        "winlog.event_data.IpPort": "49882",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1842",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "source.ip": finDb.ip,
        "user.name": daAccount,
        "user.domain": "NEXACORP",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "user",
      value: daAccount, // adm-nexa-da — the vaulted domain-admin object that was checked out
      first_seen: T(0),
      last_seen: T(10 * MIN),
      reputation: "suspicious",
      tags: ["domain-admin", "vaulted-account", "checked-out"],
    },
    {
      type: "user",
      value: engineer.sam, // r.dunphy — the engineer credited with the checkout
      first_seen: T(0),
      last_seen: T(10 * MIN),
      reputation: "unknown",
      tags: ["server-ops", "requester", "off-hours"],
    },
    {
      type: "host",
      value: engineerWs.hostname, // WKS-ROPS-14 — where the password was copied and first replayed
      first_seen: T(0),
      last_seen: T(4 * MIN),
      reputation: "suspicious",
      tags: ["checkout-station", "outside-psm", "workstation"],
    },
    {
      type: "ip",
      value: engineerWs.ip, // 10.20.6.77 — the checkout / first-logon source address
      first_seen: T(0),
      last_seen: T(4 * MIN),
      reputation: "suspicious",
      tags: ["checkout-source", "internal"],
    },
    {
      type: "host",
      value: finDb.hostname, // SRV-FIN-DB-02 — the finance DB server reached, and the pivot origin
      first_seen: T(4 * MIN),
      last_seen: T(10 * MIN),
      reputation: "unknown",
      tags: ["finance-db", "reached", "pivot-origin"],
    },
    {
      type: "host",
      value: dc.hostname, // DC-NEXA-01 — the Domain Controller the credential reached
      first_seen: T(10 * MIN),
      last_seen: T(10 * MIN),
      reputation: "unknown",
      tags: ["domain-controller", "tier-0", "reached"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "pva_q1",
      xp: 60,
      kind: "single",
      prompt:
        "The break-glass control (evt_pva_00) and the flagged checkout (evt_pva_01) both take the SAME domain-admin object out of the vault, and BOTH happen off-hours. Which combination separates the flagged checkout from the sanctioned one?",
      hint: "Read cyberark.dual_control, access.request.status and pam.session.type on each of the two CyberArk records.",
      options: [
        { value: "no_approval_no_psm", label: "The flagged checkout shows no dual-control confirmation, no access request, and pam.session.type None (Retrieve Password) — the control was confirmed and ran through a recorded PSM session" },
        { value: "off_hours", label: "The flagged checkout happens at 02:10 while the control ran in standard business hours, and that shift outside working hours is the single fact that makes it a policy violation" },
        { value: "diff_account", label: "The flagged checkout pulls a more privileged account than the control, which retrieved only a lower-tier service credential from a separate area of the same vault" },
        { value: "diff_safe", label: "The two checkouts are served from different vault safes, and only the safe behind the flagged checkout actually stores domain-admin credentials at all" },
      ],
      answer: "no_approval_no_psm",
      explanation:
        "Both records retrieve adm-nexa-da from the Windows-Domain-Admins safe, and both are in the small hours — so neither the account nor the hour is the discriminator. The difference is entirely in the governance fields. The control (evt_pva_00) shows cyberark.dual_control=confirmed, access.request.status=approved (AR-NEXA-77120, approver t.marsh), a change reference in the reason, and pam.session.type=PSM-RDP: a second person authorised it and CyberArk brokered the password into a recorded proxy session the operator never saw. The flagged checkout (evt_pva_01) is cyberark.event_type=Retrieve Password with retrieval_method=Copy, dual_control=not confirmed, access.request.status=not_requested, and pam.session.type=None — the plaintext copied to the clipboard with nobody confirming and nothing recorded. (b) is refuted because BOTH are off-hours. (c) is false — same object, same SID. (d) is false — same safe.",
    },
    {
      id: "pva_q2",
      xp: 65,
      kind: "single",
      prompt:
        "Policy requires privileged credentials to be used through the monitored PSM proxy. Which evidence shows the checked-out credential was instead used OUTSIDE PSM?",
      hint: "Compare the source of the AD logons (WorkstationName / IpAddress) against the PSM proxy host, and read what CyberArk recorded as the session type.",
      options: [
        { value: "source_not_psm", label: "The 4768 and the 4624 (LogonType 10) originate from WKS-ROPS-14, not the PSM proxy PSM-NEXA-01, and CyberArk logged a Retrieve Password with session type None rather than a PSM Connect" },
        { value: "special_privs", label: "The 4672 special-privileges assignment proves PSM was skipped, because credentials brokered through a PSM session never trigger a special-privileges event on the target host" },
        { value: "kerberos", label: "The logons authenticate with Kerberos rather than NTLM, and because PSM proxied sessions always fall back to NTLM, seeing Kerberos here means the proxy was bypassed" },
        { value: "tgs_dc", label: "The 4769 service-ticket request to the Domain Controller is the proof, since the PSM proxy is specifically designed to block all downstream Kerberos service tickets" },
      ],
      answer: "source_not_psm",
      explanation:
        "A PSM-brokered session originates FROM the PSM proxy host (PSM-NEXA-01, 10.20.9.15) — that is the whole point of the proxy: the target server sees PSM as the source, and CyberArk records a PSM Connect with a session id. Here the CyberArk record is a Retrieve Password (Copy) with pam.session.type=None, and the resulting AD logons — the 4768 TGT and the 4624 LogonType-10 RDP — both carry WorkstationName WKS-ROPS-14 and IpAddress 10.20.6.77, the engineer's workstation. The credential was copied out and replayed directly, with no proxy in the path. (b) is wrong: 4672 fires for any admin logon, PSM sessions included. (c) is wrong: PSM commonly uses Kerberos; the auth protocol does not indicate PSM vs direct. (d) is wrong: a 4769 is normal Kerberos activity and PSM does not block service tickets.",
    },
    {
      id: "pva_q3",
      xp: 60,
      kind: "single",
      prompt:
        "Setting aside how the credential left the vault, how would you characterise what the operator then DID with it across SRV-FIN-DB-02 and DC-NEXA-01?",
      hint: "The credential was a valid, working domain-admin password — nothing was cracked, replayed as a hash, or exploited.",
      options: [
        { value: "valid_account_remote", label: "Reuse of a legitimate, fully valid domain-admin credential over RDP and SMB to reach servers it never normally touches — valid-account abuse plus remote services, no vulnerability involved" },
        { value: "pth", label: "A pass-the-hash attack, in which the operator captured and replayed the NTLM hash of the domain-admin account against SRV-FIN-DB-02 and then the Domain Controller" },
        { value: "kerberoast", label: "Kerberoasting — the 4769 shows the operator harvesting an encrypted service-ticket hash for the account so its password can be cracked offline afterwards" },
        { value: "exploit", label: "Exploitation of an unpatched software vulnerability on SRV-FIN-DB-02 that elevated the logon session to domain-admin rights on the finance server" },
      ],
      answer: "valid_account_remote",
      explanation:
        "The credential was retrieved from the vault in plaintext and used exactly as intended to authenticate — the 4768 has PreAuth=2 and a normal AES256 ticket, the logons succeed cleanly, and no exploit or hash-replay artefact appears anywhere. This is the abuse of a valid domain account (obtaining and using legitimate domain-admin credentials) combined with remote-services movement (RDP onto the finance DB server, then a network logon onward to the DC). (b) is wrong: pass-the-hash replays an NTLM hash and shows an NTLM/NtLmSsp logon — here the credential is a real password driving Kerberos, and it was handed out by the vault, not dumped. (c) is wrong: a single 4769 as part of normal onward access is not Kerberoasting, which is many service-ticket requests for service accounts pulled for offline cracking. (d) is wrong: there is no exploitation evidence — the privilege came from a legitimate credential, not a vulnerability.",
    },
    {
      id: "pva_q4",
      xp: 70,
      kind: "single",
      prompt:
        "You are scoping containment. A vaulted domain-admin credential was copied out unmonitored and has already reached DC-NEXA-01. Which response matches the evidence?",
      hint: "Think about what actually invalidates a plaintext credential that is now in someone's clipboard, and how far the credential has already travelled.",
      options: [
        { value: "rotate_hunt_verify", label: "Rotate the adm-nexa-da password in CyberArk at once so the copied plaintext dies, review every adm-nexa-da logon since 02:10 on SRV-FIN-DB-02 and DC-NEXA-01, and verify with r.dunphy whether any emergency justified it" },
        { value: "block_ws_ip", label: "Block WKS-ROPS-14's address (10.20.6.77) at the firewall — cutting the workstation off the network stops the credential being replayed any further and closes the incident" },
        { value: "disable_engineer", label: "Disable r.dunphy's own user account and reset his personal password, since he initiated the checkout and locking his account down removes the exposure entirely" },
        { value: "reimage_db", label: "Reimage SRV-FIN-DB-02, because the credential was used there — wiping and rebuilding the finance server removes the operator's access and ends the incident" },
      ],
      answer: "rotate_hunt_verify",
      explanation:
        "The exposed secret is the domain-admin password itself, now sitting in plaintext on the operator's clipboard, so the one action that actually neutralises it is rotating (changing) the credential in CyberArk — after which the copied value is worthless. Because the credential already reached a Domain Controller, containment must also review every adm-nexa-da logon from the checkout onward on both SRV-FIN-DB-02 and DC-NEXA-01 (further logons, directory changes, new accounts) and treat tier-0 exposure as live, and it must verify with r.dunphy and the change process whether a real emergency justified this — because the benign control shows exactly what a legitimate break-glass looks like. (b) fails: 10.20.6.77 is an internal workstation, and blocking it does nothing about the password already replayed onward to SRV-FIN-DB-02 and the DC. (c) fails: it is the domain-admin credential adm-nexa-da that is exposed, not r.dunphy's own account. (d) ignores both the still-valid credential and the second hop to the DC.",
    },
    {
      id: "pva_q5",
      xp: 75,
      kind: "multi",
      prompt:
        "Both the break-glass checkout (evt_pva_00) and the 02:10 checkout (evt_pva_01) take a domain-admin credential out of the vault off-hours. Select the TWO observations that mark the 02:10 checkout as a policy violation while clearing the break-glass one.",
      hint: "Compare the authorisation fields on each CyberArk record, and compare whether the credential was brokered into a recorded session or copied out.",
      options: [
        { value: "no_dualcontrol", label: "The 02:10 checkout has dual_control=not confirmed and access.request.status=not_requested with no change record, whereas the break-glass one was dual-control confirmed under an approved access request tied to CHG0049211" },
        { value: "retrieve_vs_psm", label: "The 02:10 checkout is a Retrieve Password (Copy) with pam.session.type None and was replayed from the engineer's own workstation, whereas the break-glass one ran through a recorded PSM-RDP session sourced from the PSM proxy" },
        { value: "only_flagged_priv", label: "Only the 02:10 checkout involved a privileged account — the break-glass checkout used an ordinary unprivileged user" },
        { value: "diff_domain", label: "The two checkouts occurred against different domains, so the break-glass activity is unrelated to this incident and can be set aside" },
      ],
      answer: ["no_dualcontrol", "retrieve_vs_psm"],
      explanation:
        "The discriminators are authorisation and monitored-use, never the fact of a privileged checkout or the hour. First, governance: the 02:10 record shows dual_control=not confirmed and access.request.status=not_requested with only a vague 'adhoc' reason, while the break-glass record carries dual_control=confirmed, an approved access request (AR-NEXA-77120, approver t.marsh) and a linked change (CHG0049211) — a second person authorised the sanctioned one and nobody authorised the flagged one. Second, use: the 02:10 checkout is a Retrieve Password with retrieval_method=Copy and pam.session.type=None, then replayed from WKS-ROPS-14, whereas the break-glass ran through a recorded PSM-RDP session sourced from PSM-NEXA-01 — one is monitored, the other is not. (c) is false: BOTH checkouts pull the same domain-admin object adm-nexa-da. (d) is false: both are the same nexacorp.com domain, and the break-glass event is the control precisely because it is comparable.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "PAM Vault Abuse — an Off-Hours Domain-Admin Checkout Used Outside PSM",
    threat_actor: "Credential-abusing operator misusing a PAM-vaulted domain-admin account (insider or account takeover)",
    attack_kind: "privileged_access_abuse",
    briefing:
      "A CyberArk alert fired at 02:14: a domain-administrator credential was pulled from the vault in the middle of the night by an on-call server engineer who does not normally hold that access. Work out whether the checkout was legitimate, what the credential did next across the servers, and how far it reached before you contain it.",
    narrative:
      "NexaCorp brokers its most powerful credentials through CyberArk. The intended way to use one is a PSM session: the operator never sees the password — CyberArk injects it into a proxied, fully-recorded RDP or SSH session — and on a high-value safe like Windows-Domain-Admins a second person must confirm the request before it is released. There is a second, weaker door: Retrieve Password, which copies the plaintext straight to the operator's clipboard to use however they like, unmonitored.\n\nAt 02:10 that second door was used. r.dunphy, a server-operations engineer whose day job is patching and who has no standing domain-admin role, was recorded retrieving the domain-admin object adm-nexa-da from the vault — retrieval method Copy, no dual-control confirmation, no linked access request, no change ticket, and no PSM session opened. Three minutes later a Kerberos TGT for adm-nexa-da was requested from his workstation WKS-ROPS-14, and at 02:14 a RemoteInteractive (RDP) logon for that domain-admin account landed on the finance database server SRV-FIN-DB-02 — sourced from the workstation, not from the PSM proxy the policy requires. A 4672 confirmed the session held domain-admin privileges, and Sysmon caught sqlcmd querying the finance wire-transfer table under it. From SRV-FIN-DB-02 the credential moved on: a 4769 service ticket for the Domain Controller at 02:19, and a network logon onto DC-NEXA-01 at 02:20.\n\nThe one legitimate comparison in the data is a break-glass checkout of the very same object a week earlier: also in the small hours, but dual-control confirmed by t.marsh under an approved access request, tied to an emergency change ticket, and used entirely inside a recorded PSM session sourced from the PSM proxy. Same account, same safe, same time of night — opposite verdict. The difference was never the checkout or the hour; it was the approval and the monitored session, both of which the 02:10 activity lacked.",
    learning_objectives: [
      "Read CyberArk vault activity — Retrieve Password vs PSM Connect, dual-control confirmation, access-request status and the linked change record — to judge whether a privileged checkout followed policy",
      "Recognise that a domain-admin credential leaving the vault, and an off-hours privileged logon, are each normal on their own — the incident lives in the governance and session-mediation fields, not the event itself",
      "Prove a checked-out credential was used OUTSIDE the monitored PSM proxy by comparing the source of the resulting AD logons (WorkstationName / IpAddress) against the PSM host and the CyberArk session type",
      "Characterise privileged-credential reuse (valid domain account + remote services) and distinguish it from pass-the-hash, Kerberoasting or vulnerability exploitation using the Kerberos and logon evidence",
      "Scope containment for an abused vaulted credential — rotate the credential to kill the copied plaintext, hunt every logon by that account since the checkout, treat a reached Domain Controller as tier-0, and verify the business justification against the break-glass control",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-23T03:02:11.000Z", phase: "Baseline", action: `Break-glass PSM checkout of ${daAccount} — dual-control confirmed, change CHG0049211, recorded PSM session: the sanctioned control case` },
      { ts: T(0), phase: "Credential Access", action: `CyberArk Retrieve Password (Copy) on ${daAccount} — no dual control, no change record, no PSM session (T1555.005)` },
      { ts: T(3 * MIN), phase: "Defense Evasion", action: `4768 TGT for ${daAccount} requested from ${engineerWs.hostname} — the copied credential authenticating (T1078.002)` },
      { ts: T(4 * MIN), phase: "Lateral Movement", action: `4624 LogonType 10 (RDP) on ${finDb.hostname} from ${engineerWs.hostname} — direct, not via the PSM proxy (T1021.001)` },
      { ts: T(4 * MIN + 5 * SEC), phase: "Privilege Escalation", action: "4672 — the RDP session carries domain-admin privileges (T1078.002)" },
      { ts: T(6 * MIN), phase: "Defense Evasion", action: `Sysmon: sqlcmd queries the finance database under the ${daAccount} session — credential used outside PSM (T1078.002)` },
      { ts: T(9 * MIN), phase: "Lateral Movement", action: `4769 service ticket for the DC requested from ${finDb.hostname} (T1021.002)` },
      { ts: T(10 * MIN), phase: "Lateral Movement", action: `4624 LogonType 3 on ${dc.hostname} from ${finDb.hostname} — the credential reaches a Domain Controller (T1021.002)` },
    ],
    questions,
  };
}
