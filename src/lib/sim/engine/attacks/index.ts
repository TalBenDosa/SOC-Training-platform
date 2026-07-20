/**
 * Attack playbook engine for the algorithmic SOC training log generator.
 *
 * Each playbook is a multi-phase kill chain. Phases generate realistic raw log
 * events that share context (PIDs, IPs, hostnames, correlationId) across phases.
 *
 * Real attacks (isFP: false) — expected_verdict "tp"
 * False positives  (isFP: true)  — expected_verdict "fp"
 */

import type {
  WorldState,
  AttackCtx,
  AttackPlaybook,
  AttackPhaseResult,
  GeneratedEvent,
  CompanyUser,
} from "@/lib/sim/engine/types";
import {
  getOrCreateSession,
  pickUser,
  externalAttackerIp,
} from "@/lib/sim/engine/worldState";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Generate a short unique event id inside a playbook phase. */
let _eventSeq = 0;
function eid(prefix: string): string {
  return `${prefix}_${Date.now()}_${++_eventSeq}`;
}

/** Return the victim's current (or newly created) session IP. */
function victimIp(world: WorldState, victim: CompanyUser): string {
  return getOrCreateSession(world, victim).ip;
}

/** Attach the attack correlation id to every raw block. */
function withCorr(raw: Record<string, unknown>, world: WorldState): Record<string, unknown> {
  return { ...raw, "attack.correlationId": world.attack?.correlationId ?? "" };
}

/** Pick a server that acts as a lateral movement target (DC or file_server first). */
function lateralTargetServer(world: WorldState): { hostname: string; ip: string } {
  const preferred = world.meta.servers.find(
    (s) => s.role === "domain_controller" || s.role === "file_server"
  );
  const server = preferred ?? world.meta.servers[0];
  return { hostname: server.hostname, ip: server.ip };
}

/** Vendor string for the company's EDR. */
function edrVendor(world: WorldState): string {
  switch (world.meta.edr) {
    case "crowdstrike": return "CrowdStrike Falcon";
    case "MDE":         return "Microsoft Defender for Endpoint";
    default:            return "Microsoft Defender for Endpoint";
  }
}

/** Vendor string for the company's firewall. */
function fwVendor(world: WorldState): string {
  switch (world.meta.firewall) {
    case "paloalto":   return "Palo Alto Networks NGFW";
    case "fortigate":  return "FortiGate NGFW";
    case "checkpoint": return "Check Point NGFW";
    default:           return "Palo Alto Networks NGFW";
  }
}

/** Build a Palo Alto firewall raw block for outbound connection. */
function paloAltoConnRaw(
  srcIp: string,
  srcPort: number,
  dstIp: string,
  dstPort: number,
  app: string,
  action: string,
  rule: string,
  bytesOut = 4096,
  bytesIn = 2048
): Record<string, unknown> {
  return {
    "data.srcip": srcIp,
    "data.srcport": String(srcPort),
    "data.dstip": dstIp,
    "data.dport": String(dstPort),
    "data.proto": dstPort === 53 ? "17" : "6",
    "data.action": action,
    "data.app": app,
    "data.rule": rule,
    "data.bytes_sent": String(bytesOut),
    "data.bytes_received": String(bytesIn),
  };
}

/** C2 domain pool for phishing / ransomware playbooks. */
const C2_DOMAINS = [
  "update-svc.windowscdn-delivery.net",
  "cdn-telemetry-svc.net",
  "ms-update-service.org",
  "api-gateway-proxy.net",
];

// ─── PLAYBOOK 1: Phishing → BEC ───────────────────────────────────────────────

const playbookPhishingBEC: AttackPlaybook = {
  id: "phishing_bec",
  name: "Phishing → Business Email Compromise",
  isFP: false,

  selectVictim(world: WorldState): CompanyUser | null {
    return pickUser(world, (u) => !u.isAdmin);
  },

  phases: [
    // ── Phase 0: email_delivery ──────────────────────────────────────────────
    {
      id: "email_delivery",
      name: "Email Delivery",
      mitre: "T1566.001",
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const attachSize = world.rng.range(45_000, 120_000);

        const ev: GeneratedEvent = {
          id: eid("phish_email"),
          source: "email_gateway",
          vendor: "Microsoft Defender for Endpoint",
          event_type: "email_received",
          severity: "medium",
          mitre_technique: "T1566.001",
          hostname: victim.hostname,
          user_email: victim.email,
          description: `Suspicious email received by ${victim.email} — spoofed sender, .docm attachment`,
          expected_verdict: "tp",
          raw: withCorr(
            {
              "data.office365.Operation": "MessageDelivered",
              "data.office365.UserId": victim.email,
              "data.office365.ClientIP": "10.0.0.1",
              "email.from.address": `it-helpdesk@${world.meta.domain.split(".")[0]}-support.net`,
              "email.to.address": victim.email,
              "email.subject": "URGENT: Your password expires in 24 hours — Action Required",
              "email.spf": "fail",
              "email.dkim": "fail",
              "email.dmarc": "fail",
              "email.attachments[0].name": "IT-SecureForm-2026.docm",
              "email.attachments[0].size": attachSize,
              "email.direction": "Inbound",
              "email.x_mailer": "PHPMailer 6.6.0",
            },
            world
          ),
        };

        return {
          events: [ev],
          nextDelayMs: world.rng.range(90_000, 180_000),
        };
      },
    },

    // ── Phase 1: macro_execution ─────────────────────────────────────────────
    {
      id: "macro_execution",
      name: "Macro Execution",
      mitre: "T1059.001",
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const session = getOrCreateSession(world, victim);
        const adDomain = world.meta.adDomain || "CORP";

        const winwordPid = world.rng.pid();
        const psPid = world.rng.pid();
        const psHash = world.rng.sha256();

        // Event 1: WINWORD opens attachment
        const ev1: GeneratedEvent = {
          id: eid("phish_winword"),
          source: "sysmon",
          vendor: "Microsoft Sysmon",
          event_type: "process_create",
          severity: "low",
          hostname: victim.hostname,
          user_email: victim.email,
          description: `WINWORD.EXE opened malicious .docm attachment on ${victim.hostname}`,
          process: {
            name: "WINWORD.EXE",
            pid: winwordPid,
            path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            parent_name: "outlook.exe",
            parent_pid: 4128,
            cmdline: `WINWORD.EXE "C:\\Users\\${victim.id}\\AppData\\Local\\Temp\\IT-SecureForm-2026.docm"`,
            user: `${adDomain}\\${victim.id}`,
            integrity: "medium",
          },
          raw: withCorr(
            {
              "event.code": "1",
              "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
              "winlog.provider_name": "Microsoft-Windows-Sysmon",
              "winlog.computer_name": victim.hostname,
              "winlog.event_data.Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
              "winlog.event_data.CommandLine": `WINWORD.EXE "C:\\Users\\${victim.id}\\AppData\\Local\\Temp\\IT-SecureForm-2026.docm"`,
              "winlog.event_data.ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
              "winlog.event_data.ParentProcessId": "4128",
              "winlog.event_data.ProcessId": String(winwordPid),
              "winlog.event_data.User": `${adDomain}\\${victim.id}`,
              "winlog.event_data.IntegrityLevel": "Medium",
              "winlog.event_data.Hashes": `SHA256=${world.rng.sha256()}`,
              "winlog.event_data.LogonId": session.logonId,
            },
            world
          ),
        };

        // Event 2: powershell.exe spawned by WINWORD (macro fired)
        const ev2: GeneratedEvent = {
          id: eid("phish_ps"),
          source: "sysmon",
          vendor: "Microsoft Sysmon",
          event_type: "process_create",
          severity: "high",
          mitre_technique: "T1059.001",
          hostname: victim.hostname,
          user_email: victim.email,
          description: `powershell.exe spawned by WINWORD.EXE via macro on ${victim.hostname} — encoded command`,
          expected_verdict: "tp",
          process: {
            name: "powershell.exe",
            pid: psPid,
            path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            parent_name: "WINWORD.EXE",
            parent_pid: winwordPid,
            cmdline:
              "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7",
            user: `${adDomain}\\${victim.id}`,
            integrity: "medium",
            hash: { sha256: psHash },
          },
          raw: withCorr(
            {
              "event.code": "1",
              "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
              "winlog.provider_name": "Microsoft-Windows-Sysmon",
              "winlog.computer_name": victim.hostname,
              "winlog.event_data.Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "winlog.event_data.CommandLine":
                "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7",
              "winlog.event_data.ParentImage":
                "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
              "winlog.event_data.ParentProcessId": String(winwordPid),
              "winlog.event_data.ProcessId": String(psPid),
              "winlog.event_data.User": `${adDomain}\\${victim.id}`,
              "winlog.event_data.IntegrityLevel": "Medium",
              "winlog.event_data.Hashes": `SHA256=${psHash}`,
              "winlog.event_data.LogonId": session.logonId,
              "file.signed": "false",
            },
            world
          ),
        };

        return {
          events: [ev1, ev2],
          ctxUpdate: { winword_pid: winwordPid, ps_pid: psPid },
          nextDelayMs: 15_000,
        };
      },
    },

    // ── Phase 2: c2_beacon ───────────────────────────────────────────────────
    {
      id: "c2_beacon",
      name: "C2 Beacon",
      mitre: "T1071.001",
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const ctx = world.attack!.ctx;
        const session = getOrCreateSession(world, victim);
        const srcPort = world.rng.srcPort();

        const c2Domain = world.rng.choice(C2_DOMAINS);
        const attackerIp = externalAttackerIp(world);
        const psPid = ctx.ps_pid as number;

        // DNS query for C2
        const ev1: GeneratedEvent = {
          id: eid("phish_c2dns"),
          source: "sysmon",
          vendor: "Microsoft Sysmon",
          event_type: "dns_query",
          severity: "medium",
          mitre_technique: "T1071.001",
          hostname: victim.hostname,
          user_email: victim.email,
          description: `DNS query for C2 domain ${c2Domain} from powershell.exe on ${victim.hostname}`,
          expected_verdict: "tp",
          dns: {
            query: c2Domain,
            query_type: "A",
            response: attackerIp,
            rcode: "NOERROR",
          },
          raw: withCorr(
            {
              "event.code": "22",
              "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
              "winlog.provider_name": "Microsoft-Windows-Sysmon",
              "winlog.computer_name": victim.hostname,
              "winlog.event_data.QueryName": c2Domain,
              "winlog.event_data.QueryResults": attackerIp,
              "winlog.event_data.QueryStatus": "0",
              "winlog.event_data.Image":
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "winlog.event_data.ProcessId": String(psPid),
              "winlog.event_data.User": `${world.meta.adDomain || "CORP"}\\${victim.id}`,
            },
            world
          ),
        };

        // Outbound HTTPS to C2
        const ev2: GeneratedEvent = {
          id: eid("phish_c2conn"),
          source: "firewall",
          vendor: fwVendor(world),
          event_type: "net_connection",
          severity: "high",
          hostname: victim.hostname,
          user_email: victim.email,
          src_ip: session.ip,
          dst_ip: attackerIp,
          dst_port: 443,
          protocol: "tcp",
          description: `Outbound HTTPS from ${victim.hostname} to C2 ${attackerIp}:443 — firewall allowed (ssl traffic)`,
          expected_verdict: "tp",
          raw: withCorr(
            paloAltoConnRaw(session.ip, srcPort, attackerIp, 443, "ssl", "allow", "Allow-Web-Outbound", 2048, 512),
            world
          ),
        };

        return {
          events: [ev1, ev2],
          ctxUpdate: { c2Domain, attackerIp },
          nextDelayMs: world.rng.range(180_000, 300_000),
        };
      },
    },

    // ── Phase 3: discovery ───────────────────────────────────────────────────
    {
      id: "discovery",
      name: "Discovery",
      mitre: "T1033",
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const ctx = world.attack!.ctx;
        const session = getOrCreateSession(world, victim);
        const adDomain = world.meta.adDomain || "CORP";
        const psPid = ctx.ps_pid as number;

        const discoveryCommands: Array<{
          name: string;
          path: string;
          cmdLine: string;
          mitre: string;
          severity: GeneratedEvent["severity"];
          desc: string;
        }> = [
          {
            name: "whoami.exe",
            path: "C:\\Windows\\System32\\whoami.exe",
            cmdLine: "whoami.exe /all",
            mitre: "T1033",
            severity: "low",
            desc: `whoami /all executed by powershell on ${victim.hostname}`,
          },
          {
            name: "net.exe",
            path: "C:\\Windows\\System32\\net.exe",
            cmdLine: 'net.exe group "Domain Admins" /domain',
            mitre: "T1087.002",
            severity: "medium",
            desc: `Domain Admins group enumerated via net.exe on ${victim.hostname}`,
          },
          {
            name: "ipconfig.exe",
            path: "C:\\Windows\\System32\\ipconfig.exe",
            cmdLine: "ipconfig.exe /all",
            mitre: "T1016",
            severity: "low",
            desc: `Network configuration enumerated via ipconfig on ${victim.hostname}`,
          },
        ];

        const events: GeneratedEvent[] = discoveryCommands.map((cmd, i) => ({
          id: eid(`phish_disc${i}`),
          source: "sysmon" as const,
          vendor: "Microsoft Sysmon",
          event_type: "process_create" as const,
          severity: cmd.severity,
          mitre_technique: cmd.mitre,
          hostname: victim.hostname,
          user_email: victim.email,
          description: cmd.desc,
          expected_verdict: "tp" as const,
          process: {
            name: cmd.name,
            pid: world.rng.pid(),
            path: cmd.path,
            parent_name: "powershell.exe",
            parent_pid: psPid,
            cmdline: cmd.cmdLine,
            user: `${adDomain}\\${victim.id}`,
            integrity: "medium",
          },
          raw: withCorr(
            {
              "event.code": "1",
              "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
              "winlog.provider_name": "Microsoft-Windows-Sysmon",
              "winlog.computer_name": victim.hostname,
              "winlog.event_data.Image": cmd.path,
              "winlog.event_data.CommandLine": cmd.cmdLine,
              "winlog.event_data.ParentImage":
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "winlog.event_data.ParentProcessId": String(psPid),
              "winlog.event_data.ProcessId": String(world.rng.pid()),
              "winlog.event_data.User": `${adDomain}\\${victim.id}`,
              "winlog.event_data.IntegrityLevel": "Medium",
              "winlog.event_data.LogonId": session.logonId,
            },
            world
          ),
        }));

        return {
          events,
          nextDelayMs: world.rng.range(300_000, 480_000),
        };
      },
    },

    // ── Phase 4: credential_access ───────────────────────────────────────────
    {
      id: "credential_access",
      name: "Credential Access — LSASS Dump",
      mitre: "T1003.001",
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const ctx = world.attack!.ctx;
        const psPid = ctx.ps_pid as number;
        const adDomain = world.meta.adDomain || "CORP";

        const ev: GeneratedEvent = {
          id: eid("phish_lsass"),
          source: "edr",
          vendor: edrVendor(world),
          event_type: "process_access",
          severity: "critical",
          mitre_technique: "T1003.001",
          hostname: victim.hostname,
          user_email: victim.email,
          description: `LSASS memory access with PROCESS_ALL_ACCESS from powershell.exe on ${victim.hostname}`,
          expected_verdict: "tp",
          process: {
            name: "powershell.exe",
            pid: psPid,
            path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            user: `${adDomain}\\${victim.id}`,
          },
          raw: withCorr(
            {
              "event.code": "10",
              "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
              "winlog.provider_name": "Microsoft-Windows-Sysmon",
              "winlog.computer_name": victim.hostname,
              "winlog.event_data.SourceImage":
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "winlog.event_data.TargetImage": "C:\\Windows\\System32\\lsass.exe",
              "winlog.event_data.GrantedAccess": "0x1FFFFF",
              "winlog.event_data.CallTrace":
                "C:\\Windows\\SYSTEM32\\ntdll.dll+9a2ab|C:\\Windows\\System32\\KERNELBASE.dll+2b09e|C:\\Windows\\System32\\comsvcs.dll+15a37",
              "winlog.event_data.SourceProcessId": String(psPid),
              "winlog.event_data.TargetProcessId": "700",
              "winlog.event_data.User": `${adDomain}\\${victim.id}`,
            },
            world
          ),
        };

        return {
          events: [ev],
          nextDelayMs: world.rng.range(480_000, 720_000),
        };
      },
    },

    // ── Phase 5: lateral_movement ────────────────────────────────────────────
    {
      id: "lateral_movement",
      name: "Lateral Movement — Pass-the-Hash",
      mitre: "T1021.002",
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const session = getOrCreateSession(world, victim);
        const adDomain = world.meta.adDomain || "CORP";
        const { hostname: serverHostname, ip: serverIp } = lateralTargetServer(world);
        const lateralLogonId = world.rng.logonId();
        const srcPort = world.rng.srcPort();

        // SMB connection
        const ev1: GeneratedEvent = {
          id: eid("phish_smb"),
          source: "firewall",
          vendor: fwVendor(world),
          event_type: "net_connection",
          severity: "high",
          mitre_technique: "T1021.002",
          hostname: victim.hostname,
          user_email: victim.email,
          src_ip: session.ip,
          dst_ip: serverIp,
          dst_port: 445,
          protocol: "tcp",
          description: `SMB connection from ${victim.hostname} (${session.ip}) to ${serverHostname} (${serverIp}):445`,
          expected_verdict: "tp",
          raw: withCorr(
            {
              "data.srcip": session.ip,
              "data.srcport": String(srcPort),
              "data.dstip": serverIp,
              "data.dport": "445",
              "data.proto": "6",
              "data.action": "allow",
              "data.app": "smb",
              "data.rule": "Allow-Internal-SMB",
              "data.bytes_sent": "2048",
              "data.bytes_received": "1024",
            },
            world
          ),
        };

        // Successful logon on server via pass-the-hash (NTLM, type 3)
        const ev2: GeneratedEvent = {
          id: eid("phish_pth"),
          source: "ad",
          vendor: "Windows Security",
          event_type: "auth_success",
          severity: "critical",
          mitre_technique: "T1550.002",
          hostname: serverHostname,
          user_email: victim.email,
          src_ip: session.ip,
          description: `Pass-the-Hash: ${victim.id} authenticated to ${serverHostname} via NTLM from ${session.ip}`,
          expected_verdict: "tp",
          raw: withCorr(
            {
              "event.code": "4624",
              "event.action": "logged-in",
              "event.outcome": "success",
              "winlog.channel": "Security",
              "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
              "winlog.computer_name": serverHostname,
              "winlog.event_data.LogonType": "3",
              "winlog.event_data.TargetUserName": victim.id,
              "winlog.event_data.TargetDomainName": adDomain,
              "winlog.event_data.IpAddress": session.ip,
              "winlog.event_data.IpPort": String(srcPort),
              "winlog.event_data.WorkstationName": victim.hostname,
              "winlog.event_data.AuthenticationPackageName": "NTLM",
              "winlog.event_data.LogonProcessName": "NtLmSsp",
              "winlog.event_data.LogonId": lateralLogonId,
              "source.ip": session.ip,
              "user.name": victim.id,
              "user.domain": adDomain,
            },
            world
          ),
        };

        return {
          events: [ev1, ev2],
          nextDelayMs: 0,
        };
      },
    },
  ],
};

// ─── PLAYBOOK 2: Password Spray → Account Takeover ────────────────────────────

const playbookPasswordSpray: AttackPlaybook = {
  id: "password_spray_ato",
  name: "Password Spray → Account Takeover",
  isFP: false,

  selectVictim(world: WorldState): CompanyUser | null {
    return pickUser(world, (u) => !u.isAdmin);
  },

  phases: [
    // ── Phase 0: spray_failures ──────────────────────────────────────────────
    {
      id: "spray_failures",
      name: "Password Spray — Auth Failures",
      mitre: "T1110.003",
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const attackerIp = externalAttackerIp(world);
        const adDomain = world.meta.adDomain || "CORP";

        // Pick 5 distinct non-admin users (including the victim)
        const sprayTargets = world.meta.users
          .filter((u) => !u.isAdmin)
          .slice(0, 5);
        // Ensure we have 5 targets by cycling
        const targets: CompanyUser[] = [];
        for (let i = 0; i < 5; i++) {
          targets.push(sprayTargets[i % sprayTargets.length]);
        }

        const events: GeneratedEvent[] = targets.map((target, i) => ({
          id: eid(`spray_fail${i}`),
          source: "ad" as const,
          vendor: "Windows Security",
          event_type: "auth_failure" as const,
          severity: "medium" as const,
          mitre_technique: "T1110.003",
          hostname: world.meta.servers.find((s) => s.role === "domain_controller")?.hostname ?? "DC-CORP-01",
          user_email: target.email,
          src_ip: attackerIp,
          description: `Authentication failure for ${target.id} from external IP ${attackerIp} — password spray pattern`,
          expected_verdict: (i >= 2 ? "tp" : "informational") as GeneratedEvent["expected_verdict"],
          geo: { country: "Russia", city: "Moscow", latitude: 55.75, longitude: 37.62 },
          raw: withCorr(
            {
              "event.code": "4625",
              "event.action": "logon-failed",
              "event.outcome": "failure",
              "winlog.channel": "Security",
              "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
              "winlog.computer_name": world.meta.servers.find((s) => s.role === "domain_controller")?.hostname ?? "DC-CORP-01",
              "winlog.event_data.LogonType": "3",
              "winlog.event_data.TargetUserName": target.id,
              "winlog.event_data.TargetDomainName": adDomain,
              "winlog.event_data.IpAddress": attackerIp,
              "winlog.event_data.WorkstationName": "",
              "winlog.event_data.AuthenticationPackageName": "NTLM",
              "winlog.event_data.FailureReason": "%%2313",
              "winlog.event_data.Status": "0xC000006D",
              "winlog.event_data.SubStatus": "0xC000006A",
              "source.ip": attackerIp,
              "user.name": target.id,
              "user.domain": adDomain,
            },
            world
          ),
        }));

        return {
          events,
          ctxUpdate: { attackerIp },
          nextDelayMs: 30_000,
        };
      },
    },

    // ── Phase 1: spray_success ───────────────────────────────────────────────
    {
      id: "spray_success",
      name: "Password Spray — Successful Auth",
      mitre: "T1078",
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const ctx = world.attack!.ctx;
        const attackerIp = ctx.attackerIp as string;
        const adDomain = world.meta.adDomain || "CORP";
        const logonId = world.rng.logonId();
        const dcHostname = world.meta.servers.find((s) => s.role === "domain_controller")?.hostname ?? "DC-CORP-01";

        const ev: GeneratedEvent = {
          id: eid("spray_success"),
          source: "ad",
          vendor: "Windows Security",
          event_type: "auth_success",
          severity: "critical",
          mitre_technique: "T1078",
          hostname: dcHostname,
          user_email: victim.email,
          src_ip: attackerIp,
          description: `Successful authentication for ${victim.id} from known spray IP ${attackerIp} — account takeover`,
          expected_verdict: "tp",
          geo: { country: "Russia", city: "Moscow", latitude: 55.7, longitude: 37.6 },
          raw: withCorr(
            {
              "event.code": "4624",
              "event.action": "logged-in",
              "event.outcome": "success",
              "winlog.channel": "Security",
              "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
              "winlog.computer_name": dcHostname,
              "winlog.event_data.LogonType": "3",
              "winlog.event_data.TargetUserName": victim.id,
              "winlog.event_data.TargetDomainName": adDomain,
              "winlog.event_data.IpAddress": attackerIp,
              "winlog.event_data.WorkstationName": "",
              "winlog.event_data.AuthenticationPackageName": "NTLM",
              "winlog.event_data.LogonProcessName": "NtLmSsp",
              "winlog.event_data.LogonId": logonId,
              "source.ip": attackerIp,
              "user.name": victim.id,
              "user.domain": adDomain,
            },
            world
          ),
        };

        return {
          events: [ev],
          ctxUpdate: { spray_logon_id: logonId },
          nextDelayMs: 60_000,
        };
      },
    },

    // ── Phase 2: mailbox_access ──────────────────────────────────────────────
    {
      id: "mailbox_access",
      name: "Mailbox Access",
      mitre: "T1114.002",
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const ctx = world.attack!.ctx;
        const attackerIp = ctx.attackerIp as string;

        const ev: GeneratedEvent = {
          id: eid("spray_mail"),
          source: "o365",
          vendor: "Microsoft 365 Unified Audit Log",
          event_type: "email_received",
          severity: "high",
          mitre_technique: "T1114.002",
          hostname: victim.hostname,
          user_email: victim.email,
          src_ip: attackerIp,
          description: `Mailbox items accessed for ${victim.email} from attacker IP ${attackerIp} — REST API via proxy`,
          expected_verdict: "tp",
          geo: { country: "Russia", city: "Moscow", latitude: 55.7, longitude: 37.6 },
          raw: withCorr(
            {
              "data.office365.Operation": "MailItemsAccessed",
              "data.office365.Workload": "Exchange",
              "data.office365.UserId": victim.email,
              "data.office365.ClientIP": attackerIp,
              "data.office365.ClientInfoString": "Client=REST;Action=ViaProxy",
              "data.office365.ResultStatus": "Succeeded",
              "data.office365.AzureActiveDirectoryEventType": "AccountLogon",
              "GeoLocation.country_name": "Russia",
              "GeoLocation.location.lat": 55.75,
              "GeoLocation.location.lon": 37.62,
            },
            world
          ),
        };

        return {
          events: [ev],
          nextDelayMs: 120_000,
        };
      },
    },

    // ── Phase 3: inbox_rule ──────────────────────────────────────────────────
    {
      id: "inbox_rule",
      name: "Inbox Forwarding Rule",
      mitre: "T1137.005",
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const ctx = world.attack!.ctx;
        const attackerIp = ctx.attackerIp as string;
        const forwardEmail = `${victim.id}.backup@proton.me`;

        const ev: GeneratedEvent = {
          id: eid("spray_rule"),
          source: "o365",
          vendor: "Microsoft 365 Unified Audit Log",
          event_type: "account_modify",
          severity: "critical",
          mitre_technique: "T1137.005",
          hostname: victim.hostname,
          user_email: victim.email,
          src_ip: attackerIp,
          description: `New inbox forwarding rule created for ${victim.email} — forwarding to external ${forwardEmail}`,
          expected_verdict: "tp",
          geo: { country: "Russia", city: "Moscow", latitude: 55.7, longitude: 37.6 },
          raw: withCorr(
            {
              "data.office365.Operation": "New-InboxRule",
              "data.office365.Workload": "Exchange",
              "data.office365.UserId": victim.email,
              "data.office365.ClientIP": attackerIp,
              "data.office365.ResultStatus": "Succeeded",
              "data.office365.Parameters[0].Name": "ForwardTo",
              "data.office365.Parameters[0].Value": forwardEmail,
              "data.office365.Parameters[1].Name": "Name",
              "data.office365.Parameters[1].Value": ".",
              "data.office365.Parameters[2].Name": "StopProcessingRules",
              "data.office365.Parameters[2].Value": "True",
              "GeoLocation.country_name": "Russia",
              "GeoLocation.location.lat": 55.75,
              "GeoLocation.location.lon": 37.62,
            },
            world
          ),
        };

        return {
          events: [ev],
          ctxUpdate: { forwardEmail },
          nextDelayMs: 0,
        };
      },
    },
  ],
};

// ─── PLAYBOOK 3: Ransomware ───────────────────────────────────────────────────

const playbookRansomware: AttackPlaybook = {
  id: "ransomware_encrypt",
  name: "Ransomware — Encrypt and Extort",
  isFP: false,

  selectVictim(world: WorldState): CompanyUser | null {
    // Prefer non-admin
    const nonAdmin = world.meta.users.filter((u) => !u.isAdmin);
    if (nonAdmin.length > 0) return world.rng.choice(nonAdmin);
    return world.rng.choice(world.meta.users);
  },

  phases: [
    // ── Phase 0: initial_dropper ─────────────────────────────────────────────
    {
      id: "initial_dropper",
      name: "Initial Dropper Execution",
      mitre: "T1059.003",
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const session = getOrCreateSession(world, victim);
        const adDomain = world.meta.adDomain || "CORP";
        const dropperPid = world.rng.pid();
        const dropperHash = world.rng.sha256();

        const ev: GeneratedEvent = {
          id: eid("ransom_drop"),
          source: "edr",
          vendor: edrVendor(world),
          event_type: "process_create",
          severity: "critical",
          mitre_technique: "T1059.003",
          hostname: victim.hostname,
          user_email: victim.email,
          description: `Suspicious dropper svchost32.exe executed from Temp directory on ${victim.hostname}`,
          expected_verdict: "tp",
          process: {
            name: "cmd.exe",
            pid: dropperPid,
            path: "C:\\Windows\\System32\\cmd.exe",
            parent_name: "explorer.exe",
            parent_pid: 2400,
            cmdline: `cmd.exe /c "C:\\Users\\${victim.id}\\AppData\\Local\\Temp\\svchost32.exe" /quiet`,
            user: `${adDomain}\\${victim.id}`,
            integrity: "medium",
            hash: { sha256: dropperHash },
          },
          raw: withCorr(
            {
              "event.code": "1",
              "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
              "winlog.provider_name": "Microsoft-Windows-Sysmon",
              "winlog.computer_name": victim.hostname,
              "winlog.event_data.Image": "C:\\Windows\\System32\\cmd.exe",
              "winlog.event_data.CommandLine": `cmd.exe /c "C:\\Users\\${victim.id}\\AppData\\Local\\Temp\\svchost32.exe" /quiet`,
              "winlog.event_data.ParentImage": "C:\\Windows\\explorer.exe",
              "winlog.event_data.ParentProcessId": "2400",
              "winlog.event_data.ProcessId": String(dropperPid),
              "winlog.event_data.User": `${adDomain}\\${victim.id}`,
              "winlog.event_data.IntegrityLevel": "Medium",
              "winlog.event_data.Hashes": `SHA256=${dropperHash}`,
              "winlog.event_data.LogonId": session.logonId,
              "file.path": `C:\\Users\\${victim.id}\\AppData\\Local\\Temp\\svchost32.exe`,
              "file.signed": "false",
            },
            world
          ),
        };

        return {
          events: [ev],
          ctxUpdate: { dropper_pid: dropperPid },
          nextDelayMs: 20_000,
        };
      },
    },

    // ── Phase 1: c2_and_keygen ───────────────────────────────────────────────
    {
      id: "c2_and_keygen",
      name: "C2 Check-in and Key Generation",
      mitre: "T1071.004",
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const ctx = world.attack!.ctx;
        const session = getOrCreateSession(world, victim);
        const dropperPid = ctx.dropper_pid as number;
        const adDomain = world.meta.adDomain || "CORP";
        const c2Domain = world.rng.choice(C2_DOMAINS);
        const attackerIp = externalAttackerIp(world);
        const srcPort = world.rng.srcPort();

        // DNS query
        const ev1: GeneratedEvent = {
          id: eid("ransom_dns"),
          source: "sysmon",
          vendor: "Microsoft Sysmon",
          event_type: "dns_query",
          severity: "high",
          mitre_technique: "T1071.004",
          hostname: victim.hostname,
          user_email: victim.email,
          description: `Ransomware dropper queried C2 domain ${c2Domain} for encryption key retrieval`,
          expected_verdict: "tp",
          dns: {
            query: c2Domain,
            query_type: "A",
            response: attackerIp,
            rcode: "NOERROR",
          },
          raw: withCorr(
            {
              "event.code": "22",
              "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
              "winlog.provider_name": "Microsoft-Windows-Sysmon",
              "winlog.computer_name": victim.hostname,
              "winlog.event_data.QueryName": c2Domain,
              "winlog.event_data.QueryResults": attackerIp,
              "winlog.event_data.QueryStatus": "0",
              "winlog.event_data.Image": `C:\\Users\\${victim.id}\\AppData\\Local\\Temp\\svchost32.exe`,
              "winlog.event_data.ProcessId": String(dropperPid),
              "winlog.event_data.User": `${adDomain}\\${victim.id}`,
            },
            world
          ),
        };

        // Outbound connection
        const ev2: GeneratedEvent = {
          id: eid("ransom_c2conn"),
          source: "firewall",
          vendor: fwVendor(world),
          event_type: "net_connection",
          severity: "high",
          hostname: victim.hostname,
          user_email: victim.email,
          src_ip: session.ip,
          dst_ip: attackerIp,
          dst_port: 443,
          protocol: "tcp",
          description: `Outbound HTTPS from ${victim.hostname} to C2 ${attackerIp}:443 — ransomware key exchange`,
          expected_verdict: "tp",
          raw: withCorr(
            paloAltoConnRaw(session.ip, srcPort, attackerIp, 443, "ssl", "allow", "Allow-Web-Outbound", 1024, 512),
            world
          ),
        };

        return {
          events: [ev1, ev2],
          ctxUpdate: { c2Domain, ransom_attacker_ip: attackerIp },
          nextDelayMs: 15_000,
        };
      },
    },

    // ── Phase 2: shadow_copy_delete ──────────────────────────────────────────
    {
      id: "shadow_copy_delete",
      name: "Shadow Copy Deletion",
      mitre: "T1490",
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const ctx = world.attack!.ctx;
        const session = getOrCreateSession(world, victim);
        const adDomain = world.meta.adDomain || "CORP";
        const dropperPid = ctx.dropper_pid as number;
        const vssPid = world.rng.pid();

        const ev: GeneratedEvent = {
          id: eid("ransom_vss"),
          source: "sysmon",
          vendor: "Microsoft Sysmon",
          event_type: "process_create",
          severity: "critical",
          mitre_technique: "T1490",
          hostname: victim.hostname,
          user_email: victim.email,
          description: `vssadmin.exe deleting all shadow copies on ${victim.hostname} — ransomware pre-encryption cleanup`,
          expected_verdict: "tp",
          process: {
            name: "vssadmin.exe",
            pid: vssPid,
            path: "C:\\Windows\\System32\\vssadmin.exe",
            parent_name: "cmd.exe",
            parent_pid: dropperPid,
            cmdline: "vssadmin.exe delete shadows /all /quiet",
            user: `${adDomain}\\${victim.id}`,
            integrity: "medium",
          },
          raw: withCorr(
            {
              "event.code": "1",
              "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
              "winlog.provider_name": "Microsoft-Windows-Sysmon",
              "winlog.computer_name": victim.hostname,
              "winlog.event_data.Image": "C:\\Windows\\System32\\vssadmin.exe",
              "winlog.event_data.CommandLine": "vssadmin.exe delete shadows /all /quiet",
              "winlog.event_data.ParentImage": "C:\\Windows\\System32\\cmd.exe",
              "winlog.event_data.ParentProcessId": String(dropperPid),
              "winlog.event_data.ProcessId": String(vssPid),
              "winlog.event_data.User": `${adDomain}\\${victim.id}`,
              "winlog.event_data.IntegrityLevel": "Medium",
              "winlog.event_data.Hashes": `SHA256=${world.rng.sha256()}`,
              "winlog.event_data.LogonId": session.logonId,
            },
            world
          ),
        };

        return {
          events: [ev],
          nextDelayMs: 10_000,
        };
      },
    },

    // ── Phase 3: mass_encrypt ────────────────────────────────────────────────
    {
      id: "mass_encrypt",
      name: "Mass File Encryption",
      mitre: "T1486",
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const ctx = world.attack!.ctx;
        const dropperPid = ctx.dropper_pid as number;
        const filesEncrypted = world.rng.range(847, 2341);

        const ev: GeneratedEvent = {
          id: eid("ransom_enc"),
          source: "edr",
          vendor: edrVendor(world),
          event_type: "file_modify",
          severity: "critical",
          mitre_technique: "T1486",
          hostname: victim.hostname,
          user_email: victim.email,
          description: `Mass file encryption detected on ${victim.hostname} — ${filesEncrypted} files modified with .locked extension`,
          expected_verdict: "tp",
          file: {
            name: "DECRYPT_FILES.txt",
            path: `C:\\Users\\${victim.id}\\Documents\\`,
          },
          raw: withCorr(
            {
              "cs.FileName": "DECRYPT_FILES.txt",
              "cs.FilePath": `C:\\Users\\${victim.id}\\Documents\\`,
              "cs.ContextProcessName": "svchost32.exe",
              "cs.OperationType": "WRITE",
              "cs.ContextProcessId_decimal": String(dropperPid),
              "data.files_encrypted": filesEncrypted,
              "data.file_extension_changed_to": ".locked",
              "data.ransom_note_dropped": "true",
              "data.ransom_note_path": `C:\\Users\\${victim.id}\\Desktop\\DECRYPT_FILES.txt`,
            },
            world
          ),
        };

        return {
          events: [ev],
          nextDelayMs: 0,
        };
      },
    },
  ],
};

// ─── PLAYBOOK 4: IT Admin Maintenance (False Positive) ────────────────────────

const playbookITMaintenance: AttackPlaybook = {
  id: "it_admin_maintenance",
  name: "IT Admin Maintenance — False Positive",
  isFP: true,

  selectVictim(world: WorldState): CompanyUser | null {
    const admins = world.meta.users.filter((u) => u.isAdmin);
    if (admins.length === 0) return world.meta.users[0];
    return world.rng.choice(admins);
  },

  phases: [
    // ── Phase 0: powershell_script ───────────────────────────────────────────
    {
      id: "powershell_script",
      name: "IT Admin PowerShell Script",
      mitre: "T1059.001",
      isFPPhase: true,
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const session = getOrCreateSession(world, victim);
        const adDomain = world.meta.adDomain || "CORP";
        const psPid = world.rng.pid();
        const cmdPid = world.rng.pid();

        const ev: GeneratedEvent = {
          id: eid("itadmin_ps"),
          source: "sysmon",
          vendor: "Microsoft Sysmon",
          event_type: "process_create",
          severity: "medium",
          mitre_technique: "T1059.001",
          hostname: victim.hostname,
          user_email: victim.email,
          description: `PowerShell script executed by IT admin ${victim.id} on ${victim.hostname}`,
          expected_verdict: "fp",
          process: {
            name: "powershell.exe",
            pid: psPid,
            path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            parent_name: "cmd.exe",
            parent_pid: cmdPid,
            cmdline: `powershell.exe -NonInteractive -ExecutionPolicy RemoteSigned -File "C:\\Scripts\\AD-UserReport.ps1" -OutputPath "C:\\ Reports\\"`,
            user: `${adDomain}\\${victim.id}`,
            integrity: "high",
          },
          raw: withCorr(
            {
              "event.code": "1",
              "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
              "winlog.provider_name": "Microsoft-Windows-Sysmon",
              "winlog.computer_name": victim.hostname,
              "winlog.event_data.Image":
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "winlog.event_data.CommandLine": `powershell.exe -NonInteractive -ExecutionPolicy RemoteSigned -File "C:\\Scripts\\AD-UserReport.ps1" -OutputPath "C:\\Reports\\"`,
              "winlog.event_data.ParentImage": "C:\\Windows\\System32\\cmd.exe",
              "winlog.event_data.ParentProcessId": String(cmdPid),
              "winlog.event_data.ProcessId": String(psPid),
              "winlog.event_data.User": `${adDomain}\\${victim.id}`,
              "winlog.event_data.IntegrityLevel": "High",
              "winlog.event_data.Hashes": `SHA256=${world.rng.sha256()}`,
              "winlog.event_data.LogonId": session.logonId,
              "file.signed": "true",
            },
            world
          ),
        };

        return {
          events: [ev],
          ctxUpdate: { admin_ps_pid: psPid, admin_cmd_pid: cmdPid },
          nextDelayMs: 30_000,
        };
      },
    },

    // ── Phase 1: net_commands ────────────────────────────────────────────────
    {
      id: "net_commands",
      name: "IT Admin Net Commands",
      mitre: "T1087.002",
      isFPPhase: true,
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const ctx = world.attack!.ctx;
        const session = getOrCreateSession(world, victim);
        const adDomain = world.meta.adDomain || "CORP";
        const psPid = ctx.admin_ps_pid as number;

        const cmds = [
          {
            cmdline: 'net.exe group "Domain Admins" /domain',
            desc: `Domain Admins group verified by IT admin ${victim.id} — routine admin check`,
            mitre: "T1087.002",
          },
          {
            cmdline: "net.exe user /domain",
            desc: `Full domain user enumeration by IT admin ${victim.id} — generating user report`,
            mitre: "T1087.002",
          },
        ];

        const events: GeneratedEvent[] = cmds.map((cmd, i) => {
          const netPid = world.rng.pid();
          return {
            id: eid(`itadmin_net${i}`),
            source: "sysmon" as const,
            vendor: "Microsoft Sysmon",
            event_type: "process_create" as const,
            severity: "medium" as const,
            mitre_technique: cmd.mitre,
            hostname: victim.hostname,
            user_email: victim.email,
            description: cmd.desc,
            expected_verdict: "fp" as const,
            process: {
              name: "net.exe",
              pid: netPid,
              path: "C:\\Windows\\System32\\net.exe",
              parent_name: "powershell.exe",
              parent_pid: psPid,
              cmdline: cmd.cmdline,
              user: `${adDomain}\\${victim.id}`,
              integrity: "high",
            },
            raw: withCorr(
              {
                "event.code": "1",
                "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
                "winlog.provider_name": "Microsoft-Windows-Sysmon",
                "winlog.computer_name": victim.hostname,
                "winlog.event_data.Image": "C:\\Windows\\System32\\net.exe",
                "winlog.event_data.CommandLine": cmd.cmdline,
                "winlog.event_data.ParentImage":
                  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "winlog.event_data.ParentProcessId": String(psPid),
                "winlog.event_data.ProcessId": String(netPid),
                "winlog.event_data.User": `${adDomain}\\${victim.id}`,
                "winlog.event_data.IntegrityLevel": "High",
                "winlog.event_data.LogonId": session.logonId,
              },
              world
            ),
          };
        });

        return {
          events,
          nextDelayMs: 60_000,
        };
      },
    },

    // ── Phase 2: scheduled_task_create ───────────────────────────────────────
    {
      id: "scheduled_task_create",
      name: "IT Admin Scheduled Task Creation",
      mitre: "T1053.005",
      isFPPhase: true,
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const ctx = world.attack!.ctx;
        const session = getOrCreateSession(world, victim);
        const adDomain = world.meta.adDomain || "CORP";
        const psPid = ctx.admin_ps_pid as number;
        const schtaskPid = world.rng.pid();

        const ev: GeneratedEvent = {
          id: eid("itadmin_schtask"),
          source: "sysmon",
          vendor: "Microsoft Sysmon",
          event_type: "scheduled_task",
          severity: "medium",
          mitre_technique: "T1053.005",
          hostname: victim.hostname,
          user_email: victim.email,
          description: `Scheduled task created by IT admin ${victim.id} for daily backup`,
          expected_verdict: "fp",
          process: {
            name: "schtasks.exe",
            pid: schtaskPid,
            path: "C:\\Windows\\System32\\schtasks.exe",
            parent_name: "powershell.exe",
            parent_pid: psPid,
            cmdline: `schtasks.exe /create /tn "Daily-Backup-Job" /tr "C:\\Scripts\\backup.bat" /sc daily /st 02:00 /ru "SYSTEM"`,
            user: `${adDomain}\\${victim.id}`,
            integrity: "high",
          },
          raw: withCorr(
            {
              "event.code": "1",
              "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
              "winlog.provider_name": "Microsoft-Windows-Sysmon",
              "winlog.computer_name": victim.hostname,
              "winlog.event_data.Image": "C:\\Windows\\System32\\schtasks.exe",
              "winlog.event_data.CommandLine": `schtasks.exe /create /tn "Daily-Backup-Job" /tr "C:\\Scripts\\backup.bat" /sc daily /st 02:00 /ru "SYSTEM"`,
              "winlog.event_data.ParentImage":
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "winlog.event_data.ParentProcessId": String(psPid),
              "winlog.event_data.ProcessId": String(schtaskPid),
              "winlog.event_data.User": `${adDomain}\\${victim.id}`,
              "winlog.event_data.IntegrityLevel": "High",
              "winlog.event_data.LogonId": session.logonId,
              "task.name": "Daily-Backup-Job",
              "task.trigger": "Daily",
              "task.start_time": "02:00",
              "task.run_as": "SYSTEM",
            },
            world
          ),
        };

        return {
          events: [ev],
          nextDelayMs: 0,
        };
      },
    },
  ],
};

// ─── PLAYBOOK 5: Penetration Test Noise (False Positive) ─────────────────────

const playbookPentestNoise: AttackPlaybook = {
  id: "pentest_noise",
  name: "Penetration Test Noise — False Positive",
  isFP: true,

  selectVictim(world: WorldState): CompanyUser | null {
    // Prefer security/IT admin
    const securityAdmin = world.meta.users.find(
      (u) => u.isAdmin && (u.department === "Security" || u.department === "IT")
    );
    if (securityAdmin) return securityAdmin;
    const admin = world.meta.users.find((u) => u.isAdmin);
    return admin ?? world.meta.users[0];
  },

  phases: [
    // ── Phase 0: port_scan ───────────────────────────────────────────────────
    {
      id: "port_scan",
      name: "Internal Port Scan (Nessus)",
      mitre: "T1046",
      isFPPhase: true,
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        // Security team subnet — use a known internal security range
        const scannerIp = "10.0.50.10";
        const targetServer = world.meta.servers[0];
        const targetIp = targetServer.ip;

        const ev: GeneratedEvent = {
          id: eid("pentest_scan"),
          source: "firewall",
          vendor: fwVendor(world),
          event_type: "net_connection",
          severity: "medium",
          hostname: victim.hostname,
          user_email: victim.email,
          src_ip: scannerIp,
          dst_ip: targetIp,
          dst_port: 443,
          protocol: "tcp",
          description: `Port scan detected from internal security subnet — likely Nessus/vulnerability scanner`,
          expected_verdict: "fp",
          raw: withCorr(
            {
              "data.srcip": scannerIp,
              "data.srcport": String(world.rng.srcPort()),
              "data.dstip": targetIp,
              "data.dport": "443",
              "data.proto": "6",
              "data.action": "allow",
              "data.app": "ssl",
              "data.rule": "Allow-Internal-Scan",
              "data.scan_tool": "Nessus",
              "data.ports_scanned": "22,80,443,445,3389,8080,8443",
              "data.bytes_sent": "512",
              "data.bytes_received": "0",
              "data.session_count": "47",
            },
            world
          ),
        };

        return {
          events: [ev],
          ctxUpdate: { scanner_ip: scannerIp },
          nextDelayMs: 45_000,
        };
      },
    },

    // ── Phase 1: auth_attempts ───────────────────────────────────────────────
    {
      id: "auth_attempts",
      name: "Scanner Auth Attempts",
      mitre: "T1110.001",
      isFPPhase: true,
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const ctx = world.attack!.ctx;
        const scannerIp = ctx.scanner_ip as string;
        const adDomain = world.meta.adDomain || "CORP";

        // 3 different hosts to test
        const targets = world.meta.servers.slice(0, 3);

        const events: GeneratedEvent[] = targets.map((target, i) => ({
          id: eid(`pentest_auth${i}`),
          source: "ad" as const,
          vendor: "Windows Security",
          event_type: "auth_failure" as const,
          severity: "low" as const,
          mitre_technique: "T1110.001",
          hostname: target.hostname,
          user_email: victim.email,
          src_ip: scannerIp,
          description: `Auth failure from internal scanner ${scannerIp} against ${target.hostname} — Nessus default credential test`,
          expected_verdict: "fp" as const,
          raw: withCorr(
            {
              "event.code": "4625",
              "event.action": "logon-failed",
              "event.outcome": "failure",
              "winlog.channel": "Security",
              "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
              "winlog.computer_name": target.hostname,
              "winlog.event_data.LogonType": "3",
              "winlog.event_data.TargetUserName": "administrator",
              "winlog.event_data.TargetDomainName": adDomain,
              "winlog.event_data.IpAddress": scannerIp,
              "winlog.event_data.WorkstationName": "NESSUS-SCANNER",
              "winlog.event_data.AuthenticationPackageName": "NTLM",
              "winlog.event_data.FailureReason": "%%2313",
              "winlog.event_data.Status": "0xC000006D",
              "winlog.event_data.SubStatus": "0xC0000064",
              "source.ip": scannerIp,
              "user.name": "administrator",
              "user.domain": adDomain,
            },
            world
          ),
        }));

        return {
          events,
          nextDelayMs: 30_000,
        };
      },
    },

    // ── Phase 2: vuln_scan_http ──────────────────────────────────────────────
    {
      id: "vuln_scan_http",
      name: "WAF Hit from Vulnerability Scanner",
      mitre: "T1190",
      isFPPhase: true,
      generate(world: WorldState): AttackPhaseResult {
        const victim = world.attack!.victim;
        const ctx = world.attack!.ctx;
        const scannerIp = ctx.scanner_ip as string;
        const targetServer = world.meta.servers.find((s) => s.role !== "domain_controller") ?? world.meta.servers[0];

        const ev: GeneratedEvent = {
          id: eid("pentest_waf"),
          source: "waf",
          vendor: "AWS WAF",
          event_type: "waf_allow",
          severity: "low",
          mitre_technique: "T1190",
          hostname: targetServer.hostname,
          user_email: victim.email,
          src_ip: scannerIp,
          dst_ip: targetServer.ip,
          dst_port: 443,
          protocol: "tcp",
          description: `WAF rule triggered by vulnerability scanner — internal IP ${scannerIp} (Nessus)`,
          expected_verdict: "fp",
          network: {
            url: `https://${targetServer.hostname}/admin/login`,
            method: "GET",
            status: 200,
            user_agent: "Nessus/10.6.1 (compatible; scanner)",
            bytes_out: 1024,
            bytes_in: 4096,
          },
          raw: withCorr(
            {
              "waf.action": "Allow",
              "waf.rule_id": "AWSManagedRulesCommonRuleSet",
              "waf.rule_name": "SQLi_BODY",
              "waf.terminating_rule_type": "REGULAR",
              "waf.request.uri": "/admin/login",
              "waf.request.method": "GET",
              "waf.request.headers.host": targetServer.hostname,
              "waf.request.headers.user-agent": "Nessus/10.6.1 (compatible; scanner)",
              "waf.client_ip": scannerIp,
              "waf.web_acl_id": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-waf/abc123",
              "http.response.status_code": "200",
              "http.request.referrer": "",
              "waf.labels": ["scanner", "internal", "pentest"],
              "waf.country": "Reserved",
            },
            world
          ),
        };

        return {
          events: [ev],
          nextDelayMs: 0,
        };
      },
    },
  ],
};

// ─── Playbook registry ────────────────────────────────────────────────────────

export const PLAYBOOKS: AttackPlaybook[] = [
  playbookPhishingBEC,
  playbookPasswordSpray,
  playbookRansomware,
  playbookITMaintenance,
  playbookPentestNoise,
];

const REAL_ATTACKS = PLAYBOOKS.filter((p) => !p.isFP);
const FP_PLAYBOOKS = PLAYBOOKS.filter((p) => p.isFP);

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Pick a random playbook weighted 60% real attacks / 40% false positives.
 * Never picks the same playbook that is currently active.
 */
export function pickPlaybook(world: WorldState): AttackPlaybook {
  const pool = world.rng.next() < 0.6 ? REAL_ATTACKS : FP_PLAYBOOKS;
  // Avoid re-picking the same active playbook
  const eligible = pool.filter((p) => p.id !== world.attack?.playbookId);
  if (eligible.length === 0) return world.rng.choice(pool);
  return world.rng.choice(eligible);
}

/**
 * Initialize a new attack: selects victim, builds AttackCtx, sets on world.attack.
 * Returns the initialized AttackCtx.
 */
export function startAttack(world: WorldState, playbook: AttackPlaybook): AttackCtx {
  const victim = playbook.selectVictim(world) ?? world.meta.users[0];

  const ctx: AttackCtx = {
    playbookId: playbook.id,
    isFP: playbook.isFP,
    phase: 0,
    victim,
    attackerIp: externalAttackerIp(world),
    correlationId: world.rng.guid(),
    startTime: world.simTime,
    nextEventAt: world.simTime, // fire immediately
    ctx: {},
  };

  world.attack = ctx;
  return ctx;
}

/**
 * Advance the current attack by one phase.
 * Generates events for the current phase, updates ctx, increments phase counter.
 * Returns the batch of events, or null if the attack is finished.
 */
export function advanceAttack(world: WorldState): GeneratedEvent[] | null {
  if (!world.attack) return null;

  const { playbookId, phase } = world.attack;
  const playbook = PLAYBOOKS.find((p) => p.id === playbookId);

  if (!playbook || phase >= playbook.phases.length) {
    world.attack = null;
    return null;
  }

  const result: AttackPhaseResult = playbook.phases[phase].generate(world);

  // Merge ctx updates into attack state
  if (result.ctxUpdate) {
    Object.assign(world.attack.ctx, result.ctxUpdate);
  }

  // Advance to next phase
  world.attack.phase++;
  world.attack.nextEventAt = world.simTime + result.nextDelayMs;

  // Clear attack when all phases are done
  if (world.attack.phase >= playbook.phases.length) {
    const completedId = playbookId;
    // Defer clear so callers can still inspect world.attack.correlationId
    const ref = world.attack;
    Promise.resolve().then(() => {
      if (world.attack === ref && world.attack?.playbookId === completedId) {
        world.attack = null;
      }
    });
  }

  return result.events;
}

/**
 * Returns true if it's time to emit the next attack event.
 * The caller should call advanceAttack() when this returns true.
 */
export function attackDue(world: WorldState): boolean {
  if (!world.attack) return false;
  return world.simTime >= world.attack.nextEventAt;
}
