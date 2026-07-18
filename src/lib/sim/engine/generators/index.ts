/**
 * generators/index.ts
 * Benign event generator — delegates to category-specific generators based
 * on the company's behavior weight profile.
 */

import type { WorldState, GeneratedEvent, CompanyUser } from "@/lib/sim/engine/types";
import {
  getOrCreateSession,
  spawnProcess,
  getProcessByName,
  pickUser,
} from "@/lib/sim/engine/worldState";

// ─── Utility helpers ──────────────────────────────────────────────────────────

function ts(world: WorldState): string {
  return new Date(world.simTime).toISOString();
}

function nextId(world: WorldState, prefix: string): string {
  world.count += 1;
  return `${prefix}_${world.count.toString().padStart(5, "0")}`;
}

function pickActiveUser(world: WorldState): CompanyUser {
  const active = [...world.sessions.values()].map((s) => s.user);
  if (active.length > 0) return world.rng.choice(active);
  // Fall back: pick any non-service user and create a session
  return pickUser(world, (u) => !u.id.includes(".svc") && !u.id.includes("ci."));
}

function pickActiveOrAnyUser(world: WorldState): CompanyUser {
  return pickActiveUser(world);
}

// Well-known external IP → geo mapping used across generators
const WELL_KNOWN_DEST_IPS: Record<string, string> = {
  "teams.microsoft.com": "52.113.194.132",
  "outlook.office365.com": "40.97.64.9",
  "login.microsoftonline.com": "20.190.144.147",
  "github.com": "140.82.121.4",
  "api.pagerduty.com": "52.74.183.40",
  "api.github.com": "140.82.121.5",
  "registry.npmjs.org": "104.16.17.35",
  "hub.docker.com": "54.236.7.185",
  "8.8.8.8": "8.8.8.8",
  "1.1.1.1": "1.1.1.1",
};

// ─── Auth generator ───────────────────────────────────────────────────────────

function genAuth(world: WorldState): GeneratedEvent {
  const roll = world.rng.next();

  // auth_success 70%
  if (roll < 0.70) {
    const user = pickUser(world);
    const session = getOrCreateSession(world, user);

    if (world.meta.idp === "okta") {
      return {
        id: nextId(world, "auth"),
        ts: ts(world),
        source: "okta",
        vendor: "Okta",
        event_type: "auth_success",
        severity: "informational",
        hostname: user.hostname,
        user_email: user.email,
        user_title: user.title,
        user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
        src_ip: session.ip,
        description: `${user.name} signed in via Okta from ${session.ip}`,
        raw: {
          "data.okta.eventType": "user.session.start",
          "data.okta.outcome.result": "SUCCESS",
          "data.okta.outcome.reason": null,
          "data.okta.actor.alternateId": user.email,
          "data.okta.actor.displayName": user.name,
          "data.okta.actor.type": "User",
          "data.okta.client.ipAddress": session.ip,
          "data.okta.client.userAgent.rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
          "data.okta.client.geographicalContext.country": "Israel",
          "data.okta.client.geographicalContext.city": "Tel Aviv",
          "data.okta.authenticationContext.authenticationStep": 2,
          "data.okta.authenticationContext.credentialProvider": "OKTA_CREDENTIAL_PROVIDER",
          "data.okta.uuid": world.rng.guid(),
          "action_result": "success",
        },
      };
    }

    // AzureAD path (nexacorp / medcore)
    return {
      id: nextId(world, "auth"),
      ts: ts(world),
      source: "ad",
      vendor: "Microsoft Active Directory",
      event_type: "auth_success",
      severity: "informational",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      src_ip: session.ip,
      description: `${user.name} logged on to ${user.hostname} (Logon Type 3, Kerberos)`,
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": user.hostname,
        "winlog.record_id": String(world.rng.range(1_000_000, 9_999_999)),
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.TargetUserName": user.id,
        "winlog.event_data.TargetDomainName": world.meta.adDomain,
        "winlog.event_data.LogonProcessName": "Kerberos",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.LogonId": session.logonId,
        "winlog.event_data.IpAddress": session.ip,
        "winlog.event_data.WorkstationName": user.hostname,
        "data.office365.Operation": "UserLoggedIn",
        "data.office365.ActorIpAddress": session.ip,
        "data.office365.UserId": user.email,
        "data.office365.ResultStatus": "Succeeded",
        "event.outcome": "success",
        "user.name": user.id,
        "user.domain": world.meta.adDomain,
        "source.ip": session.ip,
        "action_result": "success",
      },
    };
  }

  // auth_failure 20% (brute-force noise — user NOT in active sessions)
  if (roll < 0.90) {
    const activeSessions = new Set(world.sessions.keys());
    const inactiveUsers = world.meta.users.filter((u) => !activeSessions.has(u.id));
    const user = inactiveUsers.length > 0
      ? world.rng.choice(inactiveUsers)
      : world.rng.choice(world.meta.users);

    return {
      id: nextId(world, "auth"),
      ts: ts(world),
      source: "ad",
      vendor: "Microsoft Active Directory",
      event_type: "auth_failure",
      severity: "low",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      description: `Failed logon attempt for ${user.id} on ${user.hostname} — wrong password`,
      raw: {
        "event.code": "4625",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": user.hostname,
        "winlog.record_id": String(world.rng.range(1_000_000, 9_999_999)),
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.TargetUserName": user.id,
        "winlog.event_data.TargetDomainName": world.meta.adDomain,
        "winlog.event_data.WorkstationName": user.hostname,
        "winlog.event_data.Status": "0xC000006D",
        "winlog.event_data.SubStatus": "0xC000006A",
        "winlog.event_data.FailureReason": "%%2313",
        "event.outcome": "failure",
        "user.name": user.id,
        "action_result": "failure",
      },
    };
  }

  // mfa_challenge 10%
  const user = pickActiveOrAnyUser(world);
  const session = getOrCreateSession(world, user);
  const mfaMethod = world.rng.choice(["push", "totp", "push"]);

  if (world.meta.idp === "okta") {
    return {
      id: nextId(world, "auth"),
      ts: ts(world),
      source: "okta",
      vendor: "Okta",
      event_type: "mfa_challenge",
      severity: "informational",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      src_ip: session.ip,
      description: `MFA ${mfaMethod === "push" ? "push notification" : "TOTP"} challenge approved for ${user.name}`,
      raw: {
        "data.okta.eventType": "user.authentication.auth_via_mfa",
        "data.okta.outcome.result": "SUCCESS",
        "data.okta.actor.alternateId": user.email,
        "data.okta.client.ipAddress": session.ip,
        "data.okta.authenticationContext.credentialProvider": mfaMethod === "totp" ? "GOOGLE_AUTH" : "OKTA_CREDENTIAL_PROVIDER",
        "data.okta.authenticationContext.authenticationStep": "1",
        "data.okta.target.displayName": "Okta Dashboard",
        "data.okta.target.type": "AppInstance",
        "data.okta.uuid": world.rng.guid(),
        "mfa.method": mfaMethod,
        "mfa.result": "approved",
        "action_result": "success",
      },
    };
  }

  return {
    id: nextId(world, "auth"),
    ts: ts(world),
    source: "mfa",
    vendor: "Microsoft Azure AD MFA",
    event_type: "mfa_challenge",
    severity: "informational",
    hostname: user.hostname,
    user_email: user.email,
    user_title: user.title,
    user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
    src_ip: session.ip,
    description: `Azure MFA ${mfaMethod === "push" ? "push" : "TOTP"} approved for ${user.name}`,
    raw: {
      "data.office365.Operation": "UserLoginFailed",
      "data.office365.ErrorNumber": "50074",
      "data.office365.ResultStatus": "Interrupted",
      "data.office365.UserId": user.email,
      "data.office365.ActorIpAddress": session.ip,
      "data.office365.Workload": "AzureActiveDirectory",
      "data.office365.AzureActiveDirectoryEventType": "AccountLogon",
      "mfa.method": mfaMethod,
      "mfa.result": "approved",
      "action_result": "success",
    },
  };
}

// ─── Process generator ────────────────────────────────────────────────────────

function genProcess(world: WorldState): GeneratedEvent {
  const user = pickActiveOrAnyUser(world);
  const session = getOrCreateSession(world, user);
  const hostname = user.hostname;
  const isWindows = user.osType === "windows";
  const isMac = user.osType === "macos";
  const isAdmin = user.isAdmin;
  const domain = world.meta.adDomain;

  // Explorer parent pid (Windows default)
  const explorerProc = getProcessByName(world, hostname, "explorer.exe");
  const explorerPid = explorerProc?.pid ?? 2400;
  const explorerPath = "C:\\Windows\\explorer.exe";

  // RocketStack dev environment
  if (!isWindows) {
    const devChoices = [
      {
        name: "node",
        path: "/usr/local/bin/node",
        cmdLine: "node dist/server.js --port 3000",
        parentName: "iTerm2",
        parentPath: "/Applications/iTerm.app/Contents/MacOS/iTerm2",
      },
      {
        name: "python3",
        path: "/usr/local/bin/python3",
        cmdLine: "python3 scripts/migrate_db.py --env staging",
        parentName: "iTerm2",
        parentPath: "/Applications/iTerm.app/Contents/MacOS/iTerm2",
      },
      {
        name: "docker",
        path: "/usr/local/bin/docker",
        cmdLine: "docker build -t rocketstack/api:latest .",
        parentName: "iTerm2",
        parentPath: "/Applications/iTerm.app/Contents/MacOS/iTerm2",
      },
      {
        name: "kubectl",
        path: "/usr/local/bin/kubectl",
        cmdLine: "kubectl get pods -n production",
        parentName: "iTerm2",
        parentPath: "/Applications/iTerm.app/Contents/MacOS/iTerm2",
      },
      {
        name: "git",
        path: "/usr/bin/git",
        cmdLine: "git push origin main",
        parentName: "iTerm2",
        parentPath: "/Applications/iTerm.app/Contents/MacOS/iTerm2",
      },
    ];
    const choice = world.rng.choice(devChoices);
    const parentPid = world.rng.range(500, 2000);
    const node = spawnProcess(world, hostname, {
      name: choice.name,
      path: choice.path,
      cmdLine: choice.cmdLine,
      parentName: choice.parentName,
      parentPath: choice.parentPath,
      parentPid,
      userId: user.id,
      logonId: session.logonId,
      integrity: "medium",
      signed: true,
    });

    return {
      id: nextId(world, "proc"),
      ts: ts(world),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      severity: "informational",
      hostname,
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      process: {
        name: node.name,
        pid: node.pid,
        path: node.path,
        parent_name: node.parentName,
        parent_pid: node.parentPid,
        cmdline: node.cmdLine,
        user: user.id,
        integrity: node.integrity,
        hash: { sha256: node.sha256 },
      },
      description: `${user.name} ran ${node.name} — ${choice.cmdLine}`,
      raw: {
        "crowdstrike.event_simplename": "ProcessRollup2",
        "cs.ContextProcessName": node.name,
        "cs.CommandLine": node.cmdLine,
        "cs.ParentProcessName": node.parentName,
        "cs.TargetProcessId_decimal": String(node.pid),
        "cs.UserName": user.id,
        "cs.ComputerName": hostname,
        "cs.FilePath": node.path,
        "cs.SHA256HashData": node.sha256,
        "host.name": hostname,
        "user.name": user.id,
        "file.signed": "true",
        "action_result": "allowed",
      },
    };
  }

  // MedCore Epic EMR
  if (world.meta.id === "medcore" && world.rng.next() < 0.25) {
    const serverIp = "172.16.20.10";
    const node = spawnProcess(world, hostname, {
      name: "EpicCare.exe",
      path: "C:\\Program Files\\Epic\\EpicCare\\EpicCare.exe",
      cmdLine: `EpicCare.exe /server=${serverIp} /user=${user.id}`,
      parentName: "explorer.exe",
      parentPath: explorerPath,
      parentPid: explorerPid,
      userId: user.id,
      logonId: session.logonId,
      integrity: "medium",
      signed: true,
    });

    return {
      id: nextId(world, "proc"),
      ts: ts(world),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "process_create",
      severity: "informational",
      hostname,
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      process: {
        name: node.name,
        pid: node.pid,
        path: node.path,
        parent_name: "explorer.exe",
        parent_pid: explorerPid,
        cmdline: node.cmdLine,
        user: `${domain}\\${user.id}`,
        integrity: "medium",
        hash: { sha256: node.sha256 },
      },
      description: `${user.name} launched Epic EMR client connecting to ${serverIp}`,
      raw: {
        "event.code": "1",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.event_data.Image": node.path,
        "winlog.event_data.CommandLine": node.cmdLine,
        "winlog.event_data.ParentImage": explorerPath,
        "winlog.event_data.ParentProcessId": String(explorerPid),
        "winlog.event_data.ProcessId": String(node.pid),
        "winlog.event_data.User": `${domain}\\${user.id}`,
        "winlog.event_data.IntegrityLevel": "Medium",
        "winlog.event_data.Hashes": `SHA256=${node.sha256}`,
        "winlog.computer_name": hostname,
        "action_result": "allowed",
      },
    };
  }

  // Windows processes
  const winChoices = [
    {
      name: "msedge.exe",
      path: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
      cmdLine: "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window",
      parentName: "explorer.exe",
      parentPath: explorerPath,
      parentPid: explorerPid,
      adminOnly: false,
    },
    {
      name: "OUTLOOK.EXE",
      path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
      cmdLine: "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"",
      parentName: "explorer.exe",
      parentPath: explorerPath,
      parentPid: explorerPid,
      adminOnly: false,
    },
    {
      name: "Teams.exe",
      path: "C:\\Users\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
      cmdLine: "C:\\Users\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe --processStart \"Teams.exe\"",
      parentName: "explorer.exe",
      parentPath: explorerPath,
      parentPid: explorerPid,
      adminOnly: false,
    },
    {
      name: "EXCEL.EXE",
      path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
      cmdLine: `"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" "C:\\Users\\${user.id}\\Documents\\Q3-Budget-Review.xlsx"`,
      parentName: "explorer.exe",
      parentPath: explorerPath,
      parentPid: explorerPid,
      adminOnly: false,
    },
    {
      name: "powershell.exe",
      path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdLine: "powershell.exe -NonInteractive -File C:\\Scripts\\backup.ps1",
      parentName: "services.exe",
      parentPath: "C:\\Windows\\System32\\services.exe",
      parentPid: 600,
      adminOnly: true,
    },
    {
      name: "cmd.exe",
      path: "C:\\Windows\\System32\\cmd.exe",
      cmdLine: "cmd.exe /c net group \"Domain Admins\" /domain",
      parentName: "explorer.exe",
      parentPath: explorerPath,
      parentPid: explorerPid,
      adminOnly: true,
    },
  ];

  const available = winChoices.filter((c) => !c.adminOnly || isAdmin);
  const choice = world.rng.choice(available);

  const node = spawnProcess(world, hostname, {
    name: choice.name,
    path: choice.path,
    cmdLine: choice.cmdLine,
    parentName: choice.parentName,
    parentPath: choice.parentPath,
    parentPid: choice.parentPid,
    userId: `${domain}\\${user.id}`,
    logonId: session.logonId,
    integrity: "medium",
    signed: true,
  });

  return {
    id: nextId(world, "proc"),
    ts: ts(world),
    source: "sysmon",
    vendor: "Microsoft Sysmon",
    event_type: "process_create",
    severity: "informational",
    hostname,
    user_email: user.email,
    user_title: user.title,
    user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
    process: {
      name: node.name,
      pid: node.pid,
      path: node.path,
      parent_name: node.parentName,
      parent_pid: node.parentPid,
      cmdline: node.cmdLine,
      user: `${domain}\\${user.id}`,
      integrity: "medium",
      hash: { sha256: node.sha256 },
    },
    description: `${user.name} launched ${node.name} on ${hostname}`,
    raw: {
      "event.code": "1",
      "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
      "winlog.provider_name": "Microsoft-Windows-Sysmon",
      "winlog.event_data.Image": node.path,
      "winlog.event_data.CommandLine": node.cmdLine,
      "winlog.event_data.ParentImage": node.parentPath,
      "winlog.event_data.ParentProcessId": String(node.parentPid),
      "winlog.event_data.ProcessId": String(node.pid),
      "winlog.event_data.User": `${domain}\\${user.id}`,
      "winlog.event_data.IntegrityLevel": "Medium",
      "winlog.event_data.Hashes": `SHA256=${node.sha256}`,
      "winlog.computer_name": hostname,
      "action_result": "allowed",
    },
  };
}

// ─── Network generator ────────────────────────────────────────────────────────

function genNetwork(world: WorldState): GeneratedEvent {
  const user = pickActiveOrAnyUser(world);
  const session = getOrCreateSession(world, user);
  const hostIp = session.ip;
  const firewall = world.meta.firewall;

  // Destination choices vary by company
  const m365Dests = [
    { domain: "teams.microsoft.com", ip: "52.113.194.132", port: 443, app: "ssl" },
    { domain: "outlook.office365.com", ip: "40.97.64.9", port: 443, app: "ssl" },
    { domain: "login.microsoftonline.com", ip: "20.190.144.147", port: 443, app: "ssl" },
  ];
  const devDests = [
    { domain: "api.github.com", ip: "140.82.121.5", port: 443, app: "ssl" },
    { domain: "registry.npmjs.org", ip: "104.16.17.35", port: 443, app: "ssl" },
    { domain: "hub.docker.com", ip: "54.236.7.185", port: 443, app: "ssl" },
  ];
  const commonDests = [
    { domain: "github.com", ip: "140.82.121.4", port: 443, app: "ssl" },
    { domain: "api.pagerduty.com", ip: "52.74.183.40", port: 443, app: "ssl" },
  ];

  const destPool = world.meta.emailStack === "gsuite"
    ? [...devDests, ...commonDests]
    : [...m365Dests, ...commonDests];

  // Internal SMB — 15% chance
  const doInternalSmb = world.rng.next() < 0.15;
  if (doInternalSmb && world.meta.servers.some((s) => s.role === "file_server")) {
    const fileServer = world.meta.servers.find((s) => s.role === "file_server")!;
    const srcPort = world.rng.srcPort();

    if (firewall === "checkpoint") {
      return {
        id: nextId(world, "net"),
        ts: ts(world),
        source: "firewall",
        vendor: "Check Point NGFW",
        event_type: "net_connection",
        severity: "informational",
        hostname: user.hostname,
        user_email: user.email,
        user_title: user.title,
        src_ip: hostIp,
        dst_ip: fileServer.ip,
        dst_port: 445,
        protocol: "tcp",
        description: `${user.name} accessed file share on ${fileServer.hostname} via SMB`,
        raw: {
          "data.src": hostIp,
          "data.sport_svc": String(srcPort),
          "data.dst": fileServer.ip,
          "data.svc": "445",
          "data.service": "SMB",
          "data.proto": "6",
          "data.protocol": "TCP",
          "data.action": "Accept",
          "data.rule_name": "Internal-File-Access",
          "data.ProductName": "VPN-1 & FireWall-1",
          "data.ProductFamily": "Network",
          "data.inzone": "Internal",
          "data.outzone": "Internal",
          "data.user": `${world.meta.adDomain}\\${user.id}`,
          "data.src_machine_name": user.hostname,
          "cp.app_name": "SMB",
          "cp.bytes": String(world.rng.range(4096, 102400)),
          "firewall.action": "allow",
          "action_result": "allowed",
        },
      };
    }

    // PaloAlto SMB
    return {
      id: nextId(world, "net"),
      ts: ts(world),
      source: "firewall",
      vendor: "Palo Alto Networks NGFW",
      event_type: "net_connection",
      severity: "informational",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      src_ip: hostIp,
      dst_ip: fileServer.ip,
      dst_port: 445,
      protocol: "tcp",
      description: `${user.name} accessed file share on ${fileServer.hostname} via SMB`,
      raw: {
        "data.type": "traffic",
        "data.subtype": "end",
        "data.srcip": hostIp,
        "data.sport": String(srcPort),
        "data.dstip": fileServer.ip,
        "data.dport": "445",
        "data.proto": "6",
        "data.action": "allow",
        "data.rule": "Allow-Internal-SMB",
        "data.app": "smb",
        "data.from": "Trust",
        "data.to": "Trust",
        "data.bytes": String(world.rng.range(4096, 102400)),
        "data.elapsed": String(world.rng.range(1, 5)),
        "pan.app": "smb",
        "pan.action": "allow",
        "pan.rule": "Allow-Internal-SMB",
        "firewall.action": "allow",
        "action_result": "allowed",
      },
    };
  }

  const dest = world.rng.choice(destPool);
  const srcPort = world.rng.srcPort();
  const bytesOut = world.rng.range(1200, 50000);
  const bytesIn = world.rng.range(500, 200000);

  if (firewall === "paloalto") {
    return {
      id: nextId(world, "net"),
      ts: ts(world),
      source: "firewall",
      vendor: "Palo Alto Networks NGFW",
      event_type: "net_connection",
      severity: "informational",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      src_ip: hostIp,
      dst_ip: dest.ip,
      dst_port: dest.port,
      protocol: "tcp",
      network: { domain: dest.domain, bytes_out: bytesOut, bytes_in: bytesIn },
      description: `${user.hostname} → ${dest.domain}:${dest.port} (HTTPS) allowed by firewall`,
      raw: {
        "data.type": "traffic",
        "data.subtype": "end",
        "data.srcip": hostIp,
        "data.sport": String(srcPort),
        "data.dstip": dest.ip,
        "data.dport": String(dest.port),
        "data.proto": "6",
        "data.action": "allow",
        "data.rule": "Allow-Web-Outbound",
        "data.app": dest.app,
        "data.from": "Trust",
        "data.to": "Untrust",
        "data.bytes": String(bytesOut + bytesIn),
        "data.sentbyte": String(bytesOut),
        "data.rcvdbyte": String(bytesIn),
        "data.elapsed": String(world.rng.range(1, 30)),
        "pan.app": dest.app,
        "pan.action": "allow",
        "pan.rule": "Allow-Web-Outbound",
        "network.application": dest.app,
        "firewall.action": "allow",
        "action_result": "allowed",
      },
    };
  }

  if (firewall === "fortigate") {
    return {
      id: nextId(world, "net"),
      ts: ts(world),
      source: "firewall",
      vendor: "FortiGate NGFW",
      event_type: "net_connection",
      severity: "informational",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      src_ip: hostIp,
      dst_ip: dest.ip,
      dst_port: dest.port,
      protocol: "tcp",
      network: { domain: dest.domain, bytes_out: bytesOut, bytes_in: bytesIn },
      description: `${user.hostname} → ${dest.domain}:${dest.port} (HTTPS) accepted by FortiGate`,
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.logid": "0000000013",
        "data.level": "notice",
        "data.vd": "root",
        "data.action": "accept",
        "data.msg": "Forward traffic accepted",
        "data.logdesc": "Connection Accepted",
        "data.srcip": hostIp,
        "data.srcport": String(srcPort),
        "data.dstip": dest.ip,
        "data.dstport": String(dest.port),
        "data.proto": "6",
        "data.policyid": "10",
        "data.sentbyte": String(bytesOut),
        "data.rcvdbyte": String(bytesIn),
        "data.duration": String(world.rng.range(1, 30)),
        "data.srccountry": "Reserved",
        "data.dstuser": "",
        "data.eventtime": String(world.simTime * 1000),
        "firewall.action": "allow",
        "action_result": "allowed",
      },
    };
  }

  // checkpoint (medcore)
  return {
    id: nextId(world, "net"),
    ts: ts(world),
    source: "firewall",
    vendor: "Check Point NGFW",
    event_type: "net_connection",
    severity: "informational",
    hostname: user.hostname,
    user_email: user.email,
    user_title: user.title,
    src_ip: hostIp,
    dst_ip: dest.ip,
    dst_port: dest.port,
    protocol: "tcp",
    network: { domain: dest.domain, bytes_out: bytesOut, bytes_in: bytesIn },
    description: `${user.hostname} → ${dest.domain}:${dest.port} accepted by Check Point`,
    raw: {
      "data.src": hostIp,
      "data.sport_svc": String(srcPort),
      "data.dst": dest.ip,
      "data.svc": String(dest.port),
      "data.service": "HTTPS",
      "data.proto": "6",
      "data.protocol": "TCP",
      "data.action": "Accept",
      "data.rule_name": "Web-Outbound",
      "data.layer_name": "Network",
      "data.ProductName": "VPN-1 & FireWall-1",
      "data.ProductFamily": "Network",
      "data.inzone": "Internal",
      "data.outzone": "External",
      "data.user": `${world.meta.adDomain}\\${user.id}`,
      "data.src_machine_name": user.hostname,
      "cp.bytes": String(bytesOut + bytesIn),
      "cp.bytes_out": String(bytesOut),
      "cp.service": "HTTPS",
      "cp.blade": "Firewall",
      "firewall.action": "allow",
      "action_result": "allowed",
    },
  };
}

// ─── Office 365 generator ─────────────────────────────────────────────────────

function genOffice365(world: WorldState): GeneratedEvent {
  const user = pickActiveOrAnyUser(world);
  const session = getOrCreateSession(world, user);
  const roll = world.rng.next();

  // SharePoint file access — 30%
  if (roll < 0.30) {
    const files = [
      "Q2-Report.xlsx",
      "Budget-2026.xlsx",
      "Risk-Assessment-Q3.docx",
      "Compliance-Checklist.xlsx",
      "Team-Roster.xlsx",
      "Project-Timeline.pptx",
    ];
    const fileName = world.rng.choice(files);
    const siteName = world.meta.id === "medcore" ? "MedCore-Staff" : user.department;
    const siteUrl = `https://${world.meta.domain.replace(".", "-")}.sharepoint.com/sites/${siteName}`;

    return {
      id: nextId(world, "o365"),
      ts: ts(world),
      source: "sharepoint",
      vendor: "Microsoft SharePoint Online",
      event_type: "sharepoint_access",
      severity: "informational",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      src_ip: session.ip,
      description: `${user.name} accessed ${fileName} on SharePoint (${siteName})`,
      raw: {
        "data.office365.Operation": "FileAccessed",
        "data.office365.Workload": "SharePoint",
        "data.office365.UserId": user.email,
        "data.office365.ClientIP": session.ip,
        "data.office365.ResultStatus": "Succeeded",
        "data.office365.SourceFileName": fileName,
        "data.office365.SiteUrl": siteUrl,
        "data.office365.ObjectId": `${siteUrl}/Shared%20Documents/${fileName}`,
        "data.office365.UserAgent": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Excel 16.0.17628)",
        "data.office365.AzureActiveDirectoryEventType": "ResourceServicePrincipalLogon",
        "action_result": "allowed",
      },
    };
  }

  // Teams message — 20%
  if (roll < 0.50) {
    const threadId = world.rng.guid();
    const msgId = world.rng.guid();
    return {
      id: nextId(world, "o365"),
      ts: ts(world),
      source: "teams",
      vendor: "Microsoft Teams",
      event_type: "teams_message",
      severity: "informational",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      src_ip: session.ip,
      description: `${user.name} sent a message in Microsoft Teams`,
      raw: {
        "data.office365.Operation": "MessageSent",
        "data.office365.Workload": "MicrosoftTeams",
        "data.office365.UserId": user.email,
        "data.office365.ClientIP": session.ip,
        "data.office365.ResultStatus": "Succeeded",
        "data.office365.ChatThreadId": threadId,
        "data.office365.MessageId": msgId,
        "data.office365.AzureActiveDirectoryEventType": "UserManagement",
        "action_result": "allowed",
      },
    };
  }

  // OneDrive sync — 20%
  if (roll < 0.70) {
    const syncFiles = [
      "Monthly-Report.xlsx",
      "Presentation-Draft.pptx",
      "Meeting-Notes.docx",
      "Client-Contract.pdf",
    ];
    const fileName = world.rng.choice(syncFiles);
    const bytes = world.rng.range(102400, 5242880);

    return {
      id: nextId(world, "o365"),
      ts: ts(world),
      source: "o365",
      vendor: "Microsoft OneDrive",
      event_type: "cloud_api_call",
      severity: "informational",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      src_ip: session.ip,
      network: { bytes_in: bytes },
      description: `${user.name} synced ${fileName} from OneDrive (${Math.round(bytes / 1024)} KB)`,
      raw: {
        "data.office365.Operation": "FileSyncDownloadedFull",
        "data.office365.Workload": "OneDrive",
        "data.office365.UserId": user.email,
        "data.office365.ClientIP": session.ip,
        "data.office365.ResultStatus": "Succeeded",
        "data.office365.SourceFileName": fileName,
        "data.office365.FileSize": String(bytes),
        "action_result": "allowed",
      },
    };
  }

  // Calendar event — 15%
  if (roll < 0.85) {
    return {
      id: nextId(world, "o365"),
      ts: ts(world),
      source: "exchange",
      vendor: "Microsoft Exchange Online",
      event_type: "cloud_api_call",
      severity: "informational",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      src_ip: session.ip,
      description: `${user.name} created/updated a calendar event`,
      raw: {
        "data.office365.Operation": "Set-CalendarProcessing",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": user.email,
        "data.office365.ClientIP": session.ip,
        "data.office365.ResultStatus": "Succeeded",
        "action_result": "allowed",
      },
    };
  }

  // MFA prompt (Strong Auth Required) — 15%
  return {
    id: nextId(world, "o365"),
    ts: ts(world),
    source: "o365",
    vendor: "Microsoft Azure AD",
    event_type: "mfa_challenge",
    severity: "informational",
    hostname: user.hostname,
    user_email: user.email,
    user_title: user.title,
    user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
    src_ip: session.ip,
    description: `Azure AD MFA step-up required for ${user.name} — completed successfully`,
    raw: {
      "data.office365.Operation": "UserLoginFailed",
      "data.office365.Workload": "AzureActiveDirectory",
      "data.office365.UserId": user.email,
      "data.office365.ActorIpAddress": session.ip,
      "data.office365.ClientIP": session.ip,
      "data.office365.ResultStatus": "Interrupted",
      "data.office365.ErrorNumber": "50074",
      "data.office365.LogonError": "StrongAuthRequired",
      "data.office365.AzureActiveDirectoryEventType": "AccountLogon",
      "action_result": "success",
    },
  };
}

// ─── Email generator ──────────────────────────────────────────────────────────

function genEmail(world: WorldState): GeneratedEvent {
  const user = pickActiveOrAnyUser(world);
  const session = getOrCreateSession(world, user);

  const subjects = [
    "Q3 Budget Review",
    "Team standup notes",
    "Updated project timeline",
    "Client meeting tomorrow",
    "Invoice #INV-2026-447",
    "Re: Compliance training",
    "Monthly risk report",
    "Action items from today's call",
    "Updated SLA document",
    "Welcome to the team!",
  ];

  const externalDomains = ["gmail.com", "outlook.com", "yahoo.com", "partnerco.com", "consulting-grp.com"];
  const internalUsers = world.meta.users.filter((u) => u.id !== user.id && !u.id.includes("svc") && !u.id.includes("ci."));

  const subject = world.rng.choice(subjects);
  const isInternalSender = world.rng.next() < 0.6 && internalUsers.length > 0;
  const fromUser = isInternalSender ? world.rng.choice(internalUsers) : null;
  const fromAddress = fromUser
    ? fromUser.email
    : `contact@${world.rng.choice(externalDomains)}`;

  const isReceived = world.rng.next() < 0.6;

  return {
    id: nextId(world, "email"),
    ts: ts(world),
    source: "email_gateway",
    vendor: world.meta.emailStack === "gsuite" ? "Google Workspace" : "Microsoft Exchange Online",
    event_type: isReceived ? "email_received" : "email_sent",
    severity: "informational",
    hostname: user.hostname,
    user_email: user.email,
    user_title: user.title,
    user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
    src_ip: session.ip,
    description: isReceived
      ? `${user.name} received email: "${subject}" from ${fromAddress}`
      : `${user.name} sent email: "${subject}" to ${fromAddress}`,
    raw: {
      "data.office365.Operation": isReceived ? "MessageDelivered" : "SendMail",
      "data.office365.Workload": "Exchange",
      "data.office365.UserId": user.email,
      "data.office365.ClientIP": session.ip,
      "data.office365.ResultStatus": "Succeeded",
      "email.from.address": isReceived ? fromAddress : user.email,
      "email.to.address": isReceived ? user.email : fromAddress,
      "email.subject": subject,
      "email.spf": "pass",
      "email.dkim": "pass",
      "email.dmarc": "pass",
      "email.message_id": `<${world.rng.hex(16)}@${world.meta.domain}>`,
      "action_result": "allowed",
    },
  };
}

// ─── Active Directory generator ───────────────────────────────────────────────

function genAD(world: WorldState): GeneratedEvent {
  // Prefer admin users for AD events
  const adminUsers = world.meta.users.filter((u) => u.isAdmin);
  const user = adminUsers.length > 0 ? world.rng.choice(adminUsers) : pickUser(world);
  const session = getOrCreateSession(world, user);
  const dc = world.meta.servers.find((s) => s.role === "domain_controller");
  const dcHostname = dc?.hostname ?? `DC-${world.meta.adDomain}-01`;
  const domain = world.meta.adDomain;
  const roll = world.rng.next();

  // 4799 — Group membership query (20%)
  if (roll < 0.20) {
    const groups = ["Domain Admins", "Server Operators", "Backup Operators", "Remote Desktop Users"];
    const group = world.rng.choice(groups);
    return {
      id: nextId(world, "ad"),
      ts: ts(world),
      source: "ad",
      vendor: "Microsoft Active Directory",
      event_type: "privileged_operation",
      severity: "informational",
      hostname: dcHostname,
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      src_ip: session.ip,
      description: `${user.name} queried membership of "${group}" group on ${dcHostname}`,
      raw: {
        "event.code": "4799",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": dcHostname,
        "winlog.event_data.SubjectUserName": user.id,
        "winlog.event_data.SubjectDomainName": domain,
        "winlog.event_data.SubjectLogonId": session.logonId,
        "winlog.event_data.TargetUserName": group,
        "winlog.event_data.CallerProcessName": "C:\\Windows\\System32\\net.exe",
        "user.name": user.id,
        "action_result": "success",
      },
    };
  }

  // 4768 — Kerberos TGT (20%)
  if (roll < 0.40) {
    const computerAccounts = world.meta.users.map((u) => `${u.hostname}$`);
    const computerAccount = world.rng.choice(computerAccounts);
    return {
      id: nextId(world, "ad"),
      ts: ts(world),
      source: "ad",
      vendor: "Microsoft Active Directory",
      event_type: "kerberos_tgt",
      severity: "informational",
      hostname: dcHostname,
      user_email: user.email,
      user_title: user.title,
      src_ip: session.ip,
      description: `Kerberos TGT issued for ${computerAccount} (AES256)`,
      raw: {
        "event.code": "4768",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": dcHostname,
        "winlog.event_data.TargetUserName": computerAccount,
        "winlog.event_data.TargetDomainName": domain,
        "winlog.event_data.TicketEncryptionType": "0x12",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.IpAddress": session.ip,
        "user.name": computerAccount,
        "action_result": "success",
      },
    };
  }

  // 4723 — Password reset (20%)
  if (roll < 0.60) {
    const nonAdminUsers = world.meta.users.filter((u) => !u.isAdmin);
    const targetUser = nonAdminUsers.length > 0 ? world.rng.choice(nonAdminUsers) : world.rng.choice(world.meta.users);
    return {
      id: nextId(world, "ad"),
      ts: ts(world),
      source: "ad",
      vendor: "Microsoft Active Directory",
      event_type: "account_modify",
      severity: "low",
      hostname: dcHostname,
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      src_ip: session.ip,
      description: `${user.name} (helpdesk) reset password for ${targetUser.name}`,
      raw: {
        "event.code": "4723",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": dcHostname,
        "winlog.event_data.SubjectUserName": user.id,
        "winlog.event_data.SubjectDomainName": domain,
        "winlog.event_data.SubjectLogonId": session.logonId,
        "winlog.event_data.TargetUserName": targetUser.id,
        "winlog.event_data.TargetDomainName": domain,
        "user.name": user.id,
        "action_result": "success",
      },
    };
  }

  // 4672 — Privileged logon (20%)
  if (roll < 0.80) {
    return {
      id: nextId(world, "ad"),
      ts: ts(world),
      source: "ad",
      vendor: "Microsoft Active Directory",
      event_type: "privilege_escalation",
      severity: "informational",
      hostname: dcHostname,
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      src_ip: session.ip,
      description: `Admin ${user.name} assigned special privileges at logon on ${dcHostname}`,
      raw: {
        "event.code": "4672",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": dcHostname,
        "winlog.event_data.SubjectUserName": user.id,
        "winlog.event_data.SubjectDomainName": domain,
        "winlog.event_data.SubjectLogonId": session.logonId,
        "winlog.event_data.PrivilegeList": "SeSecurityPrivilege\n\t\t\t\tSeTakeOwnershipPrivilege\n\t\t\t\tSeLoadDriverPrivilege\n\t\t\t\tSeBackupPrivilege\n\t\t\t\tSeRestorePrivilege\n\t\t\t\tSeDebugPrivilege\n\t\t\t\tSeAuditPrivilege",
        "user.name": user.id,
        "action_result": "success",
      },
    };
  }

  // 4738 — Account modified (20%)
  const targetUser = world.rng.choice(world.meta.users.filter((u) => u.id !== user.id));
  return {
    id: nextId(world, "ad"),
    ts: ts(world),
    source: "ad",
    vendor: "Microsoft Active Directory",
    event_type: "account_modify",
    severity: "low",
    hostname: dcHostname,
    user_email: user.email,
    user_title: user.title,
    user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
    src_ip: session.ip,
    description: `${user.name} modified user account attributes for ${targetUser.name}`,
    raw: {
      "event.code": "4738",
      "winlog.channel": "Security",
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      "winlog.computer_name": dcHostname,
      "winlog.event_data.SubjectUserName": user.id,
      "winlog.event_data.SubjectDomainName": domain,
      "winlog.event_data.SubjectLogonId": session.logonId,
      "winlog.event_data.TargetUserName": targetUser.id,
      "winlog.event_data.TargetDomainName": domain,
      "winlog.event_data.DisplayName": targetUser.name,
      "user.name": user.id,
      "action_result": "success",
    },
  };
}

// ─── VPN generator ────────────────────────────────────────────────────────────

function genVPN(world: WorldState): GeneratedEvent {
  const user = pickUser(world, (u) => !u.id.includes("svc") && !u.id.includes("ci."));
  const session = getOrCreateSession(world, user);

  // Generate external IP (WFH user)
  const externalIp = `${world.rng.range(77, 220)}.${world.rng.range(1, 254)}.${world.rng.range(1, 254)}.${world.rng.range(1, 254)}`;
  const isLogin = world.rng.next() < 0.65;

  const vpnGateways: Record<string, string> = {
    nexacorp: "gp.nexacorp.com",
    medcore: "vpn.medcorehealth.org",
    rocketstack: "vpn.rocketstack.io",
  };
  const gateway = vpnGateways[world.meta.id] ?? "vpn.corp.com";
  const durationSec = world.rng.range(3600, 28800);
  const bytesIn = world.rng.range(50_000_000, 500_000_000);
  const bytesOut = world.rng.range(5_000_000, 50_000_000);

  return {
    id: nextId(world, "vpn"),
    ts: ts(world),
    source: "vpn",
    vendor: world.meta.firewall === "paloalto" ? "Palo Alto GlobalProtect" : "Cisco AnyConnect",
    event_type: isLogin ? "vpn_login" : "vpn_logout",
    severity: "informational",
    hostname: user.hostname,
    user_email: user.email,
    user_title: user.title,
    user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
    src_ip: externalIp,
    dst_ip: session.ip,
    description: isLogin
      ? `${user.name} connected to VPN from ${externalIp}, assigned ${session.ip}`
      : `${user.name} disconnected from VPN (session ${Math.round(durationSec / 60)}m)`,
    raw: {
      "vpn.user": user.email,
      "vpn.src_ip": externalIp,
      "vpn.assigned_ip": session.ip,
      "vpn.gateway": gateway,
      "vpn.event": isLogin ? "connected" : "disconnected",
      "vpn.duration_sec": String(durationSec),
      "vpn.bytes_in": String(bytesIn),
      "vpn.bytes_out": String(bytesOut),
      "vpn.tunnel_protocol": "IPsec/IKEv2",
      "vpn.auth_method": "certificate+mfa",
      "action_result": "success",
    },
  };
}

// ─── EDR / AV generator ───────────────────────────────────────────────────────

function genEDR(world: WorldState): GeneratedEvent {
  const user = pickUser(world);
  const hostname = user.hostname;
  const roll = world.rng.next();

  const edrVendor = world.meta.edr === "crowdstrike"
    ? "CrowdStrike Falcon"
    : "Microsoft Defender for Endpoint";
  const source = world.meta.edr === "crowdstrike" ? "edr" : "av";

  // Clean scan — 50%
  if (roll < 0.50) {
    return {
      id: nextId(world, "edr"),
      ts: ts(world),
      source,
      vendor: edrVendor,
      event_type: "av_detection",
      severity: "informational",
      hostname,
      user_email: user.email,
      user_title: user.title,
      description: `Scheduled AV scan completed on ${hostname} — no threats detected`,
      raw: {
        "av.scan_type": "scheduled",
        "av.result": "clean",
        "av.threat_name": "",
        "av.action": "no_action_needed",
        "av.scanned_files": String(world.rng.range(120000, 450000)),
        "av.scan_duration_sec": String(world.rng.range(180, 1800)),
        "host.name": hostname,
        "user.name": user.id,
        "action_result": "clean",
      },
    };
  }

  // PUA quarantine — 20%
  if (roll < 0.70) {
    const puas = [
      { name: "PUA:Win32/InstallCore", file: "setup_installer.exe" },
      { name: "PUA:Win32/Presenoker", file: "free_vpn_setup.exe" },
      { name: "PUA:Win32/CoinMiner", file: "video_converter.exe" },
    ];
    const pua = world.rng.choice(puas);
    const sha = world.rng.sha256();
    return {
      id: nextId(world, "edr"),
      ts: ts(world),
      source,
      vendor: edrVendor,
      event_type: "av_quarantine",
      severity: "low",
      hostname,
      user_email: user.email,
      user_title: user.title,
      file: {
        path: `C:\\Users\\${user.id}\\Downloads\\${pua.file}`,
        sha256: sha,
        size: world.rng.range(524288, 10485760),
        extension: "exe",
      },
      description: `PUA detected and quarantined on ${hostname}: ${pua.name} in Downloads folder`,
      raw: {
        "av.threat_name": pua.name,
        "av.threat_type": "PUA",
        "av.action": "quarantine",
        "av.file_path": `C:\\Users\\${user.id}\\Downloads\\${pua.file}`,
        "av.sha256": sha,
        "av.detection_source": "realtime",
        "host.name": hostname,
        "user.name": user.id,
        "action_result": "quarantined",
      },
    };
  }

  // Network protection block (gambling/policy) — 15%
  if (roll < 0.85) {
    const blockedSites = [
      { domain: "pokerstars.com", category: "Gambling" },
      { domain: "bet365.com", category: "Gambling" },
      { domain: "streamingfree.xyz", category: "Streaming/Unlicensed" },
    ];
    const site = world.rng.choice(blockedSites);
    return {
      id: nextId(world, "edr"),
      ts: ts(world),
      source,
      vendor: edrVendor,
      event_type: "net_blocked",
      severity: "low",
      hostname,
      user_email: user.email,
      user_title: user.title,
      network: { domain: site.domain },
      description: `Network protection blocked access to ${site.domain} (${site.category}) on ${hostname}`,
      raw: {
        "av.network_protection.action": "block",
        "av.network_protection.url": `https://${site.domain}`,
        "av.network_protection.category": site.category,
        "av.network_protection.reason": "policy_violation",
        "host.name": hostname,
        "user.name": user.id,
        "action_result": "blocked",
      },
    };
  }

  // Tamper protection — 15%
  return {
    id: nextId(world, "edr"),
    ts: ts(world),
    source,
    vendor: edrVendor,
    event_type: "edr_alert",
    severity: "low",
    hostname,
    user_email: user.email,
    user_title: user.title,
    description: `Tamper protection triggered on ${hostname} — attempt to disable AV service blocked`,
    raw: {
      "av.tamper_protection.action": "blocked",
      "av.tamper_protection.target_service": "WinDefend",
      "av.tamper_protection.caller_process": "cmd.exe",
      "av.tamper_protection.reason": "Attempted service stop via sc.exe",
      "host.name": hostname,
      "user.name": user.id,
      "action_result": "blocked",
    },
  };
}

// ─── Cloud generator (RocketStack / AWS) ─────────────────────────────────────

function genCloud(world: WorldState): GeneratedEvent {
  const user = pickActiveOrAnyUser(world);
  const session = getOrCreateSession(world, user);
  const roll = world.rng.next();
  const region = world.rng.choice(["us-east-1", "eu-west-1", "us-west-2"]);
  const accountId = "123456789012";

  // S3 GetObject — 25%
  if (roll < 0.25) {
    const buildNum = world.rng.range(1000, 9999);
    return {
      id: nextId(world, "cloud"),
      ts: ts(world),
      source: "cloudtrail",
      vendor: "AWS CloudTrail",
      event_type: "cloud_storage_access",
      severity: "informational",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      src_ip: session.ip,
      description: `S3 GetObject: rocketstack-assets-prod/build-${buildNum}/app.tar.gz by ${user.name}`,
      raw: {
        "aws.cloudtrail.eventName": "GetObject",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.user_identity.type": "IAMUser",
        "aws.cloudtrail.user_identity.arn": `arn:aws:iam::${accountId}:user/${user.id}`,
        "aws.cloudtrail.user_identity.account_id": accountId,
        "aws.cloudtrail.source_ip_address": session.ip,
        "aws.cloudtrail.user_agent": "aws-cli/2.15.0 Python/3.11.0",
        "aws.cloudtrail.aws_region": region,
        "aws.cloudtrail.error_code": "",
        "aws.cloudtrail.request_parameters": { "bucketName": "rocketstack-assets-prod", "key": `build-${buildNum}/app.tar.gz` },
        "aws.cloudtrail.request_id": world.rng.guid(),
        "cloud.account.id": accountId,
        "cloud.region": region,
        "action_result": "allowed",
      },
    };
  }

  // EC2 DescribeInstances — 20%
  if (roll < 0.45) {
    return {
      id: nextId(world, "cloud"),
      ts: ts(world),
      source: "cloudtrail",
      vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      severity: "informational",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      src_ip: session.ip,
      description: `EC2 DescribeInstances called by ${user.name} (CI pipeline/SDK)`,
      raw: {
        "aws.cloudtrail.eventName": "DescribeInstances",
        "aws.cloudtrail.eventSource": "ec2.amazonaws.com",
        "aws.cloudtrail.user_identity.type": user.id === "ci.deploy" ? "AssumedRole" : "IAMUser",
        "aws.cloudtrail.user_identity.arn": `arn:aws:iam::${accountId}:user/${user.id}`,
        "aws.cloudtrail.source_ip_address": session.ip,
        "aws.cloudtrail.user_agent": "aws-sdk-python/1.34.0 Python/3.11.0 Boto3/1.34.0",
        "aws.cloudtrail.aws_region": region,
        "aws.cloudtrail.error_code": "",
        "aws.cloudtrail.request_id": world.rng.guid(),
        "cloud.account.id": accountId,
        "cloud.region": region,
        "action_result": "allowed",
      },
    };
  }

  // K8s pod create — 20%
  if (roll < 0.65) {
    const namespace = world.rng.choice(["production", "staging", "default"]);
    const podName = `api-${world.rng.hex(8)}`;
    return {
      id: nextId(world, "cloud"),
      ts: ts(world),
      source: "k8s_audit",
      vendor: "Kubernetes",
      event_type: "k8s_pod_create",
      severity: "informational",
      hostname: "SRV-RS-BUILD-01",
      user_email: user.email,
      user_title: user.title,
      description: `Kubernetes pod ${podName} created in namespace ${namespace}`,
      raw: {
        "kubernetes.audit.verb": "create",
        "kubernetes.audit.objectRef.resource": "pods",
        "kubernetes.audit.objectRef.namespace": namespace,
        "kubernetes.audit.objectRef.name": podName,
        "kubernetes.audit.user.username": user.id,
        "kubernetes.audit.sourceIPs": [session.ip],
        "kubernetes.audit.responseStatus.code": "201",
        "kubernetes.audit.requestURI": `/api/v1/namespaces/${namespace}/pods`,
        "cloud.region": region,
        "action_result": "allowed",
      },
    };
  }

  // Vault secret read — 15%
  if (roll < 0.80) {
    const secrets = ["secret/data/prod/db-password", "secret/data/prod/api-key", "secret/data/staging/jwt-secret"];
    const secretPath = world.rng.choice(secrets);
    return {
      id: nextId(world, "cloud"),
      ts: ts(world),
      source: "cloudtrail",
      vendor: "HashiCorp Vault",
      event_type: "cloud_api_call",
      severity: "informational",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      src_ip: session.ip,
      description: `Vault secret read: ${secretPath} by ${user.name}`,
      raw: {
        "vault.path": secretPath,
        "vault.operation": "read",
        "vault.auth.accessor": world.rng.hex(12),
        "vault.auth.display_name": user.id,
        "vault.remote_address": session.ip,
        "vault.response.code": "200",
        "action_result": "allowed",
      },
    };
  }

  // Terraform apply — 20%
  const tfPid = world.rng.pid();
  spawnProcess(world, user.hostname, {
    name: "terraform",
    path: "/usr/local/bin/terraform",
    cmdLine: "terraform apply -auto-approve -var-file=prod.tfvars",
    parentName: "bash",
    parentPath: "/bin/bash",
    userId: user.id,
    logonId: session.logonId,
    integrity: "medium",
    signed: true,
  });

  return {
    id: nextId(world, "cloud"),
    ts: ts(world),
    source: "edr",
    vendor: "CrowdStrike Falcon",
    event_type: "process_create",
    severity: "informational",
    hostname: user.hostname,
    user_email: user.email,
    user_title: user.title,
    process: {
      name: "terraform",
      pid: tfPid,
      path: "/usr/local/bin/terraform",
      parent_name: "bash",
      cmdline: "terraform apply -auto-approve -var-file=prod.tfvars",
      user: user.id,
    },
    description: `${user.name} ran terraform apply on ${user.hostname} (prod infrastructure)`,
    raw: {
      "crowdstrike.event_simplename": "ProcessRollup2",
      "cs.ContextProcessName": "terraform",
      "cs.CommandLine": "terraform apply -auto-approve -var-file=prod.tfvars",
      "cs.ParentProcessName": "bash",
      "cs.TargetProcessId_decimal": String(tfPid),
      "cs.UserName": user.id,
      "cs.ComputerName": user.hostname,
      "cs.FilePath": "/usr/local/bin/terraform",
      "action_result": "allowed",
    },
  };
}

// ─── EMR generator (MedCore) ─────────────────────────────────────────────────

function genEMR(world: WorldState): GeneratedEvent {
  const user = pickActiveOrAnyUser(world);
  const session = getOrCreateSession(world, user);
  const roll = world.rng.next();
  const emrServer = world.meta.servers.find((s) => s.role === "emr");
  const pacsServer = world.meta.servers.find((s) => s.role === "pacs");
  const emrIp = emrServer?.ip ?? "172.16.20.10";
  const pacsIp = pacsServer?.ip ?? "172.16.30.10";

  // Epic EMR login — 20%
  if (roll < 0.20) {
    const node = spawnProcess(world, user.hostname, {
      name: "EpicCare.exe",
      path: "C:\\Program Files\\Epic\\EpicCare\\EpicCare.exe",
      cmdLine: `EpicCare.exe /server=${emrIp} /user=${user.id}`,
      parentName: "explorer.exe",
      parentPath: "C:\\Windows\\explorer.exe",
      parentPid: 2400,
      userId: user.id,
      logonId: session.logonId,
      integrity: "medium",
      signed: true,
    });

    return {
      id: nextId(world, "emr"),
      ts: ts(world),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "process_create",
      severity: "informational",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      process: {
        name: node.name,
        pid: node.pid,
        path: node.path,
        parent_name: "explorer.exe",
        parent_pid: 2400,
        cmdline: node.cmdLine,
        user: `MEDCORE\\${user.id}`,
        integrity: "medium",
      },
      description: `${user.name} launched Epic EMR (EpicCare.exe) connecting to ${emrServer?.hostname ?? "EMR server"}`,
      raw: {
        "event.code": "1",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.event_data.Image": node.path,
        "winlog.event_data.CommandLine": node.cmdLine,
        "winlog.event_data.ParentImage": "C:\\Windows\\explorer.exe",
        "winlog.event_data.ParentProcessId": "2400",
        "winlog.event_data.ProcessId": String(node.pid),
        "winlog.event_data.User": `MEDCORE\\${user.id}`,
        "winlog.event_data.IntegrityLevel": "Medium",
        "winlog.computer_name": user.hostname,
        "action_result": "allowed",
      },
    };
  }

  // Patient record query — 20%
  if (roll < 0.40) {
    const patientId = `P-${world.rng.range(10000, 99999)}`;
    return {
      id: nextId(world, "emr"),
      ts: ts(world),
      source: "db_monitor",
      vendor: "IBM Guardium",
      event_type: "db_query",
      severity: "informational",
      hostname: emrServer?.hostname ?? "SRV-MEDCORE-EMR01",
      user_email: user.email,
      user_title: user.title,
      user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
      src_ip: session.ip,
      dst_ip: emrIp,
      dst_port: 1433,
      description: `${user.name} queried patient record ${patientId} in EMR database`,
      raw: {
        "db.statement": `SELECT * FROM PatientRecords WHERE patient_id='${patientId}'`,
        "db.instance": emrServer?.hostname ?? "SRV-MEDCORE-EMR01",
        "db.user": user.id,
        "db.rows_returned": String(world.rng.range(1, 5)),
        "db.duration_ms": String(world.rng.range(10, 250)),
        "db.application_name": "EpicCare",
        "client.ip": session.ip,
        "action_result": "allowed",
      },
    };
  }

  // PACS imaging query — 15%
  if (roll < 0.55) {
    const studyId = `STU-${world.rng.range(10000, 99999)}`;
    return {
      id: nextId(world, "emr"),
      ts: ts(world),
      source: "proxy",
      vendor: "Squid Proxy",
      event_type: "http_request",
      severity: "informational",
      hostname: user.hostname,
      user_email: user.email,
      user_title: user.title,
      src_ip: session.ip,
      dst_ip: pacsIp,
      dst_port: 80,
      network: {
        url: `http://${pacsIp}/api/imaging?study_id=${studyId}`,
        domain: pacsServer?.hostname ?? "SRV-PACS-01",
        method: "GET",
        status: 200,
        bytes_in: world.rng.range(204800, 10485760),
      },
      description: `${user.name} retrieved imaging study ${studyId} from PACS`,
      raw: {
        "http.request.method": "GET",
        "url.full": `http://${pacsIp}/api/imaging?study_id=${studyId}`,
        "http.response.status_code": "200",
        "source.ip": session.ip,
        "destination.ip": pacsIp,
        "destination.port": "80",
        "proxy.user": user.id,
        "action_result": "allowed",
      },
    };
  }

  // DICOM transfer — 15%
  if (roll < 0.70) {
    const radUser = world.meta.users.find((u) => u.department === "Radiology") ?? user;
    const srcPort = world.rng.srcPort();
    return {
      id: nextId(world, "emr"),
      ts: ts(world),
      source: "firewall",
      vendor: "Check Point NGFW",
      event_type: "net_connection",
      severity: "informational",
      hostname: radUser.hostname,
      user_email: radUser.email,
      user_title: radUser.title,
      src_ip: session.ip,
      dst_ip: pacsIp,
      dst_port: 104,
      protocol: "tcp",
      description: `DICOM transfer from ${radUser.hostname} to SRV-PACS-01 (port 104)`,
      raw: {
        "data.src": session.ip,
        "data.sport_svc": String(srcPort),
        "data.dst": pacsIp,
        "data.svc": "104",
        "data.service": "DICOM",
        "data.proto": "6",
        "data.protocol": "TCP",
        "data.action": "Accept",
        "data.rule_name": "PACS-DICOM-Allow",
        "data.ProductName": "VPN-1 & FireWall-1",
        "data.inzone": "Internal",
        "data.outzone": "DMZ",
        "cp.app_name": "DICOM",
        "cp.bytes": String(world.rng.range(1048576, 104857600)),
        "firewall.action": "allow",
        "action_result": "allowed",
      },
    };
  }

  // Drug interaction lookup — 15%
  if (roll < 0.85) {
    return {
      id: nextId(world, "emr"),
      ts: ts(world),
      source: "db_monitor",
      vendor: "IBM Guardium",
      event_type: "db_query",
      severity: "informational",
      hostname: emrServer?.hostname ?? "SRV-MEDCORE-EMR01",
      user_email: user.email,
      user_title: user.title,
      dst_ip: emrIp,
      dst_port: 1433,
      description: `${user.name} queried drug interactions database`,
      raw: {
        "db.statement": "SELECT * FROM drug_interactions WHERE drug_id IN ('MET-500','ASP-100')",
        "db.instance": "PharmacyDB",
        "db.user": user.id,
        "db.rows_returned": String(world.rng.range(2, 15)),
        "db.duration_ms": String(world.rng.range(5, 80)),
        "db.application_name": "PharmacyManager",
        "client.ip": session.ip,
        "action_result": "allowed",
      },
    };
  }

  // HL7 FHIR API call — 15%
  const patientId2 = `P-${world.rng.range(10000, 99999)}`;
  return {
    id: nextId(world, "emr"),
    ts: ts(world),
    source: "proxy",
    vendor: "Squid Proxy",
    event_type: "http_request",
    severity: "informational",
    hostname: user.hostname,
    user_email: user.email,
    user_title: user.title,
    src_ip: session.ip,
    network: {
      url: `https://fhir.medcorehealth.org/Patient/${patientId2}/$everything`,
      domain: "fhir.medcorehealth.org",
      method: "GET",
      status: 200,
      bytes_in: world.rng.range(51200, 512000),
    },
    description: `${user.name} made HL7 FHIR API call for patient ${patientId2}`,
    raw: {
      "http.request.method": "GET",
      "url.full": `https://fhir.medcorehealth.org/Patient/${patientId2}/$everything`,
      "http.response.status_code": "200",
      "source.ip": session.ip,
      "destination.port": "443",
      "http.request.headers.Authorization": "Bearer [redacted]",
      "proxy.user": user.id,
      "action_result": "allowed",
    },
  };
}

// ─── DLP generator ────────────────────────────────────────────────────────────

function genDLP(world: WorldState): GeneratedEvent {
  const user = pickActiveOrAnyUser(world);
  const session = getOrCreateSession(world, user);

  const policyName = world.meta.id === "medcore"
    ? "HIPAA-PHI-Protection"
    : "Financial-Data-DLP";

  const infoTypes = world.meta.id === "medcore"
    ? ["U.S. Individual Taxpayer Identification Number (ITIN)", "U.S. Social Security Number (SSN)", "Drug Enforcement Agency (DEA) Number"]
    : ["Credit Card Number", "U.S. Bank Account Number", "ABA Routing Number", "SWIFT Code"];

  const infoType = world.rng.choice(infoTypes);
  const count = world.rng.range(1, 5);
  const confidence = world.rng.range(65, 95);
  const subjects = ["Q4 Financial Projections", "Patient Summary Report", "Budget Draft", "Vendor Invoice", "Internal Audit Results"];
  const subject = world.rng.choice(subjects);

  return {
    id: nextId(world, "dlp"),
    ts: ts(world),
    source: "dlp",
    vendor: "Microsoft Purview",
    event_type: "dlp_alert",
    severity: "informational",
    hostname: user.hostname,
    user_email: user.email,
    user_title: user.title,
    user: { full_name: user.name, email: user.email, department: user.department, title: user.title },
    src_ip: session.ip,
    description: `DLP policy tip: "${policyName}" matched in email "${subject}" — action: PolicyTip (not blocked)`,
    raw: {
      "data.office365.Operation": "DlpRuleMatch",
      "data.office365.Workload": "Exchange",
      "data.office365.UserId": user.email,
      "data.office365.ClientIP": session.ip,
      "data.office365.ResultStatus": "Succeeded",
      "data.office365.IncidentId": String(world.rng.range(1_000_000, 9_999_999)),
      "data.office365.PolicyDetails[0].PolicyName": policyName,
      "data.office365.PolicyDetails[0].Rules[0].SensitiveInformationTypeName": infoType,
      "data.office365.PolicyDetails[0].Rules[0].Count": String(count),
      "data.office365.PolicyDetails[0].Rules[0].Confidence": String(confidence),
      "data.office365.PolicyDetails[0].Rules[0].DetectedValues": "****-****-****-XXXX",
      "data.office365.PolicyDetails[0].Rules[0].Actions[0]": "PolicyTip",
      "data.office365.ExchangeMetaData.From": user.email,
      "data.office365.ExchangeMetaData.To": [`compliance@${world.meta.domain}`],
      "data.office365.ExchangeMetaData.Subject": subject,
      "dlp.action": "PolicyTip",
      "dlp.blocked": "false",
      "action_result": "allowed",
    },
  };
}

// ─── Main export ──────────────────────────────────────────────────────────────

export function generateBenignEvent(world: WorldState): GeneratedEvent {
  const weights = world.meta.weights;

  // Build the category list and weight list
  const categories = Object.keys(weights) as Array<keyof typeof weights>;
  const weightValues = categories.map((c) => weights[c] ?? 0);

  let category = world.rng.pick(categories, weightValues);

  // Fallbacks: cloud/k8s only for rocketstack
  if ((category === "cloud" || category === "k8s") && world.meta.cloud !== "aws") {
    category = "network";
  }
  // emr only for medcore
  if (category === "emr" && world.meta.id !== "medcore") {
    category = "process";
  }
  // dlp: medcore and nexacorp are fine; rocketstack has low weight so it's rare
  // office365 on rocketstack → treat as email (gsuite)
  if (category === "office365" && world.meta.emailStack === "gsuite") {
    category = "email";
  }
  // ad on rocketstack (no on-prem AD) → fall back to auth
  if (category === "ad" && world.meta.adDomain === "") {
    category = "auth";
  }

  switch (category) {
    case "auth":     return genAuth(world);
    case "process":  return genProcess(world);
    case "network":  return genNetwork(world);
    case "office365":return genOffice365(world);
    case "email":    return genEmail(world);
    case "ad":       return genAD(world);
    case "vpn":      return genVPN(world);
    case "edr":      return genEDR(world);
    case "cloud":
    case "k8s":      return genCloud(world);
    case "emr":      return genEMR(world);
    case "dlp":      return genDLP(world);
    default:         return genAuth(world);
  }
}
