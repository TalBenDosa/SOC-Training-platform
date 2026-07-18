/**
 * worldState.ts
 * Company metadata registry and WorldState factory for the algorithmic log engine.
 */

import {
  SeededRNG,
  CompanyMeta,
  CompanyUser,
  WorldState,
  UserSession,
  ProcessNode,
} from "@/lib/sim/engine/types";

// ─── Company metadata ─────────────────────────────────────────────────────────

export const COMPANY_META: Record<string, CompanyMeta> = {
  nexacorp: {
    id: "nexacorp",
    name: "NexaCorp Financial",
    domain: "nexacorp.com",
    adDomain: "NEXACORP",
    ipSubnets: {
      workstations: "10.10.0.",
      servers: "10.10.1.",
      dmz: "10.10.5.",
      attackerPool: ["91.108.4.", "185.220.1.", "203.0.113."],
    },
    users: [
      {
        id: "j.chen",
        email: "j.chen@nexacorp.com",
        name: "Jennifer Chen",
        department: "Finance",
        hostname: "WS-NYC-04",
        title: "Senior Analyst",
        isAdmin: false,
        osType: "windows",
      },
      {
        id: "a.miller",
        email: "a.miller@nexacorp.com",
        name: "Alex Miller",
        department: "IT",
        hostname: "WS-IT-01",
        title: "IT Administrator",
        isAdmin: true,
        osType: "windows",
      },
      {
        id: "k.taylor",
        email: "k.taylor@nexacorp.com",
        name: "Kate Taylor",
        department: "Trading",
        hostname: "WS-TRADE-07",
        title: "Trader",
        isAdmin: false,
        osType: "windows",
      },
      {
        id: "l.nguyen",
        email: "l.nguyen@nexacorp.com",
        name: "Linh Nguyen",
        department: "Finance",
        hostname: "WS-FIN-03",
        title: "Accountant",
        isAdmin: false,
        osType: "windows",
      },
      {
        id: "m.johnson",
        email: "m.johnson@nexacorp.com",
        name: "Marcus Johnson",
        department: "IT",
        hostname: "WS-IT-02",
        title: "IT Engineer",
        isAdmin: true,
        osType: "windows",
      },
      {
        id: "r.patel",
        email: "r.patel@nexacorp.com",
        name: "Raj Patel",
        department: "Risk",
        hostname: "WS-RISK-02",
        title: "Risk Manager",
        isAdmin: false,
        osType: "windows",
      },
      {
        id: "s.wright",
        email: "s.wright@nexacorp.com",
        name: "Sarah Wright",
        department: "Compliance",
        hostname: "WS-COMP-01",
        title: "Compliance Officer",
        isAdmin: false,
        osType: "windows",
      },
      {
        id: "svc.backup",
        email: "svc-backup@nexacorp.com",
        name: "Backup Service",
        department: "IT",
        hostname: "SRV-BACKUP-01",
        title: "Service Account",
        isAdmin: true,
        osType: "windows",
      },
    ],
    servers: [
      {
        hostname: "DC-CORP-01",
        ip: "10.10.1.10",
        role: "domain_controller",
        os: "Windows Server 2022",
      },
      {
        hostname: "FS-CORP-01",
        ip: "10.10.1.20",
        role: "file_server",
        os: "Windows Server 2022",
      },
      {
        hostname: "SRV-EXCH-01",
        ip: "10.10.1.30",
        role: "exchange",
        os: "Windows Server 2022",
      },
    ],
    edr: "MDE",
    idp: "azuread",
    firewall: "paloalto",
    cloud: "azure",
    emailStack: "m365",
    weights: {
      auth: 0.22,
      process: 0.12,
      office365: 0.20,
      network: 0.14,
      email: 0.10,
      ad: 0.08,
      vpn: 0.08,
      edr: 0.06,
    },
  },

  medcore: {
    id: "medcore",
    name: "MedCore Health",
    domain: "medcorehealth.org",
    adDomain: "MEDCORE",
    ipSubnets: {
      workstations: "172.16.10.",
      servers: "172.16.20.",
      dmz: "172.16.30.",
      attackerPool: ["91.108.4.", "185.220.1.", "45.142.12."],
    },
    users: [
      {
        id: "dr.vandijk",
        email: "dr.vandijk@medcorehealth.org",
        name: "Dr. Elena van Dijk",
        department: "Cardiology",
        hostname: "WS-MED-022",
        title: "Senior Physician",
        isAdmin: false,
        osType: "windows",
      },
      {
        id: "n.okafor",
        email: "n.okafor@medcorehealth.org",
        name: "Nurse Ngozi Okafor",
        department: "ICU",
        hostname: "WS-MED-015",
        title: "ICU Nurse",
        isAdmin: false,
        osType: "windows",
      },
      {
        id: "it.admin",
        email: "it-admin@medcorehealth.org",
        name: "IT Admin",
        department: "IT",
        hostname: "WS-IT-MC-01",
        title: "IT Administrator",
        isAdmin: true,
        osType: "windows",
      },
      {
        id: "radiology.svc",
        email: "radiology.svc@medcorehealth.org",
        name: "Radiology Service",
        department: "Radiology",
        hostname: "WS-RAD-03",
        title: "Service Account",
        isAdmin: false,
        osType: "windows",
      },
      {
        id: "p.santos",
        email: "p.santos@medcorehealth.org",
        name: "Pedro Santos",
        department: "Pharmacy",
        hostname: "WS-MED-031",
        title: "Pharmacist",
        isAdmin: false,
        osType: "windows",
      },
      {
        id: "dr.chen",
        email: "dr.chen@medcorehealth.org",
        name: "Dr. Wei Chen",
        department: "Radiology",
        hostname: "WS-RAD-01",
        title: "Radiologist",
        isAdmin: false,
        osType: "windows",
      },
      {
        id: "helpdesk",
        email: "helpdesk@medcorehealth.org",
        name: "IT Helpdesk",
        department: "IT",
        hostname: "WS-HELP-01",
        title: "Helpdesk Technician",
        isAdmin: true,
        osType: "windows",
      },
    ],
    servers: [
      {
        hostname: "SRV-MEDCORE-EMR01",
        ip: "172.16.20.10",
        role: "emr",
        os: "Windows Server 2019",
      },
      {
        hostname: "SRV-PACS-01",
        ip: "172.16.30.10",
        role: "pacs",
        os: "Windows Server 2019",
      },
      {
        hostname: "DC-MED-01",
        ip: "172.16.20.5",
        role: "domain_controller",
        os: "Windows Server 2022",
      },
    ],
    edr: "MDE",
    idp: "azuread",
    firewall: "checkpoint",
    cloud: "azure",
    emailStack: "m365",
    weights: {
      auth: 0.28,
      process: 0.08,
      office365: 0.10,
      network: 0.08,
      email: 0.06,
      ad: 0.06,
      vpn: 0.02,
      edr: 0.06,
      emr: 0.14,
      dlp: 0.08,
      cloud: 0.04,
    },
  },

  rocketstack: {
    id: "rocketstack",
    name: "RocketStack",
    domain: "rocketstack.io",
    adDomain: "",
    ipSubnets: {
      workstations: "10.0.10.",
      servers: "10.0.20.",
      dmz: "10.0.30.",
      attackerPool: ["185.220.1.", "91.108.4.", "45.142.12."],
    },
    users: [
      {
        id: "t.levy",
        email: "t.levy@rocketstack.io",
        name: "Tomer Levy",
        department: "Backend",
        hostname: "LAPTOP-RS-07",
        title: "Backend Engineer",
        isAdmin: false,
        osType: "macos",
      },
      {
        id: "r.cohen",
        email: "r.cohen@rocketstack.io",
        name: "Rotem Cohen",
        department: "Platform",
        hostname: "LAPTOP-RS-12",
        title: "Platform Engineer",
        isAdmin: false,
        osType: "macos",
      },
      {
        id: "s.amir",
        email: "s.amir@rocketstack.io",
        name: "Shai Amir",
        department: "DevOps",
        hostname: "LAPTOP-RS-03",
        title: "DevOps Lead",
        isAdmin: true,
        osType: "macos",
      },
      {
        id: "n.shapiro",
        email: "n.shapiro@rocketstack.io",
        name: "Noa Shapiro",
        department: "Security",
        hostname: "LAPTOP-RS-09",
        title: "Security Engineer",
        isAdmin: true,
        osType: "macos",
      },
      {
        id: "a.kim",
        email: "a.kim@rocketstack.io",
        name: "Alice Kim",
        department: "Frontend",
        hostname: "LAPTOP-RS-15",
        title: "Frontend Developer",
        isAdmin: false,
        osType: "macos",
      },
      {
        id: "ci.deploy",
        email: "ci-deploy@rocketstack.io",
        name: "CI Deploy Bot",
        department: "DevOps",
        hostname: "SRV-RS-BUILD-01",
        title: "Service Account",
        isAdmin: true,
        osType: "linux",
      },
      {
        id: "l.friedman",
        email: "l.friedman@rocketstack.io",
        name: "Lior Friedman",
        department: "Backend",
        hostname: "LAPTOP-RS-11",
        title: "Backend Engineer",
        isAdmin: false,
        osType: "macos",
      },
    ],
    servers: [
      {
        hostname: "SRV-RS-BUILD-01",
        ip: "10.0.20.10",
        role: "ci_runner",
        os: "Ubuntu 22.04",
      },
      {
        hostname: "SRV-RS-PROD-01",
        ip: "10.0.20.20",
        role: "production",
        os: "Ubuntu 22.04",
      },
      {
        hostname: "SRV-RS-DB-01",
        ip: "10.0.20.30",
        role: "database",
        os: "Ubuntu 22.04",
      },
    ],
    edr: "crowdstrike",
    idp: "okta",
    firewall: "fortigate",
    cloud: "aws",
    emailStack: "gsuite",
    weights: {
      auth: 0.12,
      process: 0.10,
      office365: 0.04,
      network: 0.10,
      email: 0.04,
      ad: 0.02,
      vpn: 0.04,
      edr: 0.08,
      cloud: 0.20,
      k8s: 0.20,
      emr: 0,
      dlp: 0.06,
    },
  },
};

// ─── WorldState factory ───────────────────────────────────────────────────────

/**
 * Startup process trees per OS, seeded into forest on init.
 */
const STARTUP_PROCESSES: Record<string, Array<{ name: string; path: string; pid: number; parentPid: number; parentName: string; parentPath: string }>> = {
  windows: [
    { name: "System", path: "", pid: 4, parentPid: 0, parentName: "", parentPath: "" },
    { name: "smss.exe", path: "C:\\Windows\\System32\\smss.exe", pid: 300, parentPid: 4, parentName: "System", parentPath: "" },
    { name: "wininit.exe", path: "C:\\Windows\\System32\\wininit.exe", pid: 500, parentPid: 4, parentName: "System", parentPath: "" },
    { name: "services.exe", path: "C:\\Windows\\System32\\services.exe", pid: 600, parentPid: 500, parentName: "wininit.exe", parentPath: "C:\\Windows\\System32\\wininit.exe" },
    { name: "lsass.exe", path: "C:\\Windows\\System32\\lsass.exe", pid: 700, parentPid: 500, parentName: "wininit.exe", parentPath: "C:\\Windows\\System32\\wininit.exe" },
    { name: "svchost.exe", path: "C:\\Windows\\System32\\svchost.exe", pid: 900, parentPid: 600, parentName: "services.exe", parentPath: "C:\\Windows\\System32\\services.exe" },
    { name: "svchost.exe", path: "C:\\Windows\\System32\\svchost.exe", pid: 1020, parentPid: 600, parentName: "services.exe", parentPath: "C:\\Windows\\System32\\services.exe" },
    { name: "explorer.exe", path: "C:\\Windows\\explorer.exe", pid: 2400, parentPid: 4, parentName: "System", parentPath: "" },
  ],
  macos: [
    { name: "launchd", path: "/sbin/launchd", pid: 1, parentPid: 0, parentName: "", parentPath: "" },
    { name: "Finder", path: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", pid: 450, parentPid: 1, parentName: "launchd", parentPath: "/sbin/launchd" },
    { name: "loginwindow", path: "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow", pid: 200, parentPid: 1, parentName: "launchd", parentPath: "/sbin/launchd" },
    { name: "cfprefsd", path: "/usr/sbin/cfprefsd", pid: 380, parentPid: 1, parentName: "launchd", parentPath: "/sbin/launchd" },
    { name: "distnoted", path: "/usr/sbin/distnoted", pid: 420, parentPid: 1, parentName: "launchd", parentPath: "/sbin/launchd" },
  ],
  linux: [
    { name: "systemd", path: "/sbin/init", pid: 1, parentPid: 0, parentName: "", parentPath: "" },
    { name: "journald", path: "/lib/systemd/systemd-journald", pid: 200, parentPid: 1, parentName: "systemd", parentPath: "/sbin/init" },
    { name: "sshd", path: "/usr/sbin/sshd", pid: 800, parentPid: 1, parentName: "systemd", parentPath: "/sbin/init" },
    { name: "cron", path: "/usr/sbin/cron", pid: 900, parentPid: 1, parentName: "systemd", parentPath: "/sbin/init" },
  ],
};

export function initWorldState(companyId: string, seed: number): WorldState {
  const meta = COMPANY_META[companyId] ?? COMPANY_META["nexacorp"];
  const rng = new SeededRNG(seed);

  const sessions = new Map<string, UserSession>();
  const forest = new Map<string, ProcessNode[]>();

  // Seed 2-3 initial sessions (day has started)
  const sessionCount = rng.range(2, 3);
  const shuffledUsers = [...meta.users].filter(u => !u.id.startsWith("svc.") && !u.id.startsWith("ci."));
  for (let i = 0; i < Math.min(sessionCount, shuffledUsers.length); i++) {
    const user = shuffledUsers[i];
    const ip = rng.ip(meta.ipSubnets.workstations);
    const logonId = rng.logonId();
    sessions.set(user.id, {
      user,
      ip,
      logonId,
      logonTime: Date.now() - rng.range(600_000, 7_200_000),
      lastActivity: Date.now() - rng.range(0, 600_000),
    });
  }

  // Seed process forest per host
  for (const user of meta.users) {
    const osType = user.osType;
    const protoProcs = STARTUP_PROCESSES[osType] ?? STARTUP_PROCESSES["windows"];
    const nodes: ProcessNode[] = protoProcs.map((p) => ({
      pid: p.pid,
      name: p.name,
      path: p.path,
      cmdLine: p.path,
      parentPid: p.parentPid,
      parentName: p.parentName,
      parentPath: p.parentPath,
      startTime: Date.now() - rng.range(3_600_000, 14_400_000),
      hostname: user.hostname,
      userId: "SYSTEM",
      logonId: "0x000003e7",
      integrity: "system",
      sha256: rng.sha256(),
      signed: true,
    }));
    forest.set(user.hostname, nodes);
  }
  for (const server of meta.servers) {
    const osProcs = server.os.toLowerCase().includes("ubuntu")
      ? STARTUP_PROCESSES["linux"]
      : STARTUP_PROCESSES["windows"];
    const nodes: ProcessNode[] = osProcs.map((p) => ({
      pid: p.pid,
      name: p.name,
      path: p.path,
      cmdLine: p.path,
      parentPid: p.parentPid,
      parentName: p.parentName,
      parentPath: p.parentPath,
      startTime: Date.now() - rng.range(86_400_000, 604_800_000),
      hostname: server.hostname,
      userId: "SYSTEM",
      logonId: "0x000003e7",
      integrity: "system",
      sha256: rng.sha256(),
      signed: true,
    }));
    forest.set(server.hostname, nodes);
  }

  return {
    meta,
    sessions,
    forest,
    dns: new Map(),
    conns: [],
    attack: null,
    simTime: Date.now(),
    count: 0,
    rng,
  };
}

// ─── Helper functions ─────────────────────────────────────────────────────────

export function getOrCreateSession(world: WorldState, user: CompanyUser): UserSession {
  const existing = world.sessions.get(user.id);
  if (existing) {
    existing.lastActivity = world.simTime;
    return existing;
  }
  const ip = world.rng.ip(world.meta.ipSubnets.workstations);
  const session: UserSession = {
    user,
    ip,
    logonId: world.rng.logonId(),
    logonTime: world.simTime,
    lastActivity: world.simTime,
  };
  world.sessions.set(user.id, session);
  return session;
}

export function spawnProcess(
  world: WorldState,
  hostname: string,
  opts: {
    name: string;
    path: string;
    cmdLine: string;
    parentPid?: number;
    parentName?: string;
    parentPath?: string;
    userId: string;
    logonId: string;
    integrity?: ProcessNode["integrity"];
    signed?: boolean;
  }
): ProcessNode {
  const pid = world.rng.pid();

  // Find parent in forest if parentPid not specified
  let parentPid = opts.parentPid ?? 2400; // default to explorer.exe pid
  let parentName = opts.parentName ?? "explorer.exe";
  let parentPath = opts.parentPath ?? "C:\\Windows\\explorer.exe";

  const hostProcs = world.forest.get(hostname) ?? [];

  // If parentName provided but no parentPid, try to look it up
  if (opts.parentName && !opts.parentPid) {
    const parentNode = hostProcs.find((p) => p.name === opts.parentName);
    if (parentNode) {
      parentPid = parentNode.pid;
      parentPath = parentNode.path;
    }
  }

  const node: ProcessNode = {
    pid,
    name: opts.name,
    path: opts.path,
    cmdLine: opts.cmdLine,
    parentPid,
    parentName,
    parentPath,
    startTime: world.simTime,
    hostname,
    userId: opts.userId,
    logonId: opts.logonId,
    integrity: opts.integrity ?? "medium",
    sha256: world.rng.sha256(),
    signed: opts.signed ?? true,
  };

  hostProcs.push(node);
  world.forest.set(hostname, hostProcs);
  return node;
}

export function getProcessByName(
  world: WorldState,
  hostname: string,
  name: string
): ProcessNode | undefined {
  const procs = world.forest.get(hostname) ?? [];
  return procs.find((p) => p.name === name);
}

export function pickUser(
  world: WorldState,
  filter?: (u: CompanyUser) => boolean
): CompanyUser {
  const candidates = filter
    ? world.meta.users.filter(filter)
    : world.meta.users;
  if (candidates.length === 0) return world.meta.users[0];
  return world.rng.choice(candidates);
}

export function externalAttackerIp(world: WorldState): string {
  const subnet = world.rng.choice(world.meta.ipSubnets.attackerPool);
  return world.rng.ip(subnet);
}
