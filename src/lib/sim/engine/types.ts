/**
 * Core types for the algorithmic log generation engine.
 * All generators and attack playbooks import from here.
 */

import type { EventType, LogSource } from "@/lib/sim/types";

// ─── Seeded RNG (Mulberry32) ──────────────────────────────────────────────────

export class SeededRNG {
  private s: number;
  constructor(seed: number) { this.s = seed >>> 0; }

  next(): number {
    this.s = (this.s + 0x6D2B79F5) >>> 0;
    let t = Math.imul(this.s ^ (this.s >>> 15), 1 | this.s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  range(lo: number, hi: number): number {
    return lo + Math.floor(this.next() * (hi - lo + 1));
  }

  choice<T>(arr: T[]): T {
    return arr[Math.floor(this.next() * arr.length)];
  }

  pick<T>(arr: T[], weights: number[]): T {
    let r = this.next() * weights.reduce((a, b) => a + b, 0);
    for (let i = 0; i < arr.length; i++) {
      r -= weights[i];
      if (r <= 0) return arr[i];
    }
    return arr[arr.length - 1];
  }

  hex(n: number): string {
    let r = "";
    for (let i = 0; i < n; i++) r += "0123456789abcdef"[Math.floor(this.next() * 16)];
    return r;
  }

  logonId(): string { return "0x" + this.hex(8); }
  pid(): number { return this.range(1024, 65000); }
  srcPort(): number { return this.range(49152, 65535); }
  sha256(): string { return this.hex(64); }
  md5(): string { return this.hex(32); }
  guid(): string {
    return [this.hex(8), this.hex(4), "4" + this.hex(3), this.hex(4), this.hex(12)].join("-");
  }
  ip(subnet: string): string { return `${subnet}${this.range(2, 254)}`; }
}

// ─── Company metadata ─────────────────────────────────────────────────────────

export interface CompanyUser {
  id: string;           // "j.chen"
  email: string;        // "j.chen@nexacorp.com"
  name: string;         // "Jennifer Chen"
  department: string;   // "Finance"
  hostname: string;     // "WS-NYC-04"
  title: string;        // "Senior Analyst"
  isAdmin: boolean;
  osType: "windows" | "linux" | "macos";
}

export interface CompanyServer {
  hostname: string;     // "DC-CORP-01"
  ip: string;           // "10.10.1.10"
  role: string;         // "domain_controller"
  os: string;           // "Windows Server 2022"
}

export interface BehaviorWeights {
  auth: number;
  process: number;
  office365: number;
  network: number;
  email: number;
  ad: number;
  vpn: number;
  edr: number;
  cloud?: number;
  k8s?: number;
  emr?: number;
  dlp?: number;
}

export interface CompanyMeta {
  id: string;
  name: string;
  domain: string;
  adDomain: string;
  ipSubnets: {
    workstations: string;   // "10.10.0."
    servers: string;        // "10.10.1."
    dmz: string;            // "10.10.5."
    attackerPool: string[]; // known suspicious subnets for FP/attack
  };
  users: CompanyUser[];
  servers: CompanyServer[];
  weights: BehaviorWeights;
  edr: string;
  idp: "azuread" | "okta";
  firewall: "paloalto" | "fortigate" | "checkpoint";
  cloud: "azure" | "aws" | "gcp";
  emailStack: "m365" | "gsuite";
}

// ─── Live world state ─────────────────────────────────────────────────────────

export interface UserSession {
  user: CompanyUser;
  ip: string;
  logonId: string;
  logonTime: number;
  lastActivity: number;
}

export interface ProcessNode {
  pid: number;
  name: string;
  path: string;
  cmdLine: string;
  parentPid: number;
  parentName: string;
  parentPath: string;
  startTime: number;
  hostname: string;
  userId: string;
  logonId: string;
  integrity: "low" | "medium" | "high" | "system";
  sha256: string;
  signed: boolean;
}

export interface NetworkConn {
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  proto: "tcp" | "udp";
  hostname: string;
  pid: number;
  processName: string;
}

// ─── Attack playbook engine ───────────────────────────────────────────────────

export interface AttackPhaseResult {
  events: GeneratedEvent[];
  ctxUpdate?: Record<string, unknown>;
  nextDelayMs: number;
}

export interface AttackPhase {
  id: string;
  name: string;
  mitre: string;
  isFPPhase?: boolean;
  generate: (world: WorldState) => AttackPhaseResult;
}

export interface AttackPlaybook {
  id: string;
  name: string;
  isFP: boolean;
  selectVictim: (world: WorldState) => CompanyUser | null;
  phases: AttackPhase[];
}

export interface AttackCtx {
  playbookId: string;
  isFP: boolean;
  phase: number;
  victim: CompanyUser;
  attackerIp: string;
  correlationId: string;
  startTime: number;
  nextEventAt: number;
  ctx: Record<string, unknown>;
}

// ─── World state ──────────────────────────────────────────────────────────────

export interface WorldState {
  meta: CompanyMeta;
  sessions: Map<string, UserSession>;         // userId → session
  forest: Map<string, ProcessNode[]>;         // hostname → process list
  dns: Map<string, string>;                   // domain → resolved ip
  conns: NetworkConn[];
  attack: AttackCtx | null;
  simTime: number;
  count: number;
  rng: SeededRNG;
}

// ─── Generator output ─────────────────────────────────────────────────────────

export interface GeneratedEvent {
  id?: string;
  ts?: string;
  source: LogSource;
  vendor?: string;
  event_type: EventType;
  severity?: "critical" | "high" | "medium" | "low" | "informational";
  mitre_technique?: string;
  description?: string;
  expected_verdict?: "tp" | "fp" | "escalate" | "informational";
  hostname?: string;
  user_email?: string;
  user_title?: string;
  user?: { full_name?: string; email?: string; department?: string; title?: string };
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  geo?: { country?: string; city?: string; latitude?: number; longitude?: number };
  process?: {
    name: string; pid: number; path?: string; parent_name?: string;
    parent_pid?: number; cmdline?: string; user?: string;
    integrity?: "low" | "medium" | "high" | "system";
    hash?: { sha256?: string; md5?: string };
  };
  file?: { name?: string; path: string; sha256?: string; md5?: string; size?: number; extension?: string };
  network?: { url?: string; domain?: string; method?: string; status?: number; bytes_in?: number; bytes_out?: number; user_agent?: string };
  dns?: { query?: string; query_type?: string; response?: string; rcode?: string };
  raw?: Record<string, unknown>;
}
