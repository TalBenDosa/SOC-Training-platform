/**
 * The environment a named-organization team exercise runs in, as the instructor chose it
 * in the Session Builder: which platforms the organization operates beyond its Microsoft
 * workplace (Entra ID / M365 / Windows endpoints are always there), and its industry.
 *
 * It decides which attack stories the exercise can draw (a CloudTrail story needs AWS,
 * a hospital EMR chain needs a healthcare organization) and which platform noise the
 * feed carries (an AWS shop's feed has ordinary CloudTrail traffic, so the attack's
 * CloudTrail rows are not the only ones). Client-safe: data and pure checks only.
 */
import type { TelemetryEvent } from "@/lib/sim/types";

export type Platform = "azure" | "aws" | "k8s" | "linux" | "vmware" | "github" | "cyberark" | "ndr";
export type Industry = "general" | "healthcare" | "finance" | "logistics";
export interface TeamEnv { platforms: Platform[]; industry: Industry }

export const PLATFORM_CHOICES: { id: Platform; label: string; hint: string }[] = [
  { id: "azure", label: "Azure subscriptions", hint: "Azure Activity Log — Key Vault, Azure OpenAI, resource changes" },
  { id: "aws", label: "AWS", hint: "CloudTrail and GuardDuty — IAM, S3, EC2, Bedrock" },
  { id: "k8s", label: "Kubernetes", hint: "Kubernetes audit log — pods, RBAC, secrets" },
  { id: "linux", label: "Linux servers", hint: "auditd — SSH, cron, sudo, processes" },
  { id: "vmware", label: "VMware vSphere", hint: "vCenter and ESXi events" },
  { id: "github", label: "GitHub", hint: "GitHub audit log and Actions runners" },
  { id: "cyberark", label: "CyberArk PAM", hint: "Privileged vault checkouts and sessions" },
  { id: "ndr", label: "Network sensor (Zeek)", hint: "Corelight / Zeek protocol logs — Kerberos, SMB, NTLM" },
];

export const INDUSTRY_CHOICES: { id: Industry; label: string; hint: string }[] = [
  { id: "general", label: "General business", hint: "Attacks every organization faces" },
  { id: "healthcare", label: "Healthcare", hint: "Adds EMR, patient-record and medical-imaging attacks" },
  { id: "finance", label: "Financial services", hint: "Adds core-banking, SWIFT and trading attacks" },
  { id: "logistics", label: "Logistics", hint: "Adds warehouse (WMS) and ERP attacks" },
];

export const DEFAULT_ENV: TeamEnv = { platforms: ["azure", "linux"], industry: "general" };

const INDUSTRY_IDS = new Set<string>(INDUSTRY_CHOICES.map(i => i.id));

/** Known platforms / industry only (client input is never trusted); missing → the default. */
export function sanitizeEnv(input: unknown): TeamEnv {
  if (!input || typeof input !== "object") return { ...DEFAULT_ENV, platforms: [...DEFAULT_ENV.platforms] };
  const o = input as { platforms?: unknown; industry?: unknown };
  const platforms = Array.isArray(o.platforms)
    ? PLATFORM_CHOICES.map(p => p.id).filter(id => (o.platforms as unknown[]).includes(id))
    : [...DEFAULT_ENV.platforms];
  const industry = typeof o.industry === "string" && INDUSTRY_IDS.has(o.industry) ? o.industry as Industry : DEFAULT_ENV.industry;
  return { platforms, industry };
}

/** The stored environment of a session (team_sessions.config.env), or null for a Live-SOC-company session. */
export function envFromConfig(config: unknown): TeamEnv | null {
  const c = config as { tenant?: unknown; env?: unknown } | null;
  if (!c?.tenant) return null;
  return sanitizeEnv(c.env);
}

/**
 * Stories written around one industry's own systems (an EMR, PACS, SWIFT, a trading desk,
 * a WMS). Every other story is one any organization can meet.
 */
const INDUSTRY_STORIES: Record<string, Industry> = {
  "medcore-chain-a": "healthcare", "medcore-chain-b": "healthcare", "medcore-chain-c": "healthcare", "medcore-chain-d": "healthcare",
  "quantumbank-chain-a": "finance", "quantumbank-chain-c": "finance", "quantumbank-chain-d": "finance",
  "qb-swift-wire-fraud": "finance", "qb-fraud-monitoring-tampering": "finance", "qb-cyberark-mule-payout": "finance",
  "globallogis-chain-a": "logistics", "globallogis-chain-b": "logistics",
};
export function storyIndustry(storyId: string): Industry { return INDUSTRY_STORIES[storyId] ?? "general"; }

const v = (ev: TelemetryEvent) => (ev.vendor ?? "").toLowerCase();

/**
 * The platforms an event needs the organization to run. Workplace telemetry (endpoints,
 * firewall, VPN, identity, mail, DNS, the SIEM / SOAR / DLP / UEBA tooling) needs none —
 * the products for those are the stack's choice.
 */
export function platformsOfEvent(ev: TelemetryEvent): Platform[] {
  switch (ev.source as string) {
    case "cloud_azure": return /entra|azure active directory|azure ad/.test(v(ev)) ? [] : ["azure"];
    case "cloudtrail": return /github/.test(v(ev)) ? ["github"] : ["aws"];
    case "k8s_audit": return ["k8s"];
    case "linux_audit": case "infra_monitor": return ["linux"];
    case "virtualization": return ["vmware"];
    case "vcs": return ["github"];
    case "iam": return /cyberark/.test(v(ev)) ? ["cyberark"] : [];
    case "ids": return /zeek|corelight/.test(v(ev)) ? ["ndr"] : [];
    case "siem": return /guardduty|aws/.test(v(ev)) ? ["aws"] : [];
    case "waf": return /aws/.test(v(ev)) ? ["aws"] : [];
    default: return [];
  }
}

/** Every platform the events need is one the organization runs. */
export function envHasPlatforms(env: TeamEnv, events: TelemetryEvent[]): boolean {
  const have = new Set<Platform>(env.platforms);
  return events.every(e => platformsOfEvent(e).every(p => have.has(p)));
}

/** The story belongs in this organization: its platforms are run here and its industry (if any) is this one. */
export function envAllowsStory(env: TeamEnv, story: { id: string; events: TelemetryEvent[] }): boolean {
  const ind = storyIndustry(story.id);
  return (ind === "general" || ind === env.industry) && envHasPlatforms(env, story.events);
}
