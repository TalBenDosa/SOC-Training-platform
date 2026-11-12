import { withoutDetectionFeed, type Stack } from "@/lib/logs/native/stack";
import type { Ev } from "@/lib/team/types";
import type { TeamEnv } from "@/lib/team/environment";
import { escalationHandoff, type Handoff, type NameOf } from "@/lib/team/handoff";

/**
 * Where a Team Training session investigates: the EDR console, or XDR, this platform's own
 * investigation console with KQL (owner, 2026-11-08: renamed from "Sentinel" so it does not
 * imitate Microsoft's product). Chosen before the session, by the person who builds it. Stored in
 * team_sessions.config.console; the stored value stays "sentinel", only what people see changed.
 */
export type InvestigationConsole = "edr" | "sentinel";

export const CONSOLE_CHOICES: { id: InvestigationConsole; label: string; hint: string }[] = [
  { id: "edr", label: "EDR console", hint: "Endpoint detections open the EDR console of the products below." },
  { id: "sentinel", label: "XDR console (KQL)", hint: "Collects the organization's Microsoft 365, Defender and identity telemetry in one place, with its Windows and web servers. Detections raise incidents there, and the team queries the logs with KQL. An organization on other products (AWS, Okta, Google Workspace, CrowdStrike) investigates in the EDR console." },
];

/**
 * The XDR console stands for Microsoft Sentinel only (owner, 2026-11-12: "it is meant to imitate Sentinel only; fit
 * the scenario and the data to it; if they work with other things, use the EDR"). An XDR session runs the Microsoft
 * products a Sentinel workspace holds natively; network devices (firewall, VPN) keep the organization's own, as a
 * Sentinel SOC ingests them over CEF / Syslog.
 */
export const XDR_PRODUCTS: Stack = { edr: "mde", idp: "entra", collab: "m365", email_security: "defender_o365", dns: "windows_dns", waf: "azure_waf", web_server: "iis" };
/** Remote access a Sentinel workspace takes over CEF / Syslog; a cloud broker (ZPA, Cloudflare Access) is another world. */
const XDR_VPNS = new Set(["globalprotect", "anyconnect", "fortigate_sslvpn"]);
/** Products a story may not show in an XDR session: another vendor's world, never Sentinel's own tables. */
export const NOT_SENTINEL = new Set(["nginx", "aws_waf", "aws_cloudtrail", "aws_guardduty", "aws_vpcflow", "gcp_audit", "okta", "google_workspace", "crowdstrike", "sentinelone",
  "sophos", "proofpoint", "zscaler_zia", "zscaler_zpa", "cloudflare_access", "mysql_audit", "exabeam", "securonix"]);
/** Is this the stack of an XDR session (only stackForConsole sets the detection feed)? */
export const isXdrStack = (stack: Stack) => stack.detection_feed === "ms_graph";

export function sanitizeConsole(input: unknown): InvestigationConsole {
  return input === "sentinel" ? "sentinel" : "edr";
}

/** The session's console (team_sessions.config.console). Every session made before this feature reads as "edr". */
export function consoleFromConfig(config: unknown): InvestigationConsole {
  return sanitizeConsole((config as { console?: unknown } | null)?.console);
}

/** An XDR session's organization runs Azure, and only Azure among the clouds: AWS and Google Cloud are another world (EDR console). */
export function envForConsole<E extends TeamEnv | null>(env: E, console: InvestigationConsole): E {
  if (!env || console !== "sentinel") return env;
  const rest = env.platforms.filter(p => p !== "azure" && p !== "aws" && p !== "gcp");
  return { ...env, platforms: ["azure", ...rest] };
}

/**
 * What analysts escalated, for the workspace: each opens a Sentinel incident, and carries the
 * analyst's whole report (owner, 2026-11-08): the incident's title is their summary, its
 * description and first comment are their report, and their indicators become entities.
 * The latest round of a re-escalated log wins. No raw block: the incident's own events hold it.
 */
export function escalatedCases(events: Ev[], nameOf?: NameOf): { eventId: string; summary?: string; handoff?: Handoff }[] {
  const latest = new Map<string, Ev>();
  for (const e of events) {
    if (e.type !== "escalation.requested") continue;
    const id = String((e.payload as { event_id?: unknown }).event_id ?? "");
    if (id) latest.set(id, e);
  }
  return [...latest.entries()].map(([eventId, e]) => {
    const p = e.payload as { summary?: unknown };
    return { eventId, summary: typeof p.summary === "string" ? p.summary : undefined, handoff: escalationHandoff(e, events, { nameOf, raw: false, related: false }) };
  });
}

/**
 * Sentinel reads endpoint activity from the Defender tables (DeviceProcessEvents and the rest), so a
 * Sentinel session runs Defender for Endpoint. Otherwise the feed would show one product's records and
 * KQL another's. The picker shows this choice, and the server enforces it.
 *
 * Its SIEM also reads the Microsoft products' detections through the Graph Security API, as a SOC
 * on Sentinel does (detection_feed). Only this function sets that key: an EDR session never has it,
 * whatever a client sends, and the picker never offers it.
 */
export function stackForConsole(stack: Stack, console: InvestigationConsole): Stack {
  const products = withoutDetectionFeed(stack);
  if (console !== "sentinel") return products;
  const vpn = products.vpn && !XDR_VPNS.has(products.vpn) ? { vpn: undefined } : {};
  const out: Stack = { ...products, ...vpn, ...XDR_PRODUCTS, detection_feed: "ms_graph" };
  for (const k of Object.keys(out) as (keyof Stack)[]) if (out[k] === undefined) delete out[k];
  return out;
}
