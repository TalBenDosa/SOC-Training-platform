/**
 * A session's data-source stack: which native source renders each category.
 * One vendor per category (spec §6.3). The default stack comes from the company
 * profile's declared architecture; the team-session builder (spec §3) will let
 * staff override it per category.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { SourceId } from "./types";

export type StackCategory =
  | "edr" | "firewall" | "vpn" | "proxy" | "dns" | "idp" | "onprem_ad" | "collab"
  | "email_security" | "cloud" | "k8s" | "pam" | "host_telemetry" | "linux" | "itsm";

export type Stack = Partial<Record<StackCategory, SourceId>>;

/** Default stacks for the five built-in companies (from companyProfilesMeta architecture). */
export const COMPANY_STACKS: Record<string, Stack> = {
  nexacorp: { edr: "mde", firewall: "paloalto", vpn: "globalprotect", idp: "entra", onprem_ad: "windows_security",
    collab: "m365", email_security: "defender_o365", dns: "windows_dns", cloud: "azure_activity", host_telemetry: "sysmon", itsm: "servicenow" },
  rocketstack: { edr: "crowdstrike", firewall: "fortigate", vpn: "cloudflare_access", idp: "okta", collab: "google_workspace",
    cloud: "aws_cloudtrail", k8s: "k8s_audit", linux: "linux_auditd", itsm: "servicenow" },
  medcore: { edr: "sentinelone", firewall: "checkpoint", vpn: "anyconnect", idp: "entra", onprem_ad: "windows_security",
    collab: "m365", email_security: "defender_o365", dns: "infoblox", cloud: "azure_activity", itsm: "servicenow" },
  globallogis: { edr: "sophos", firewall: "cisco_ftd", vpn: "anyconnect", idp: "entra", onprem_ad: "windows_security",
    collab: "m365", email_security: "defender_o365", cloud: "aws_cloudtrail", host_telemetry: "sysmon", linux: "linux_auditd", itsm: "servicenow" },
  quantumbank: { edr: "crowdstrike", firewall: "paloalto", vpn: "zscaler_zpa", proxy: "zscaler_zia", idp: "okta",
    collab: "m365", email_security: "proofpoint", cloud: "aws_cloudtrail", pam: "cyberark", itsm: "servicenow" },
};

const has = (ev: TelemetryEvent, ...needles: string[]) => {
  const v = (ev.vendor ?? "").toLowerCase();
  return needles.some(n => v.includes(n));
};

/**
 * Which stack category an event belongs to, or null when no native module covers
 * it yet (WAF, DLP, UEBA, DB monitoring, virtualization, VCS, HR … keep their
 * legacy rendering until cards exist for them).
 */
export function categoryOf(ev: TelemetryEvent): StackCategory | null {
  switch (ev.source as string) {
    case "edr": case "av": return "edr";
    case "firewall": case "ids": return "firewall";
    case "vpn": return "vpn";
    case "proxy": return "proxy";
    case "dns": return "dns";
    case "sysmon": return "host_telemetry";
    case "linux_audit": return "linux";
    case "ad": case "windows_security": return "onprem_ad";
    case "okta": case "mfa": return "idp";
    case "o365": case "exchange": case "sharepoint": {
      if (has(ev, "entra", "azure active directory", "azure ad")) return "idp";
      // Mail-flow / gateway verdicts authored under source "o365" (Defender for
      // Office 365 vendor, or UAL-vendor MessageDelivered / SpamFiltered) are
      // email-security records, not Unified Audit Log records.
      const op = String((ev.raw ?? {})["data.office365.Operation"] ?? (ev.raw ?? {})["Operation"] ?? "");
      if (has(ev, "defender for office", "proofpoint") || /^(MessageDelivered|SpamFiltered)$/.test(op)) return "email_security";
      return "collab";
    }
    case "gws": return "collab";
    case "email_gateway": return "email_security";
    case "cloudtrail": case "cloud_azure": case "cloud_gcp":
      if (has(ev, "entra", "azure active directory", "azure ad")) return "idp";
      return "cloud";
    case "k8s_audit": return "k8s";
    case "iam": return has(ev, "cyberark") ? "pam" : has(ev, "okta") ? "idp" : has(ev, "entra", "azure") ? "idp" : null;
    case "soar": return has(ev, "servicenow") ? "itsm" : null;
    case "siem": return has(ev, "guardduty") ? "cloud" : null;
    default: return null;
  }
}

/**
 * The native source that renders `ev` under `stack`. Cloud is per-provider: an AWS
 * event stays AWS even on an Azure-first stack (GuardDuty findings → aws_guardduty).
 */
export function sourceFor(ev: TelemetryEvent, stack: Stack): SourceId | null {
  const cat = categoryOf(ev);
  if (!cat) return null;
  if (cat === "cloud") {
    if (has(ev, "guardduty")) return "aws_guardduty";
    if (ev.source === "cloudtrail" || has(ev, "aws", "cloudtrail")) return "aws_cloudtrail";
    if (ev.source === "cloud_gcp" || has(ev, "google cloud", "gcp")) return "gcp_audit";
    return "azure_activity";
  }
  if (cat === "onprem_ad") return "windows_security";
  return stack[cat] ?? nativeDefault(ev, cat);
}

/** Fall back to the vendor the event was authored for. */
function nativeDefault(ev: TelemetryEvent, cat: StackCategory): SourceId | null {
  switch (cat) {
    case "edr": return has(ev, "sentinelone") ? "sentinelone" : has(ev, "sophos") ? "sophos" : has(ev, "defender") ? "mde" : "crowdstrike";
    case "firewall": return has(ev, "forti") ? "fortigate" : has(ev, "check point", "checkpoint") ? "checkpoint" : has(ev, "asa") ? "cisco_asa" : has(ev, "cisco", "firepower") ? "cisco_ftd" : "paloalto";
    case "vpn": return has(ev, "anyconnect") ? "anyconnect" : has(ev, "forti") ? "fortigate_sslvpn" : has(ev, "zscaler") ? "zscaler_zpa" : has(ev, "cloudflare") ? "cloudflare_access" : "globalprotect";
    case "proxy": return "zscaler_zia";
    case "dns": return has(ev, "infoblox") ? "infoblox" : "windows_dns";
    case "idp": return has(ev, "okta") ? "okta" : "entra";
    case "collab": return ev.source === "gws" ? "google_workspace" : "m365";
    case "email_security": return has(ev, "proofpoint") ? "proofpoint" : "defender_o365";
    case "k8s": return "k8s_audit";
    case "pam": return "cyberark";
    case "host_telemetry": return "sysmon";
    case "linux": return "linux_auditd";
    case "itsm": return "servicenow";
    default: return null;
  }
}

// ── Vendor choice (spec §3, step 2) ──────────────────────────────────────────

/** Short product names shown in the feed and pickers (light — no module import). */
export const PRODUCT_LABEL: Partial<Record<SourceId, string>> = {
  crowdstrike: "CrowdStrike Falcon", mde: "Microsoft Defender for Endpoint", sentinelone: "SentinelOne", sophos: "Sophos Intercept X",
  paloalto: "Palo Alto Networks", fortigate: "Fortinet FortiGate", checkpoint: "Check Point", cisco_ftd: "Cisco Firepower (FTD)", cisco_asa: "Cisco ASA",
  globalprotect: "GlobalProtect", anyconnect: "Cisco AnyConnect", fortigate_sslvpn: "FortiGate SSL-VPN", zscaler_zpa: "Zscaler Private Access", cloudflare_access: "Cloudflare Access",
  entra: "Microsoft Entra ID", okta: "Okta",
  m365: "Microsoft 365", google_workspace: "Google Workspace",
  defender_o365: "Microsoft Defender for Office 365", proofpoint: "Proofpoint TAP",
  windows_dns: "Windows DNS", infoblox: "Infoblox", zscaler_zia: "Zscaler Internet Access",
};

/** The categories a trainer can switch, with the products the platform renders natively. */
export const STACK_CHOICES: { category: StackCategory; label: string; options: SourceId[]; note?: string }[] = [
  { category: "edr", label: "EDR", options: ["crowdstrike", "mde", "sentinelone", "sophos"],
    note: "Sophos streams no per-event DNS / network / file telemetry, so attacks that need that trail are not picked." },
  { category: "firewall", label: "Firewall", options: ["paloalto", "fortigate", "checkpoint", "cisco_ftd", "cisco_asa"] },
  { category: "vpn", label: "Remote access", options: ["globalprotect", "anyconnect", "fortigate_sslvpn", "zscaler_zpa", "cloudflare_access"],
    note: "ZPA and Cloudflare sign in through SAML — password failures appear in the identity provider's logs instead." },
  { category: "idp", label: "Identity provider", options: ["entra", "okta"] },
  { category: "collab", label: "Email & files", options: ["m365", "google_workspace"],
    note: "Google Workspace has no equivalent for Exchange inbox rules or mailbox delegation — those attacks are not picked." },
  { category: "email_security", label: "Email security", options: ["defender_o365", "proofpoint"] },
  { category: "dns", label: "DNS", options: ["windows_dns", "infoblox"] },
];

/** Keep only known categories / products (client input is never trusted). */
export function sanitizeStack(input: unknown): Stack {
  const out: Stack = {};
  if (!input || typeof input !== "object") return out;
  for (const c of STACK_CHOICES) {
    const v = (input as Record<string, unknown>)[c.category];
    if (typeof v === "string" && (c.options as string[]).includes(v)) out[c.category] = v as SourceId;
  }
  return out;
}

// Product names that appear in authored descriptions, per category — rewritten to
// the chosen product so a row never says "Defender killed it" on a CrowdStrike shop.
const NAME_FAMILIES: Partial<Record<StackCategory, string[]>> = {
  edr: ["Microsoft Defender for Endpoint", "Microsoft Defender Antivirus", "Microsoft Defender ATP", "Defender for Endpoint", "Windows Defender",
    "Microsoft Defender", "CrowdStrike Falcon Elite", "CrowdStrike Falcon", "CrowdStrike", "Falcon", "SentinelOne Singularity", "SentinelOne",
    "Sophos Intercept X", "Sophos", "Defender"],
  firewall: ["Palo Alto Networks", "Palo Alto NGFW", "Palo Alto", "PAN-OS", "Fortinet FortiGate", "FortiGate", "Fortinet", "Check Point",
    "Cisco Firepower", "Firepower", "Cisco ASA"],
  vpn: ["GlobalProtect", "Cisco AnyConnect", "AnyConnect", "Cisco Secure Client", "FortiGate SSL-VPN", "FortiClient", "Zscaler Private Access", "Cloudflare Access", "Cloudflare Zero Trust"],
  idp: ["Microsoft Entra ID", "Entra ID", "Azure Active Directory", "Azure AD", "Okta"],
  email_security: ["Microsoft Defender for Office 365", "Defender for Office 365", "Proofpoint TAP", "Proofpoint"],
  dns: ["Infoblox", "Windows DNS"],
};
const COLLAB_TO_GOOGLE: [string, string][] = [
  ["Microsoft 365", "Google Workspace"], ["Office 365", "Google Workspace"], ["SharePoint Online", "Google Drive"], ["SharePoint", "Google Drive"],
  ["OneDrive", "Google Drive"], ["Exchange Online", "Gmail"], ["Outlook", "Gmail"],
];
const COLLAB_TO_M365: [string, string][] = [["Google Workspace", "Microsoft 365"], ["Google Drive", "OneDrive"], ["Gmail", "Outlook"]];

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
function rewriteNames(text: string, pairs: [string, string][]): string {
  // Placeholders first (longest names first), then targets — a rewrite never re-matches its own output.
  const sorted = [...pairs].sort((a, b) => b[0].length - a[0].length);
  let out = text;
  sorted.forEach(([from], i) => { out = out.replace(new RegExp(`(?<![A-Za-z])${escapeRe(from)}(?![A-Za-z])`, "g"), `\u0000${i}\u0000`); });
  return out.replace(/\u0000(\d+)\u0000/g, (_m, i) => sorted[Number(i)][1]);
}

/** Description with the category's product names switched to `sid`'s. */
export function rewriteProductText(text: string | undefined, cat: StackCategory, sid: SourceId): string | undefined {
  if (!text) return text;
  if (cat === "collab") return rewriteNames(text, sid === "google_workspace" ? COLLAB_TO_GOOGLE : COLLAB_TO_M365);
  const fam = NAME_FAMILIES[cat];
  const to = PRODUCT_LABEL[sid];
  if (!fam || !to) return text;
  // Replace with a unique placeholder first so a rewrite never re-matches its own output.
  let out = text;
  const hits: string[] = [];
  for (const name of [...fam].sort((a, b) => b.length - a.length)) {
    out = out.replace(new RegExp(`(?<![A-Za-z])${escapeRe(name)}(?![A-Za-z])`, "g"), () => { hits.push(name); return "\u0000P\u0000"; });
  }
  return hits.length ? out.split("\u0000P\u0000").join(to) : text;
}
